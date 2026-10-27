/**
 * QuizPoint - Quiz Platform backend (Problem 16 + college login)
 * Express + MongoDB (mongodb driver, no Mongoose)
 *
 * Collections:
 *   users    { name, email, role: 'student' | 'teacher', usn (students only), passwordHash, createdAt }
 *   sessions { token, userId: ObjectId, createdAt }
 *   quizzes  { title, questions: [{ text, options: [string], correctIndex }], createdBy, createdByName, createdAt }
 *   attempts { quizId: ObjectId, usn, name, score, total, takenAt }
 *
 * Key rules:
 *   - Only @rvce.edu.in email ids can register.
 *   - Sign up always creates a STUDENT. There is no teacher option at sign up.
 *   - Teacher accounts are built in (DEFAULT_TEACHERS) and created when the server starts.
 *   - Only teachers can create quizzes (403 for students). Only students can attempt them.
 *   - Passwords are hashed with Node's built-in crypto.scrypt (never stored as plain text).
 *   - Every /api route except register and login needs a valid session token.
 *   - The server NEVER sends correctIndex to the browser (see publicQuiz()).
 *   - The server scores every attempt, never the browser.
 *   - One attempt per USN per quiz, enforced by a unique index (409 on a second try).
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuration
const MONGO_URI = 'mongodb://127.0.0.1:27017';
const DB_NAME = 'Hack_QuizPoint';
const SESSION_DAYS = 7;

// Built-in teacher (admin) accounts. Nobody can sign up as a teacher.
// They are created the first time the server starts, and skipped if they already exist.
// Change the names and passwords before the demo if you like.
const DEFAULT_TEACHERS = [
  { name: 'Prof. Ananya Rao', email: 'teacher1@rvce.edu.in', password: 'Teacher@123' },
  { name: 'Prof. Kiran Kumar', email: 'teacher2@rvce.edu.in', password: 'Teacher@123' },
  { name: 'Prof. Meera Iyer', email: 'teacher3@rvce.edu.in', password: 'Teacher@123' }
];

let db;
let usersCollection;
let sessionsCollection;
let quizzesCollection;
let attemptsCollection;

// RVCE-style USN, e.g. 1RV23CS001
const USN_PATTERN = /^[0-9][A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{3}$/;
// Only college email ids, e.g. name.cs23@rvce.edu.in
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@rvce\.edu\.in$/;

// ---------- Helpers ----------

function escapeRegex(text) {
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
}

// Turns the :id in the URL into an ObjectId, or returns null if it is not valid.
// Using this stops the driver from throwing a 500 on a bad id.
function parseId(id) {
  if (!ObjectId.isValid(id)) return null;
  return new ObjectId(id);
}

// Trims and uppercases a USN so "1rv23cs001 " and "1RV23CS001" count as the same person.
function normalizeUsn(usn) {
  if (typeof usn !== 'string') return '';
  return usn.trim().toUpperCase();
}

function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

// Hashes a password with a random salt. Stored as "salt:hash".
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) return reject(err);
      resolve(salt + ':' + key.toString('hex'));
    });
  });
}

// Checks a typed password against the stored "salt:hash".
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, hash] = stored.split(':');
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) return reject(err);
      // timingSafeEqual compares without leaking how many characters matched
      resolve(crypto.timingSafeEqual(Buffer.from(hash, 'hex'), key));
    });
  });
}

// Accounts made before roles existed count as students
function roleOf(user) {
  return user.role === 'teacher' ? 'teacher' : 'student';
}

// The user details that are safe to send to the browser (no password hash)
function publicUser(user) {
  return { _id: user._id, name: user.name, email: user.email, role: roleOf(user), usn: user.usn || null };
}

// Builds the version of a quiz that is safe to send to the browser.
// It copies only text and options, so correctIndex can never slip through.
function publicQuiz(quiz) {
  return {
    _id: quiz._id,
    title: quiz.title,
    createdByName: quiz.createdByName || 'Unknown',
    createdAt: quiz.createdAt,
    questions: quiz.questions.map((q) => ({
      text: q.text,
      options: q.options
    }))
  };
}

// Checks a new quiz from the request body. Returns an error message, or null if it is fine.
function validateQuiz(body) {
  const { title, questions } = body;

  if (!title || typeof title !== 'string' || title.trim() === '') {
    return 'Quiz title is required and must be text';
  }
  if (!Array.isArray(questions) || questions.length === 0) {
    return 'A quiz needs at least one question';
  }

  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    const num = i + 1;

    if (!q || typeof q.text !== 'string' || q.text.trim() === '') {
      return `Question ${num}: text is required`;
    }
    if (!Array.isArray(q.options) || q.options.length < 2 || q.options.length > 6) {
      return `Question ${num}: needs between 2 and 6 options`;
    }
    for (const opt of q.options) {
      if (typeof opt !== 'string' || opt.trim() === '') {
        return `Question ${num}: every option must be non-empty text`;
      }
    }
    if (!Number.isInteger(q.correctIndex) || q.correctIndex < 0 || q.correctIndex >= q.options.length) {
      return `Question ${num}: correctIndex must be a whole number between 0 and ${q.options.length - 1}`;
    }
  }

  return null;
}

// ---------- Login check (middleware) ----------
// Reads "Authorization: Bearer <token>", finds the session, and puts the user on req.user.
// Any route that uses requireAuth answers 401 if you are not logged in.
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token) {
      return res.status(401).json({ error: 'Please log in first' });
    }

    const session = await sessionsCollection.findOne({ token });
    if (!session) {
      return res.status(401).json({ error: 'Your session has expired. Please log in again' });
    }

    const user = await usersCollection.findOne({ _id: session.userId });
    if (!user) {
      return res.status(401).json({ error: 'Account not found. Please log in again' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ error: 'Failed to check login' });
  }
}

// Use after requireAuth: lets only teachers through (403 for students)
function requireTeacher(req, res, next) {
  if (roleOf(req.user) !== 'teacher') {
    return res.status(403).json({ error: 'Only teachers can do this' });
  }
  next();
}

// Use after requireAuth: lets only students through (403 for teachers)
function requireStudent(req, res, next) {
  if (roleOf(req.user) !== 'student') {
    return res.status(403).json({ error: 'Only students can attempt quizzes' });
  }
  next();
}

// ---------- Auth routes ----------

// POST /api/register  { name, email, usn, password }
// Always creates a student account. Teachers are built in (see DEFAULT_TEACHERS).
app.post('/api/register', async (req, res) => {
  try {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const email = normalizeEmail(req.body.email);
    const usn = normalizeUsn(req.body.usn);
    const { password } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    if (!EMAIL_PATTERN.test(email)) {
      return res.status(400).json({ error: 'Only RVCE email ids ending in @rvce.edu.in are allowed' });
    }
    if (!USN_PATTERN.test(usn)) {
      return res.status(400).json({ error: 'USN format looks wrong (example: 1RV23CS001)' });
    }
    if (typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // role is set here by the server, never taken from the request,
    // so nobody can make themselves a teacher by sending role: "teacher"
    const newUser = {
      name,
      email,
      usn,
      role: 'student',
      passwordHash: await hashPassword(password),
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(newUser);
    newUser._id = result.insertedId;

    res.status(201).json({ message: 'Account created. You can log in now', user: publicUser(newUser) });
  } catch (error) {
    if (error.code === 11000) {
      const field = error.keyPattern && error.keyPattern.usn ? 'USN' : 'email id';
      return res.status(409).json({ error: `An account with this ${field} already exists` });
    }
    console.error('POST /api/register error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// POST /api/login  { email, password }  ->  { token, user }
app.post('/api/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { password } = req.body;

    if (!email || typeof password !== 'string' || password === '') {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await usersCollection.findOne({ email });
    // Same message for "no such user" and "wrong password", so nobody can guess which emails exist
    if (!user || !(await verifyPassword(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Wrong email or password' });
    }

    // A random token the browser sends back on every request
    const token = crypto.randomBytes(32).toString('hex');
    await sessionsCollection.insertOne({ token, userId: user._id, createdAt: new Date() });

    res.json({ token, user: publicUser(user) });
  } catch (error) {
    console.error('POST /api/login error:', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

// GET /api/me  ->  the logged-in user
app.get('/api/me', requireAuth, (req, res) => {
  res.json(publicUser(req.user));
});

// POST /api/logout  ->  deletes this session, so the token stops working
app.post('/api/logout', requireAuth, async (req, res) => {
  try {
    await sessionsCollection.deleteOne({ token: req.token });
    res.json({ message: 'Logged out' });
  } catch (error) {
    console.error('POST /api/logout error:', error);
    res.status(500).json({ error: 'Failed to log out' });
  }
});

// ---------- Quiz routes (all need login) ----------

// 1. GET /api/quizzes  (optional ?search= on title)
// Sends only id, title, creator, question count, date, whether YOU attempted it (students)
// and whether YOU created it (teachers). No answers.
app.get('/api/quizzes', requireAuth, async (req, res) => {
  try {
    const { search } = req.query;
    let filter = {};

    if (search && search.trim() !== '') {
      filter = { title: { $regex: new RegExp(escapeRegex(search.trim()), 'i') } };
    }

    const quizzes = await quizzesCollection
      .find(filter, { projection: { title: 1, createdBy: 1, createdByName: 1, createdAt: 1, questions: 1 } })
      .sort({ createdAt: -1 })
      .toArray();

    // Which of these quizzes has the logged-in student already attempted? (Teachers have none.)
    const myAttempts = roleOf(req.user) === 'student'
      ? await attemptsCollection
          .find({ usn: req.user.usn }, { projection: { quizId: 1, score: 1, total: 1 } })
          .toArray()
      : [];
    const attemptedMap = {};
    myAttempts.forEach((a) => {
      attemptedMap[String(a.quizId)] = { score: a.score, total: a.total };
    });

    res.json(
      quizzes.map((q) => ({
        _id: q._id,
        title: q.title,
        createdByName: q.createdByName || 'Unknown',
        createdAt: q.createdAt,
        questionCount: q.questions.length,
        myAttempt: attemptedMap[String(q._id)] || null,
        isMine: String(q.createdBy) === String(req.user._id)
      }))
    );
  } catch (error) {
    console.error('GET /api/quizzes error:', error);
    res.status(500).json({ error: 'Failed to fetch quizzes' });
  }
});

// 2. POST /api/quizzes  (create a quiz) - teachers only
app.post('/api/quizzes', requireAuth, requireTeacher, async (req, res) => {
  try {
    const validationError = validateQuiz(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const newQuiz = {
      title: req.body.title.trim(),
      questions: req.body.questions.map((q) => ({
        text: q.text.trim(),
        options: q.options.map((o) => o.trim()),
        correctIndex: q.correctIndex
      })),
      createdBy: req.user._id,
      createdByName: req.user.name,
      createdAt: new Date()
    };

    const result = await quizzesCollection.insertOne(newQuiz);
    newQuiz._id = result.insertedId;

    // Even the creator's response goes through publicQuiz, so answers never leave the server.
    res.status(201).json(publicQuiz(newQuiz));
  } catch (error) {
    console.error('POST /api/quizzes error:', error);
    res.status(500).json({ error: 'Failed to create quiz' });
  }
});

// 3. GET /api/quizzes/:id  (quiz for taking, WITHOUT correctIndex)
app.get('/api/quizzes/:id', requireAuth, async (req, res) => {
  try {
    const quizId = parseId(req.params.id);
    if (!quizId) {
      return res.status(400).json({ error: 'Invalid quiz ID format' });
    }

    // Projection is a second layer of safety: correctIndex is not even read from the DB here.
    const quiz = await quizzesCollection.findOne(
      { _id: quizId },
      { projection: { 'questions.correctIndex': 0 } }
    );
    if (!quiz) {
      return res.status(404).json({ error: 'Quiz not found' });
    }

    res.json(publicQuiz(quiz));
  } catch (error) {
    console.error(`GET /api/quizzes/${req.params.id} error:`, error);
    res.status(500).json({ error: 'Failed to fetch quiz' });
  }
});

// 4. POST /api/quizzes/:id/attempts  (submit answers; the server scores them) - students only
// Body: { answers: [0, 2, 1, ...] }  (use -1 or null to skip a question)
// The USN comes from the logged-in account, so nobody can submit as someone else.
app.post('/api/quizzes/:id/attempts', requireAuth, requireStudent, async (req, res) => {
  try {
    const quizId = parseId(req.params.id);
    if (!quizId) {
      return res.status(400).json({ error: 'Invalid quiz ID format' });
    }

    const quiz = await quizzesCollection.findOne({ _id: quizId });
    if (!quiz) {
      return res.status(404).json({ error: 'Quiz not found' });
    }

    const { answers } = req.body;
    if (!Array.isArray(answers) || answers.length !== quiz.questions.length) {
      return res.status(400).json({
        error: `answers must be a list with exactly ${quiz.questions.length} entries`
      });
    }

    // Score on the server
    let score = 0;
    for (let i = 0; i < quiz.questions.length; i++) {
      const a = answers[i];
      const optionCount = quiz.questions[i].options.length;

      const skipped = a === null || a === -1;
      if (!skipped && (!Number.isInteger(a) || a < 0 || a >= optionCount)) {
        return res.status(400).json({ error: `Answer ${i + 1} is not a valid option` });
      }
      if (a === quiz.questions[i].correctIndex) {
        score++;
      }
    }

    const attempt = {
      quizId,
      usn: req.user.usn,
      name: req.user.name,
      score,
      total: quiz.questions.length,
      takenAt: new Date()
    };

    // If this USN already has an attempt for this quiz, the unique index
    // makes insertOne fail with code 11000, which we turn into a 409 below.
    await attemptsCollection.insertOne(attempt);

    res.status(201).json({ usn: attempt.usn, score, total: attempt.total });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'You have already attempted this quiz' });
    }
    console.error(`POST /api/quizzes/${req.params.id}/attempts error:`, error);
    res.status(500).json({ error: 'Failed to submit attempt' });
  }
});

// 5. GET /api/quizzes/:id/leaderboard  (top 10, highest score first, earlier attempt wins a tie)
app.get('/api/quizzes/:id/leaderboard', requireAuth, async (req, res) => {
  try {
    const quizId = parseId(req.params.id);
    if (!quizId) {
      return res.status(400).json({ error: 'Invalid quiz ID format' });
    }

    const quiz = await quizzesCollection.findOne({ _id: quizId }, { projection: { title: 1 } });
    if (!quiz) {
      return res.status(404).json({ error: 'Quiz not found' });
    }

    const top = await attemptsCollection
      .find({ quizId }, { projection: { _id: 0, usn: 1, name: 1, score: 1, total: 1, takenAt: 1 } })
      .sort({ score: -1, takenAt: 1 })
      .limit(10)
      .toArray();

    res.json({ quizId, title: quiz.title, leaderboard: top });
  } catch (error) {
    console.error(`GET /api/quizzes/${req.params.id}/leaderboard error:`, error);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

// Unknown /api route -> JSON 404 (instead of an HTML page)
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Catches broken JSON bodies and any other unexpected error, always as JSON
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Request body is not valid JSON' });
  }
  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Something went wrong on the server' });
});

// Creates the built-in teacher accounts if they don't exist yet (teachers have no USN)
async function seedTeachers() {
  for (const t of DEFAULT_TEACHERS) {
    const exists = await usersCollection.findOne({ email: t.email });
    if (!exists) {
      await usersCollection.insertOne({
        name: t.name,
        email: t.email,
        role: 'teacher',
        passwordHash: await hashPassword(t.password),
        createdAt: new Date()
      });
      console.log(`Created teacher account: ${t.email}`);
    }
  }
}

// ---------- Server startup ----------
async function startServer() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    console.log('Connected to MongoDB');

    db = client.db(DB_NAME);
    usersCollection = db.collection('users');
    sessionsCollection = db.collection('sessions');
    quizzesCollection = db.collection('quizzes');
    attemptsCollection = db.collection('attempts');

    // No two accounts with the same email
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    // No two students with the same USN. "partial" means teachers (who have no USN) are skipped.
    // First remove the older plain USN index from before teachers existed, if it is still there.
    try {
      await usersCollection.dropIndex('usn_1');
    } catch (e) {
      // Not there, nothing to remove
    }
    await usersCollection.createIndex(
      { usn: 1 },
      { unique: true, name: 'usn_students_unique', partialFilterExpression: { usn: { $type: 'string' } } }
    );
    // Fast token lookup, and MongoDB deletes sessions automatically after SESSION_DAYS
    await sessionsCollection.createIndex({ token: 1 }, { unique: true });
    await sessionsCollection.createIndex({ createdAt: 1 }, { expireAfterSeconds: SESSION_DAYS * 24 * 60 * 60 });
    // One attempt per USN per quiz, enforced by the database itself
    await attemptsCollection.createIndex({ quizId: 1, usn: 1 }, { unique: true });
    console.log('Indexes verified');

    await seedTeachers();

    const server = app.listen(PORT, () => {
      console.log(`Server running at http://127.0.0.1:${PORT}/`);
    });

    process.on('SIGINT', async () => {
      console.log('\nShutting down gracefully...');
      await client.close();
      server.close(() => {
        console.log('Database connection closed.');
        process.exit(0);
      });
    });

    return { app, client, db };
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };