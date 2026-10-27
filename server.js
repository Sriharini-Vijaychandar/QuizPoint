/**
 * QuizPoint - Quiz Platform backend (Problem 16 + college login + subjects + scheduling)
 * Express + MongoDB (mongodb driver, no Mongoose)
 *
 * Collections:
 *   users       { name, email, role: 'student' | 'teacher', usn (students only), passwordHash, createdAt }
 *   sessions    { token, userId: ObjectId, createdAt }
 *   subjects    { name, code, teacherId: ObjectId, teacherName, createdAt }
 *   enrollments { subjectId: ObjectId, userId: ObjectId, usn, name, status: 'pending' | 'approved' | 'rejected', requestedAt, decidedAt }
 *   quizzes     { title, subjectId, subjectName, questions: [{ text, options, correctIndex }],
 *                 opensAt (or null), closesAt (or null), timeLimitMinutes (or null), createdBy, createdByName, createdAt }
 *   attempts    { quizId, userId, usn, name, status: 'in-progress' | 'submitted' | 'expired',
 *                 startedAt, deadline (or null), answers, score, total, takenAt }
 *
 * Key rules:
 *   - Only @rvce.edu.in email ids can register. Sign up always creates a STUDENT.
 *   - Teacher accounts are built in (DEFAULT_TEACHERS) and created when the server starts.
 *   - Teachers create subjects. Students request to join; the subject's teacher accepts or rejects.
 *   - Students only see quizzes from subjects they have been accepted into.
 *   - A quiz can have an opening time, a closing time and a time limit (all optional).
 *   - The timer is enforced on the server: it starts at POST /start and late submissions are refused.
 *   - The server NEVER sends correctIndex while a quiz can still be taken.
 *     Students see the answers only in review, after the quiz closes.
 *   - The server scores every attempt. One attempt per USN per quiz (unique index, 409).
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
// Extra seconds allowed after the timer ends, for slow networks
const GRACE_SECONDS = 30;
const MAX_TIME_LIMIT_MINUTES = 300;

// Built-in teacher (admin) accounts. Nobody can sign up as a teacher.
// They are created the first time the server starts, and skipped if they already exist.
const DEFAULT_TEACHERS = [
  { name: 'Prof. Ananya Rao', email: 'teacher1@rvce.edu.in', password: 'Teacher@123' },
  { name: 'Prof. Kiran Kumar', email: 'teacher2@rvce.edu.in', password: 'Teacher@123' },
  { name: 'Prof. Meera Iyer', email: 'teacher3@rvce.edu.in', password: 'Teacher@123' }
];

let db;
let usersCollection;
let sessionsCollection;
let subjectsCollection;
let enrollmentsCollection;
let quizzesCollection;
let attemptsCollection;

// RVCE-style USN, e.g. 1RV23CS001
const USN_PATTERN = /^[0-9][A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{3}$/;
// Only college email ids, e.g. name.cs23@rvce.edu.in
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@rvce\.edu\.in$/;
// Subject codes like CS235AI or MA-211
const SUBJECT_CODE_PATTERN = /^[A-Z0-9-]{2,12}$/;

// ---------- Helpers ----------

function escapeRegex(text) {
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
}

// Turns an id from the URL into an ObjectId, or returns null if it is not valid.
function parseId(id) {
  if (typeof id !== 'string' || !ObjectId.isValid(id)) return null;
  return new ObjectId(id);
}

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
      resolve(crypto.timingSafeEqual(Buffer.from(hash, 'hex'), key));
    });
  });
}

// Accounts made before roles existed count as students
function roleOf(user) {
  return user.role === 'teacher' ? 'teacher' : 'student';
}

function sameId(a, b) {
  return String(a) === String(b);
}

function publicUser(user) {
  return { _id: user._id, name: user.name, email: user.email, role: roleOf(user), usn: user.usn || null };
}

// Reads an optional date from the request: '' or null means "not set".
// Returns { value: Date | null } or { error: '...' }.
function readOptionalDate(value, label) {
  if (value === undefined || value === null || value === '') return { value: null };
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return { error: `${label} is not a valid date and time` };
  return { value: d };
}

// upcoming = not open yet, ongoing = can be taken now, closed = past closing time
function quizStatus(quiz, now) {
  if (quiz.opensAt && now < quiz.opensAt) return 'upcoming';
  if (quiz.closesAt && now >= quiz.closesAt) return 'closed';
  return 'ongoing';
}

// What state is a student's attempt in right now?
// Attempts made before timers existed have no status, so they count as submitted.
function attemptState(attempt, now) {
  if (!attempt) return null;
  if (attempt.status === 'in-progress') {
    if (attempt.deadline && now.getTime() > attempt.deadline.getTime() + GRACE_SECONDS * 1000) {
      return 'expired';
    }
    return 'in-progress';
  }
  return attempt.status === 'expired' ? 'expired' : 'submitted';
}

// Students may review once they are done with the quiz AND it has closed.
// A quiz with no closing time can be reviewed as soon as you finish it.
function canReview(quiz, attempt, now) {
  const state = attemptState(attempt, now);
  if (state !== 'submitted' && state !== 'expired') return false;
  return !quiz.closesAt || now >= quiz.closesAt;
}

// The quiz details that are always safe to send (no questions, no answers)
function quizMeta(quiz, now) {
  return {
    _id: quiz._id,
    title: quiz.title,
    subjectId: quiz.subjectId,
    subjectName: quiz.subjectName || 'No subject',
    createdByName: quiz.createdByName || 'Unknown',
    createdAt: quiz.createdAt,
    questionCount: quiz.questions.length,
    opensAt: quiz.opensAt || null,
    closesAt: quiz.closesAt || null,
    timeLimitMinutes: quiz.timeLimitMinutes || null,
    status: quizStatus(quiz, now)
  };
}

// Questions for TAKING a quiz. Builds new objects with only text and options,
// so correctIndex can never slip through.
function publicQuestions(quiz) {
  return quiz.questions.map((q) => ({ text: q.text, options: q.options }));
}

// What a student sees about their own attempt (no answers)
function attemptSummary(quiz, attempt, now) {
  if (!attempt) return null;
  const state = attemptState(attempt, now);
  return {
    state,
    score: state === 'submitted' ? attempt.score : null,
    total: attempt.total,
    takenAt: attempt.takenAt || null,
    deadline: attempt.deadline || null
  };
}

// Checks a new quiz's title and questions. Returns an error message, or null if it is fine.
function validateQuestions(body) {
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

// Ids of the subjects this user can see quizzes for:
// teachers -> the subjects they own, students -> subjects they were accepted into
async function accessibleSubjectIds(user) {
  if (roleOf(user) === 'teacher') {
    const owned = await subjectsCollection.find({ teacherId: user._id }, { projection: { _id: 1 } }).toArray();
    return owned.map((s) => s._id);
  }
  const joined = await enrollmentsCollection
    .find({ userId: user._id, status: 'approved' }, { projection: { subjectId: 1 } })
    .toArray();
  return joined.map((e) => e.subjectId);
}

// Loads a quiz by the :id in the URL and checks this user may see it.
// Sends the error response itself and returns null if not.
async function loadQuizForUser(req, res) {
  const quizId = parseId(req.params.id);
  if (!quizId) {
    res.status(400).json({ error: 'Invalid quiz ID format' });
    return null;
  }

  const quiz = await quizzesCollection.findOne({ _id: quizId });
  if (!quiz) {
    res.status(404).json({ error: 'Quiz not found' });
    return null;
  }

  const allowed = await accessibleSubjectIds(req.user);
  if (!quiz.subjectId || !allowed.some((id) => sameId(id, quiz.subjectId))) {
    const message = roleOf(req.user) === 'teacher'
      ? 'This quiz belongs to another teacher\'s subject'
      : 'Join this quiz\'s subject first';
    res.status(403).json({ error: message });
    return null;
  }

  return quiz;
}

// ---------- Login check (middleware) ----------
// Reads "Authorization: Bearer <token>", finds the session, and puts the user on req.user.
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
    return res.status(403).json({ error: 'Only students can do this' });
  }
  next();
}

// ---------- Auth routes ----------

// POST /api/register  { name, email, usn, password }  -> always a student
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

    // role is set here by the server, never taken from the request
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
    if (!user || !(await verifyPassword(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Wrong email or password' });
    }

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

// ---------- Subject routes ----------

// GET /api/subjects
// Teacher: their own subjects with member and pending-request counts.
// Student: every subject, with myStatus = none | pending | approved | rejected.
app.get('/api/subjects', requireAuth, async (req, res) => {
  try {
    if (roleOf(req.user) === 'teacher') {
      const subjects = await subjectsCollection.find({ teacherId: req.user._id }).sort({ name: 1 }).toArray();
      const result = [];
      for (const s of subjects) {
        const memberCount = await enrollmentsCollection.countDocuments({ subjectId: s._id, status: 'approved' });
        const pendingCount = await enrollmentsCollection.countDocuments({ subjectId: s._id, status: 'pending' });
        result.push({ _id: s._id, name: s.name, code: s.code, teacherName: s.teacherName, memberCount, pendingCount });
      }
      return res.json(result);
    }

    const subjects = await subjectsCollection.find({}).sort({ name: 1 }).toArray();
    const mine = await enrollmentsCollection.find({ userId: req.user._id }).toArray();
    const statusMap = {};
    mine.forEach((e) => { statusMap[String(e.subjectId)] = e.status; });

    res.json(subjects.map((s) => ({
      _id: s._id,
      name: s.name,
      code: s.code,
      teacherName: s.teacherName,
      myStatus: statusMap[String(s._id)] || 'none'
    })));
  } catch (error) {
    console.error('GET /api/subjects error:', error);
    res.status(500).json({ error: 'Failed to fetch subjects' });
  }
});

// POST /api/subjects  { name, code }  - teachers only
app.post('/api/subjects', requireAuth, requireTeacher, async (req, res) => {
  try {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const code = typeof req.body.code === 'string' ? req.body.code.trim().toUpperCase() : '';

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({ error: 'Subject name must be 2 to 80 characters' });
    }
    if (!SUBJECT_CODE_PATTERN.test(code)) {
      return res.status(400).json({ error: 'Subject code must be 2 to 12 letters, numbers or dashes (example: CS235AI)' });
    }

    const subject = { name, code, teacherId: req.user._id, teacherName: req.user.name, createdAt: new Date() };
    const result = await subjectsCollection.insertOne(subject);
    subject._id = result.insertedId;

    res.status(201).json({ _id: subject._id, name, code, teacherName: subject.teacherName, memberCount: 0, pendingCount: 0 });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'A subject with this code already exists' });
    }
    console.error('POST /api/subjects error:', error);
    res.status(500).json({ error: 'Failed to create subject' });
  }
});

// POST /api/subjects/:id/join  - students only. Sends a join request to the subject's teacher.
app.post('/api/subjects/:id/join', requireAuth, requireStudent, async (req, res) => {
  try {
    const subjectId = parseId(req.params.id);
    if (!subjectId) {
      return res.status(400).json({ error: 'Invalid subject ID format' });
    }

    const subject = await subjectsCollection.findOne({ _id: subjectId });
    if (!subject) {
      return res.status(404).json({ error: 'Subject not found' });
    }

    const existing = await enrollmentsCollection.findOne({ subjectId, userId: req.user._id });
    if (existing && existing.status === 'approved') {
      return res.status(409).json({ error: 'You are already in this subject' });
    }
    if (existing && existing.status === 'pending') {
      return res.status(409).json({ error: 'Your request is already waiting for the teacher' });
    }
    if (existing && existing.status === 'rejected') {
      // Rejected students may ask again
      await enrollmentsCollection.updateOne(
        { _id: existing._id },
        { $set: { status: 'pending', requestedAt: new Date(), decidedAt: null } }
      );
      return res.json({ message: 'Request sent again', status: 'pending' });
    }

    await enrollmentsCollection.insertOne({
      subjectId,
      userId: req.user._id,
      usn: req.user.usn,
      name: req.user.name,
      status: 'pending',
      requestedAt: new Date(),
      decidedAt: null
    });

    res.status(201).json({ message: 'Request sent', status: 'pending' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'Your request is already waiting for the teacher' });
    }
    console.error(`POST /api/subjects/${req.params.id}/join error:`, error);
    res.status(500).json({ error: 'Failed to send request' });
  }
});

// GET /api/subjects/:id/requests  - the subject's teacher only. Pending requests and members.
app.get('/api/subjects/:id/requests', requireAuth, requireTeacher, async (req, res) => {
  try {
    const subjectId = parseId(req.params.id);
    if (!subjectId) {
      return res.status(400).json({ error: 'Invalid subject ID format' });
    }

    const subject = await subjectsCollection.findOne({ _id: subjectId });
    if (!subject) {
      return res.status(404).json({ error: 'Subject not found' });
    }
    if (!sameId(subject.teacherId, req.user._id)) {
      return res.status(403).json({ error: 'Only this subject\'s teacher can see its requests' });
    }

    const list = await enrollmentsCollection
      .find({ subjectId }, { projection: { userId: 0 } })
      .sort({ requestedAt: 1 })
      .toArray();

    res.json(list);
  } catch (error) {
    console.error(`GET /api/subjects/${req.params.id}/requests error:`, error);
    res.status(500).json({ error: 'Failed to fetch requests' });
  }
});

// PATCH /api/enrollments/:id  { status: 'approved' | 'rejected' }  - the subject's teacher only
app.patch('/api/enrollments/:id', requireAuth, requireTeacher, async (req, res) => {
  try {
    const enrollmentId = parseId(req.params.id);
    if (!enrollmentId) {
      return res.status(400).json({ error: 'Invalid request ID format' });
    }

    const { status } = req.body;
    if (status !== 'approved' && status !== 'rejected') {
      return res.status(400).json({ error: 'status must be "approved" or "rejected"' });
    }

    const enrollment = await enrollmentsCollection.findOne({ _id: enrollmentId });
    if (!enrollment) {
      return res.status(404).json({ error: 'Request not found' });
    }

    const subject = await subjectsCollection.findOne({ _id: enrollment.subjectId });
    if (!subject || !sameId(subject.teacherId, req.user._id)) {
      return res.status(403).json({ error: 'Only this subject\'s teacher can decide' });
    }

    await enrollmentsCollection.updateOne(
      { _id: enrollmentId },
      { $set: { status, decidedAt: new Date() } }
    );

    res.json({ _id: enrollmentId, status });
  } catch (error) {
    console.error(`PATCH /api/enrollments/${req.params.id} error:`, error);
    res.status(500).json({ error: 'Failed to update request' });
  }
});

// ---------- Quiz routes ----------

// GET /api/quizzes  (optional ?search= on title, ?subjectId= to filter)
// Only quizzes from the user's subjects. Each comes with its status (upcoming / ongoing / closed)
// and, for students, a summary of their own attempt. No questions, no answers.
app.get('/api/quizzes', requireAuth, async (req, res) => {
  try {
    const now = new Date();
    let subjectIds = await accessibleSubjectIds(req.user);

    if (req.query.subjectId) {
      const only = parseId(req.query.subjectId);
      if (!only) {
        return res.status(400).json({ error: 'Invalid subject ID format' });
      }
      subjectIds = subjectIds.filter((id) => sameId(id, only));
    }

    const filter = { subjectId: { $in: subjectIds } };
    if (req.query.search && req.query.search.trim() !== '') {
      filter.title = { $regex: new RegExp(escapeRegex(req.query.search.trim()), 'i') };
    }

    const quizzes = await quizzesCollection.find(filter).sort({ createdAt: -1 }).toArray();

    // The logged-in student's attempts, so each card can show Start / Resume / Submitted
    const attemptMap = {};
    if (roleOf(req.user) === 'student') {
      const mine = await attemptsCollection.find({ usn: req.user.usn }).toArray();
      mine.forEach((a) => { attemptMap[String(a.quizId)] = a; });
    }

    res.json(quizzes.map((q) => {
      const attempt = attemptMap[String(q._id)] || null;
      return {
        ...quizMeta(q, now),
        isMine: sameId(q.createdBy, req.user._id),
        myAttempt: attemptSummary(q, attempt, now),
        canReview: roleOf(req.user) === 'teacher' ? true : canReview(q, attempt, now)
      };
    }));
  } catch (error) {
    console.error('GET /api/quizzes error:', error);
    res.status(500).json({ error: 'Failed to fetch quizzes' });
  }
});

// POST /api/quizzes  (create a quiz) - teachers only, in one of their own subjects
// Body: { title, subjectId, questions, opensAt?, closesAt?, timeLimitMinutes? }
app.post('/api/quizzes', requireAuth, requireTeacher, async (req, res) => {
  try {
    const validationError = validateQuestions(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const subjectId = parseId(req.body.subjectId);
    if (!subjectId) {
      return res.status(400).json({ error: 'Choose a subject for this quiz' });
    }
    const subject = await subjectsCollection.findOne({ _id: subjectId });
    if (!subject) {
      return res.status(404).json({ error: 'Subject not found' });
    }
    if (!sameId(subject.teacherId, req.user._id)) {
      return res.status(403).json({ error: 'You can only add quizzes to your own subjects' });
    }

    const opens = readOptionalDate(req.body.opensAt, 'Opening time');
    if (opens.error) return res.status(400).json({ error: opens.error });
    const closes = readOptionalDate(req.body.closesAt, 'Closing time');
    if (closes.error) return res.status(400).json({ error: closes.error });

    const now = new Date();
    if (closes.value && closes.value <= now) {
      return res.status(400).json({ error: 'Closing time must be in the future' });
    }
    if (opens.value && closes.value && closes.value <= opens.value) {
      return res.status(400).json({ error: 'Closing time must be after the opening time' });
    }

    let timeLimitMinutes = null;
    const rawLimit = req.body.timeLimitMinutes;
    if (rawLimit !== undefined && rawLimit !== null && rawLimit !== '') {
      if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > MAX_TIME_LIMIT_MINUTES) {
        return res.status(400).json({ error: `Time limit must be a whole number of minutes from 1 to ${MAX_TIME_LIMIT_MINUTES}` });
      }
      timeLimitMinutes = rawLimit;
    }

    const newQuiz = {
      title: req.body.title.trim(),
      subjectId,
      subjectName: subject.name,
      questions: req.body.questions.map((q) => ({
        text: q.text.trim(),
        options: q.options.map((o) => o.trim()),
        correctIndex: q.correctIndex
      })),
      opensAt: opens.value,
      closesAt: closes.value,
      timeLimitMinutes,
      createdBy: req.user._id,
      createdByName: req.user.name,
      createdAt: now
    };

    const result = await quizzesCollection.insertOne(newQuiz);
    newQuiz._id = result.insertedId;

    res.status(201).json(quizMeta(newQuiz, now));
  } catch (error) {
    console.error('POST /api/quizzes error:', error);
    res.status(500).json({ error: 'Failed to create quiz' });
  }
});

// GET /api/quizzes/:id  ->  quiz details and your attempt. No questions: those come from /start.
app.get('/api/quizzes/:id', requireAuth, async (req, res) => {
  try {
    const quiz = await loadQuizForUser(req, res);
    if (!quiz) return;

    const now = new Date();
    const attempt = roleOf(req.user) === 'student'
      ? await attemptsCollection.findOne({ quizId: quiz._id, usn: req.user.usn })
      : null;

    res.json({
      ...quizMeta(quiz, now),
      isMine: sameId(quiz.createdBy, req.user._id),
      myAttempt: attemptSummary(quiz, attempt, now),
      canReview: roleOf(req.user) === 'teacher' ? true : canReview(quiz, attempt, now),
      serverNow: now
    });
  } catch (error) {
    console.error(`GET /api/quizzes/${req.params.id} error:`, error);
    res.status(500).json({ error: 'Failed to fetch quiz' });
  }
});

// POST /api/quizzes/:id/start  - students only. Starts the timer and sends the questions (no answers).
// Calling it again while the attempt is running resumes it with the same deadline.
app.post('/api/quizzes/:id/start', requireAuth, requireStudent, async (req, res) => {
  try {
    const quiz = await loadQuizForUser(req, res);
    if (!quiz) return;

    const now = new Date();
    const status = quizStatus(quiz, now);
    if (status === 'upcoming') {
      return res.status(403).json({ error: 'This quiz has not opened yet', opensAt: quiz.opensAt });
    }

    let attempt = await attemptsCollection.findOne({ quizId: quiz._id, usn: req.user.usn });

    if (!attempt) {
      if (status === 'closed') {
        return res.status(403).json({ error: 'This quiz is closed' });
      }

      // Deadline = start + time limit, but never later than the closing time
      let deadline = null;
      if (quiz.timeLimitMinutes) {
        deadline = new Date(now.getTime() + quiz.timeLimitMinutes * 60 * 1000);
      }
      if (quiz.closesAt && (!deadline || quiz.closesAt < deadline)) {
        deadline = quiz.closesAt;
      }

      const newAttempt = {
        quizId: quiz._id,
        userId: req.user._id,
        usn: req.user.usn,
        name: req.user.name,
        status: 'in-progress',
        startedAt: now,
        deadline,
        answers: null,
        score: null,
        total: quiz.questions.length,
        takenAt: null
      };

      try {
        const result = await attemptsCollection.insertOne(newAttempt);
        newAttempt._id = result.insertedId;
        attempt = newAttempt;
      } catch (error) {
        // Two Start clicks at once: the unique index keeps only one attempt
        if (error.code !== 11000) throw error;
        attempt = await attemptsCollection.findOne({ quizId: quiz._id, usn: req.user.usn });
      }
    }

    const state = attemptState(attempt, now);
    if (state === 'submitted') {
      return res.status(409).json({ error: 'You have already attempted this quiz' });
    }
    if (state === 'expired') {
      return res.status(409).json({ error: 'Your time for this quiz has run out' });
    }

    res.json({
      quiz: quizMeta(quiz, now),
      questions: publicQuestions(quiz),
      startedAt: attempt.startedAt,
      deadline: attempt.deadline,
      serverNow: now
    });
  } catch (error) {
    console.error(`POST /api/quizzes/${req.params.id}/start error:`, error);
    res.status(500).json({ error: 'Failed to start quiz' });
  }
});

// POST /api/quizzes/:id/submit  { answers: [0, 2, -1, ...] }  - students only. The server scores it.
app.post('/api/quizzes/:id/submit', requireAuth, requireStudent, async (req, res) => {
  try {
    const quiz = await loadQuizForUser(req, res);
    if (!quiz) return;

    const now = new Date();
    const attempt = await attemptsCollection.findOne({ quizId: quiz._id, usn: req.user.usn });
    if (!attempt) {
      return res.status(400).json({ error: 'Start the quiz before submitting' });
    }

    const state = attemptState(attempt, now);
    if (state === 'submitted') {
      return res.status(409).json({ error: 'You have already submitted this quiz' });
    }
    if (state === 'expired') {
      await attemptsCollection.updateOne({ _id: attempt._id, status: 'in-progress' }, { $set: { status: 'expired' } });
      return res.status(403).json({ error: 'Time is up. Answers sent after the time limit are not accepted' });
    }

    const { answers } = req.body;
    if (!Array.isArray(answers) || answers.length !== quiz.questions.length) {
      return res.status(400).json({ error: `answers must be a list with exactly ${quiz.questions.length} entries` });
    }

    // Score on the server. -1 or null means the question was skipped.
    let score = 0;
    const cleanAnswers = [];
    for (let i = 0; i < quiz.questions.length; i++) {
      const a = answers[i];
      const skipped = a === null || a === -1;
      if (!skipped && (!Number.isInteger(a) || a < 0 || a >= quiz.questions[i].options.length)) {
        return res.status(400).json({ error: `Answer ${i + 1} is not a valid option` });
      }
      cleanAnswers.push(skipped ? -1 : a);
      if (a === quiz.questions[i].correctIndex) score++;
    }

    // Only an attempt that is still in progress can be submitted, so a double click can't submit twice
    const result = await attemptsCollection.updateOne(
      { _id: attempt._id, status: 'in-progress' },
      { $set: { status: 'submitted', answers: cleanAnswers, score, takenAt: now } }
    );
    if (result.modifiedCount === 0) {
      return res.status(409).json({ error: 'You have already submitted this quiz' });
    }

    const reviewNow = !quiz.closesAt || now >= quiz.closesAt;
    res.status(201).json({
      score,
      total: quiz.questions.length,
      reviewOpensAt: quiz.closesAt || now,
      canReview: reviewNow
    });
  } catch (error) {
    console.error(`POST /api/quizzes/${req.params.id}/submit error:`, error);
    res.status(500).json({ error: 'Failed to submit quiz' });
  }
});

// GET /api/quizzes/:id/review
// Student: their answers next to the correct ones, only after the quiz has closed.
// Teacher (subject owner): the answer key at any time.
app.get('/api/quizzes/:id/review', requireAuth, async (req, res) => {
  try {
    const quiz = await loadQuizForUser(req, res);
    if (!quiz) return;

    const now = new Date();
    const base = {
      ...quizMeta(quiz, now),
      questions: quiz.questions.map((q) => ({ text: q.text, options: q.options, correctIndex: q.correctIndex }))
    };

    if (roleOf(req.user) === 'teacher') {
      return res.json({ ...base, mode: 'answer-key' });
    }

    const attempt = await attemptsCollection.findOne({ quizId: quiz._id, usn: req.user.usn });
    const state = attemptState(attempt, now);
    if (state !== 'submitted' && state !== 'expired') {
      return res.status(403).json({ error: 'You can only review a quiz you have attempted' });
    }
    if (!canReview(quiz, attempt, now)) {
      return res.status(403).json({ error: 'Review opens after the quiz closes', reviewOpensAt: quiz.closesAt });
    }

    const myAnswers = Array.isArray(attempt.answers) ? attempt.answers : [];
    res.json({
      ...base,
      mode: 'my-review',
      score: state === 'submitted' ? attempt.score : 0,
      total: attempt.total,
      state,
      questions: base.questions.map((q, i) => ({ ...q, myAnswer: myAnswers[i] !== undefined ? myAnswers[i] : -1 }))
    });
  } catch (error) {
    console.error(`GET /api/quizzes/${req.params.id}/review error:`, error);
    res.status(500).json({ error: 'Failed to load review' });
  }
});

// GET /api/quizzes/:id/leaderboard  (top 10 submitted attempts; earlier finish wins a tie)
app.get('/api/quizzes/:id/leaderboard', requireAuth, async (req, res) => {
  try {
    const quiz = await loadQuizForUser(req, res);
    if (!quiz) return;

    const top = await attemptsCollection
      .find(
        { quizId: quiz._id, status: { $nin: ['in-progress', 'expired'] } },
        { projection: { _id: 0, usn: 1, name: 1, score: 1, total: 1, takenAt: 1 } }
      )
      .sort({ score: -1, takenAt: 1 })
      .limit(10)
      .toArray();

    res.json({ quizId: quiz._id, title: quiz.title, subjectName: quiz.subjectName || '', leaderboard: top });
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
    subjectsCollection = db.collection('subjects');
    enrollmentsCollection = db.collection('enrollments');
    quizzesCollection = db.collection('quizzes');
    attemptsCollection = db.collection('attempts');

    // No two accounts with the same email
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    // No two students with the same USN. "partial" skips teachers, who have no USN.
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
    // Subject codes are unique, and a student has at most one request per subject
    await subjectsCollection.createIndex({ code: 1 }, { unique: true });
    await enrollmentsCollection.createIndex({ subjectId: 1, userId: 1 }, { unique: true });
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