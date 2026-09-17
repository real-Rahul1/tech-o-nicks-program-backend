require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { Session, Registration, CommunityMember } = require('./server/models');

const app = express();
const PORT = process.env.PORT || 3000;

// ── PASSWORD HASHING (built-in crypto, no extra dependency) ──
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const hashToCompare = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(hashToCompare, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.set('trust proxy', 1);

// In production (Render) set NODE_ENV=production so this stays exactly as
// before: only the deployed frontend is allowed, and cookies require HTTPS.
// Locally, set NODE_ENV=development in your .env to relax both.
const isDev = process.env.NODE_ENV === 'development';

const allowedOrigins = [
  'https://tech-o-nicks-program.netlify.app',
  'https://cgeccse.in',
  'https://cgeccse.in/techonicks-program',
  'https://cgeccse.in/techonicks-program/index.html'
  ];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
// Raised limit (default is 100kb) so session banner images sent as base64
// data URIs from the admin panel don't get rejected as "payload too large".
app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    secure: !isDev,
    sameSite: isDev ? 'lax' : 'none',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

mongoose.connection.on('error', err => console.error('Mongoose error:', err));
mongoose.connection.once('open', () => console.log('DB open:', mongoose.connection.name));

const requireAdmin = (req, res, next) => {
  if (req.session.isAdmin) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

const requireStudent = (req, res, next) => {
  if (req.session.studentEmail) return next();
  res.status(401).json({ error: 'Please log in to continue' });
};

// ── AUTH ──
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === (process.env.ADMIN_PASSWORD)) {
    req.session.isAdmin = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/admin/status', (req, res) => {
  res.json({ isAdmin: !!req.session.isAdmin });
});

// ── SESSIONS (public) ──
app.get('/api/sessions', async (req, res) => {
  try {
    const sessions = await Session.find({ isActive: true }).sort({ date: 1 });
    const withCounts = await Promise.all(sessions.map(async s => {
      const count = await Registration.countDocuments({ sessionId: s._id });
      return { ...s.toObject(), registrationCount: count };
    }));
    res.json(withCounts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/sessions/:id', async (req, res) => {
  try {
    const sess = await Session.findById(req.params.id);
    if (!sess) return res.status(404).json({ error: 'Session not found' });
    const regCount = await Registration.countDocuments({ sessionId: req.params.id });
    res.json({ ...sess.toObject(), registrationCount: regCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── STATS (public) ──
app.get('/api/stats/public', async (req, res) => {
  try {
    const activeSessions = await Session.countDocuments({ isActive: true });
    const totalRegistrations = await Registration.countDocuments();
    const totalCommunityMembers = await CommunityMember.countDocuments();
    res.json({ activeSessions, totalRegistrations, totalCommunityMembers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SESSIONS (admin) ──
app.get('/api/admin/sessions', requireAdmin, async (req, res) => {
  try {
    const sessions = await Session.find().sort({ createdAt: -1 });
    const withCounts = await Promise.all(sessions.map(async s => {
      const count = await Registration.countDocuments({ sessionId: s._id });
      return { ...s.toObject(), registrationCount: count };
    }));
    res.json(withCounts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/sessions', requireAdmin, async (req, res) => {
  try {
    const { title, description, speaker, date, endDate, time, duration, venue, meetLink, image, tags, maxCapacity } = req.body;
    // Reject sessions with a past date
    const sessionDate = new Date(date);
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    if (sessionDate < todayStart) {
      return res.status(400).json({ error: 'Session date cannot be in the past.' });
    }
    // If the session spans multiple dates, validate the end date
    let parsedEndDate;
    if (endDate) {
      parsedEndDate = new Date(endDate);
      if (parsedEndDate < sessionDate) {
        return res.status(400).json({ error: 'End date cannot be before the start date.' });
      }
    }
    const sess = new Session({
      title, description, speaker,
      date: new Date(date),
      endDate: parsedEndDate,
      time,
      duration: parseInt(duration, 10),
      venue, meetLink, image,
      maxCapacity: parseInt(maxCapacity, 10) || 100,
      tags: tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []
    });
    await sess.save();
    res.status(201).json(sess);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/admin/sessions/:id', requireAdmin, async (req, res) => {
  try {
    const { tags, date, endDate, duration, maxCapacity, ...rest } = req.body;
    if (tags !== undefined) rest.tags = tags.split(',').map(t => t.trim()).filter(Boolean);
    if (date) rest.date = new Date(date);
    if (duration) rest.duration = parseInt(duration, 10);
    if (maxCapacity) rest.maxCapacity = parseInt(maxCapacity, 10);
    // endDate: a real value sets/updates it, an explicit empty string clears it
    // back to a single-day session, and omitting it entirely leaves it untouched.
    if (endDate) {
      const startDate = rest.date || (await Session.findById(req.params.id))?.date;
      if (startDate && new Date(endDate) < new Date(startDate)) {
        return res.status(400).json({ error: 'End date cannot be before the start date.' });
      }
      rest.endDate = new Date(endDate);
    } else if (endDate === '') {
      rest.endDate = null;
    }
    const sess = await Session.findByIdAndUpdate(req.params.id, rest, { new: true });
    res.json(sess);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/admin/sessions/:id', requireAdmin, async (req, res) => {
  try {
    await Session.findByIdAndDelete(req.params.id);
    await Registration.deleteMany({ sessionId: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/admin/sessions/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const sess = await Session.findById(req.params.id);
    sess.isActive = !sess.isActive;
    await sess.save();
    res.json(sess);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── SESSION REGISTRATIONS ──
app.post('/api/register', async (req, res) => {
  try {
    const { sessionId, fullName, email, phone, college, branch, year, googleAccountEmail, experience, motivation } = req.body;
    const sess = await Session.findById(sessionId);
    if (!sess || !sess.isActive) return res.status(400).json({ error: 'Session not available' });
    const regCount = await Registration.countDocuments({ sessionId });
    if (regCount >= sess.maxCapacity) return res.status(400).json({ error: 'Session is full' });
    const existing = await Registration.findOne({ email, sessionId });
    if (existing) return res.status(400).json({ error: 'You are already registered for this session' });
    const reg = new Registration({ sessionId, fullName, email, phone, college, branch, year, googleAccountEmail, experience, motivation });
    await reg.save();
    res.status(201).json({ success: true, registration: reg });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Already registered for this session' });
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/admin/sessions/:id/registrations', requireAdmin, async (req, res) => {
  try {
    const regs = await Registration.find({ sessionId: req.params.id }).sort({ registeredAt: -1 });
    res.json(regs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/registrations/:id', requireAdmin, async (req, res) => {
  try {
    const reg = await Registration.findByIdAndDelete(req.params.id);
    if (!reg) return res.status(404).json({ error: 'Registration not found' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── COMMUNITY MEMBERS ──
app.post('/api/community/join', async (req, res) => {
  try {
    const { fullName, email, password, rollNumber, phone, college, branch, year, interests, experience, whyJoin } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }
    if (!rollNumber || !rollNumber.trim()) {
      return res.status(400).json({ error: 'Roll number is required.' });
    }

    const existing = await CommunityMember.findOne({ email });
    if (existing) return res.status(400).json({ error: 'You have already joined the community with this email.' });

    const existingRoll = await CommunityMember.findOne({ rollNumber: rollNumber.trim().toUpperCase() });
    if (existingRoll) return res.status(400).json({ error: 'This roll number has already been used to join the community.' });

    const member = new CommunityMember({
      fullName, email, phone, college, branch, year,
      passwordHash: hashPassword(password),
      rollNumber,
      interests: Array.isArray(interests) ? interests : (interests ? interests.split(',').map(i => i.trim()).filter(Boolean) : []),
      experience, whyJoin
    });
    await member.save();
    const { passwordHash, ...safeMember } = member.toObject();
    res.status(201).json({ success: true, member: safeMember });
  } catch (err) {
    if (err.code === 11000) {
      const field = err.keyPattern && err.keyPattern.rollNumber ? 'roll number' : 'email';
      return res.status(400).json({ error: `This ${field} is already registered in the community.` });
    }
    res.status(400).json({ error: err.message });
  }
});

// ── STUDENT AUTH (community members log in with email + password) ──
app.post('/api/student/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
    const member = await CommunityMember.findOne({ email: email.trim().toLowerCase() });
    if (!member || !verifyPassword(password, member.passwordHash)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    req.session.studentEmail = member.email;
    const { passwordHash, ...safeMember } = member.toObject();
    res.json({ success: true, member: safeMember });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/student/logout', (req, res) => {
  delete req.session.studentEmail;
  res.json({ success: true });
});

app.get('/api/student/status', async (req, res) => {
  if (!req.session.studentEmail) return res.json({ loggedIn: false });
  try {
    const member = await CommunityMember.findOne({ email: req.session.studentEmail }).select('-passwordHash');
    if (!member) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, member });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// A logged-in student registers for a session using only their saved community
// profile — no need to retype their details.
app.post('/api/student/register', requireStudent, async (req, res) => {
  try {
    const { sessionId } = req.body;
    const member = await CommunityMember.findOne({ email: req.session.studentEmail });
    if (!member) return res.status(401).json({ error: 'Please log in again.' });

    const sess = await Session.findById(sessionId);
    if (!sess || !sess.isActive) return res.status(400).json({ error: 'Session not available' });
    const regCount = await Registration.countDocuments({ sessionId });
    if (regCount >= sess.maxCapacity) return res.status(400).json({ error: 'Session is full' });
    const existing = await Registration.findOne({ email: member.email, sessionId });
    if (existing) return res.status(400).json({ error: 'You are already registered for this session' });

    const reg = new Registration({
      sessionId,
      fullName: member.fullName,
      email: member.email,
      phone: member.phone,
      college: member.college,
      branch: member.branch,
      year: member.year,
      googleAccountEmail: member.email,
      experience: member.experience
    });
    await reg.save();
    res.status(201).json({ success: true, registration: reg });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Already registered for this session' });
    res.status(400).json({ error: err.message });
  }
});

// Sessions the logged-in student has joined
app.get('/api/student/my-sessions', requireStudent, async (req, res) => {
  try {
    const regs = await Registration.find({ email: req.session.studentEmail }).sort({ registeredAt: -1 });
    const withSessions = await Promise.all(regs.map(async r => {
      const sess = await Session.findById(r.sessionId);
      return { registration: r, session: sess };
    }));
    res.json(withSessions.filter(x => x.session));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/community', requireAdmin, async (req, res) => {
  try {
    const members = await CommunityMember.find().sort({ joinedAt: -1 }).select('-passwordHash');
    res.json(members);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/community/:id', requireAdmin, async (req, res) => {
  try {
    const member = await CommunityMember.findByIdAndDelete(req.params.id);
    if (!member) return res.status(404).json({ error: 'Member not found' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── STATS ──
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    // Only count sessions whose date is today or in the future
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const totalSessions = await Session.countDocuments({ date: { $gte: todayStart } });
    const activeSessions = await Session.countDocuments({ isActive: true, date: { $gte: todayStart } });
    const totalRegistrations = await Registration.countDocuments();
    const totalCommunityMembers = await CommunityMember.countDocuments();
    res.json({ totalSessions, activeSessions, totalRegistrations, totalCommunityMembers });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));