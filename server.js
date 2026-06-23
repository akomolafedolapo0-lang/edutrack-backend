// ════════════════════════════════════════════
// EduTrack AI — Backend Server (v2: Multi-School + Login)
// ════════════════════════════════════════════
// What's new compared to the old server.js:
//   1. A real database (SQLite, stored in one file: edutrack.db) — no more
//      losing data when a browser's storage is cleared.
//   2. Login support — each school has a username + password. Logging in
//      gives back a "token" (like a temporary pass) that proves who they
//      are on every later request, so School A can never see School B's
//      students.
//   3. The same AI proxy as before — still keeps your Anthropic key safe,
//      schools never see it.
//
// You (the owner) create each school's login using the /admin/create-school
// route below — schools never sign themselves up.
// ════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// ── CONFIG ──
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '*';
const PORT = process.env.PORT || 3000;

// JWT_SECRET signs login tokens so they can't be forged. Render generates
// a random one for you automatically if you don't set it — see
// DEPLOY_README_V2.md for how that works.
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';

// ADMIN_PASSWORD protects the /admin routes (creating new schools).
// This is YOUR password, not a school's. Set it in Render's Environment
// Variables, same place as your Anthropic key.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ANTHROPIC_API_KEY) {
  console.error('❌ ANTHROPIC_API_KEY is not set. AI features will fail until you set it.');
}
if (!ADMIN_PASSWORD) {
  console.error('❌ ADMIN_PASSWORD is not set. You will not be able to create new school logins until you set it.');
}

// ── DATABASE SETUP ──
// This creates (or opens, if it already exists) a single file called
// edutrack.db sitting next to this server. All schools' data lives in
// here, kept separate by school_id on every table.
const db = new Database('edutrack.db');
db.pragma('journal_mode = WAL'); // safer for concurrent reads/writes

db.exec(`
  CREATE TABLE IF NOT EXISTS schools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    school_name TEXT,
    school_addr TEXT,
    principal TEXT,
    motto TEXT,
    logo TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY,
    school_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (school_id) REFERENCES schools(id)
  );

  CREATE INDEX IF NOT EXISTS idx_students_school ON students(school_id);
`);

console.log('Database ready: edutrack.db');

// ── MIDDLEWARE ──
app.use(express.json({ limit: '5mb' }));
app.use(cors({
  origin: ALLOWED_ORIGINS === '*' ? '*' : ALLOWED_ORIGINS.split(',').map(s => s.trim()),
}));

// ── AUTH HELPERS ──
function requireSchoolAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.schoolId = payload.schoolId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }
}

function requireAdmin(req, res, next) {
  const providedPassword = req.headers['x-admin-password'];
  if (!ADMIN_PASSWORD || providedPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid admin password.' });
  }
  next();
}

// ── BASIC RATE LIMITING ──
const requestLog = new Map();
const MAX_REQUESTS_PER_MINUTE = 30;
function isRateLimited(key) {
  const now = Date.now();
  const windowStart = now - 60_000;
  const timestamps = (requestLog.get(key) || []).filter(t => t > windowStart);
  timestamps.push(now);
  requestLog.set(key, timestamps);
  return timestamps.length > MAX_REQUESTS_PER_MINUTE;
}
setInterval(() => {
  const windowStart = Date.now() - 60_000;
  for (const [key, timestamps] of requestLog.entries()) {
    const recent = timestamps.filter(t => t > windowStart);
    if (recent.length === 0) requestLog.delete(key);
    else requestLog.set(key, recent);
  }
}, 5 * 60_000);

// ── HEALTH CHECK ──
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'EduTrack AI backend (v2)',
    apiKeyConfigured: Boolean(ANTHROPIC_API_KEY),
    adminConfigured: Boolean(ADMIN_PASSWORD),
  });
});

// ════════════════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════════════════
app.post('/admin/create-school', requireAdmin, (req, res) => {
  const { username, password, schoolName } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password should be at least 6 characters.' });
  }

  const existing = db.prepare('SELECT id FROM schools WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'That username is already taken. Choose another.' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO schools (username, password_hash, school_name) VALUES (?, ?, ?)'
  ).run(username, passwordHash, schoolName || '');

  res.json({ success: true, schoolId: result.lastInsertRowid, username });
});

app.get('/admin/schools', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, school_name, created_at FROM schools').all();
  res.json({ schools: rows });
});

app.post('/admin/reset-password', requireAdmin, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'username and a newPassword (6+ chars) are required.' });
  }
  const passwordHash = bcrypt.hashSync(newPassword, 10);
  const result = db.prepare('UPDATE schools SET password_hash = ? WHERE username = ?').run(passwordHash, username);
  if (result.changes === 0) return res.status(404).json({ error: 'No school found with that username.' });
  res.json({ success: true });
});

// ════════════════════════════════════════════
// SCHOOL LOGIN
// ════════════════════════════════════════════
app.post('/auth/login', (req, res) => {
  const ip = req.ip || 'unknown';
  if (isRateLimited('login:' + ip)) {
    return res.status(429).json({ error: 'Too many login attempts. Please wait a moment.' });
  }

  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const school = db.prepare('SELECT * FROM schools WHERE username = ?').get(username);
  if (!school || !bcrypt.compareSync(password, school.password_hash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const token = jwt.sign({ schoolId: school.id, username: school.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({
    token,
    school: {
      id: school.id,
      username: school.username,
      schoolName: school.school_name,
      schoolAddr: school.school_addr,
      principal: school.principal,
      motto: school.motto,
      logo: school.logo,
    },
  });
});

// ════════════════════════════════════════════
// SCHOOL DATA ROUTES
// ════════════════════════════════════════════
app.get('/api/school-data', requireSchoolAuth, (req, res) => {
  const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(req.schoolId);
  const studentRows = db.prepare('SELECT data FROM students WHERE school_id = ?').all(req.schoolId);
  const students = studentRows.map(row => JSON.parse(row.data));

  res.json({
    schoolDetails: {
      name: school.school_name,
      addr: school.school_addr,
      principal: school.principal,
      motto: school.motto,
    },
    logo: school.logo,
    students,
  });
});

app.post('/api/school-details', requireSchoolAuth, (req, res) => {
  const { name, addr, principal, motto } = req.body || {};
  db.prepare(
    'UPDATE schools SET school_name = ?, school_addr = ?, principal = ?, motto = ? WHERE id = ?'
  ).run(name || '', addr || '', principal || '', motto || '', req.schoolId);
  res.json({ success: true });
});

app.post('/api/school-logo', requireSchoolAuth, (req, res) => {
  const { logo } = req.body || {};
  db.prepare('UPDATE schools SET logo = ? WHERE id = ?').run(logo || null, req.schoolId);
  res.json({ success: true });
});

app.post('/api/students', requireSchoolAuth, (req, res) => {
  const student = req.body;
  if (!student || !student.id) {
    return res.status(400).json({ error: 'Student data with an id is required.' });
  }
  const data = JSON.stringify(student);
  db.prepare(`
    INSERT INTO students (id, school_id, data, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
  `).run(student.id, req.schoolId, data);
  res.json({ success: true });
});

app.post('/api/students/bulk', requireSchoolAuth, (req, res) => {
  const { students } = req.body || {};
  if (!Array.isArray(students)) {
    return res.status(400).json({ error: 'students must be an array.' });
  }
  const insert = db.prepare(`
    INSERT INTO students (id, school_id, data, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
  `);
  const insertMany = db.transaction((rows) => {
    for (const s of rows) insert.run(s.id, req.schoolId, JSON.stringify(s));
  });
  insertMany(students);
  res.json({ success: true, count: students.length });
});

app.delete('/api/students/:id', requireSchoolAuth, (req, res) => {
  db.prepare('DELETE FROM students WHERE id = ? AND school_id = ?').run(req.params.id, req.schoolId);
  res.json({ success: true });
});

app.delete('/api/students', requireSchoolAuth, (req, res) => {
  db.prepare('DELETE FROM students WHERE school_id = ?').run(req.schoolId);
  res.json({ success: true });
});

// ════════════════════════════════════════════
// AI PROXY
// ════════════════════════════════════════════
app.post('/api/generate', requireSchoolAuth, async (req, res) => {
  if (isRateLimited('ai:' + req.schoolId)) {
    return res.status(429).json({ error: 'Too many AI requests right now. Please wait a moment and try again.' });
  }
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is not configured with an API key yet.' });
  }

  const { prompt, max_tokens } = req.body || {};
  if (!prompt || typeof prompt !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "prompt" in request body.' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: Math.min(Math.max(Number(max_tokens) || 1000, 1), 2000),
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      console.error('Anthropic API error:', data);
      return res.status(response.status).json({ error: data.error?.message || 'AI service returned an error.' });
    }
    res.json({ text: data.content?.[0]?.text || '' });
  } catch (err) {
    console.error('Request to Anthropic failed:', err);
    res.status(502).json({ error: 'Could not reach the AI service. Please try again shortly.' });
  }
});

app.listen(PORT, () => {
  console.log(`EduTrack AI backend (v2) running on port ${PORT}`);
  console.log(`API key configured: ${Boolean(ANTHROPIC_API_KEY)}`);
  console.log(`Admin password configured: ${Boolean(ADMIN_PASSWORD)}`);
});
