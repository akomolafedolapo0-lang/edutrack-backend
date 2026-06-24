// ════════════════════════════════════════════
// EduTrack AI — Backend Server (v2: Multi-School + Login)
// ════════════════════════════════════════════
// What this does:
//   1. Real, permanent storage — schools and students are saved to a file
//      called data.json sitting next to this server, not in the school's
//      browser. Clearing browser data no longer loses anything.
//   2. Login support — each school has a username + password. Logging in
//      gives back a "token" (like a temporary pass) that proves who they
//      are on every later request, so School A can never see School B's
//      students.
//   3. The same AI proxy as before — still keeps your Anthropic key safe,
//      schools never see it.
//
// You (the owner) create each school's login using the /admin/create-school
// route below — schools never sign themselves up.
//
// Storage note: this uses a plain JSON file instead of a SQL database
// (like SQLite). For a handful of schools and a few hundred students each,
// this is genuinely enough — it avoids a class of deployment problems that
// SQL database packages can run into on some hosting platforms (they need
// to compile native code during install, which can fail). A JSON file
// needs no compiling at all, so it just works everywhere, every time.
// ════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// ── CONFIG ──
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '*';
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ANTHROPIC_API_KEY) {
  console.error('❌ ANTHROPIC_API_KEY is not set. AI features will fail until you set it.');
}
if (!ADMIN_PASSWORD) {
  console.error('❌ ADMIN_PASSWORD is not set. You will not be able to create new school logins until you set it.');
}

// ── STORAGE ──
const DATA_FILE = path.join(__dirname, 'data.json');

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    return { schools: [], students: [], nextSchoolId: 1 };
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (err) {
    console.error('⚠️ Could not parse data.json — starting fresh. Original file backed up as data.json.bak');
    if (fs.existsSync(DATA_FILE)) fs.copyFileSync(DATA_FILE, DATA_FILE + '.bak');
    return { schools: [], students: [], nextSchoolId: 1 };
  }
}

function saveData(data) {
  const tmpFile = DATA_FILE + '.tmp';
  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2));
  fs.renameSync(tmpFile, DATA_FILE);
}

let data = loadData();
console.log(`Database ready: data.json (${data.schools.length} schools, ${data.students.length} students)`);

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
    schools: data.schools.length,
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

  const existing = data.schools.find(s => s.username === username);
  if (existing) {
    return res.status(409).json({ error: 'That username is already taken. Choose another.' });
  }

  const newSchool = {
    id: data.nextSchoolId++,
    username,
    password_hash: bcrypt.hashSync(password, 10),
    school_name: schoolName || '',
    school_addr: '',
    principal: '',
    motto: '',
    logo: null,
    created_at: new Date().toISOString(),
  };
  data.schools.push(newSchool);
  saveData(data);

  res.json({ success: true, schoolId: newSchool.id, username });
});

app.get('/admin/schools', requireAdmin, (req, res) => {
  const rows = data.schools.map(s => ({
    id: s.id, username: s.username, school_name: s.school_name, created_at: s.created_at,
  }));
  res.json({ schools: rows });
});

app.post('/admin/reset-password', requireAdmin, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'username and a newPassword (6+ chars) are required.' });
  }
  const school = data.schools.find(s => s.username === username);
  if (!school) return res.status(404).json({ error: 'No school found with that username.' });
  school.password_hash = bcrypt.hashSync(newPassword, 10);
  saveData(data);
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

  const school = data.schools.find(s => s.username === username);
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
  const school = data.schools.find(s => s.id === req.schoolId);
  if (!school) return res.status(404).json({ error: 'School not found.' });
  const students = data.students.filter(s => s.school_id === req.schoolId).map(s => s.payload);

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
  const school = data.schools.find(s => s.id === req.schoolId);
  if (!school) return res.status(404).json({ error: 'School not found.' });
  const { name, addr, principal, motto } = req.body || {};
  school.school_name = name || '';
  school.school_addr = addr || '';
  school.principal = principal || '';
  school.motto = motto || '';
  saveData(data);
  res.json({ success: true });
});

app.post('/api/school-logo', requireSchoolAuth, (req, res) => {
  const school = data.schools.find(s => s.id === req.schoolId);
  if (!school) return res.status(404).json({ error: 'School not found.' });
  const { logo } = req.body || {};
  school.logo = logo || null;
  saveData(data);
  res.json({ success: true });
});

app.post('/api/students', requireSchoolAuth, (req, res) => {
  const student = req.body;
  if (!student || !student.id) {
    return res.status(400).json({ error: 'Student data with an id is required.' });
  }
  const existingIndex = data.students.findIndex(s => s.id === student.id && s.school_id === req.schoolId);
  const record = { id: student.id, school_id: req.schoolId, payload: student, updated_at: new Date().toISOString() };
  if (existingIndex >= 0) data.students[existingIndex] = record;
  else data.students.push(record);
  saveData(data);
  res.json({ success: true });
});

app.post('/api/students/bulk', requireSchoolAuth, (req, res) => {
  const { students } = req.body || {};
  if (!Array.isArray(students)) {
    return res.status(400).json({ error: 'students must be an array.' });
  }
  for (const s of students) {
    const existingIndex = data.students.findIndex(row => row.id === s.id && row.school_id === req.schoolId);
    const record = { id: s.id, school_id: req.schoolId, payload: s, updated_at: new Date().toISOString() };
    if (existingIndex >= 0) data.students[existingIndex] = record;
    else data.students.push(record);
  }
  saveData(data);
  res.json({ success: true, count: students.length });
});

app.delete('/api/students/:id', requireSchoolAuth, (req, res) => {
  data.students = data.students.filter(s => !(s.id === req.params.id && s.school_id === req.schoolId));
  saveData(data);
  res.json({ success: true });
});

app.delete('/api/students', requireSchoolAuth, (req, res) => {
  data.students = data.students.filter(s => s.school_id !== req.schoolId);
  saveData(data);
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
    const responseData = await response.json();
    if (!response.ok) {
      console.error('Anthropic API error:', responseData);
      return res.status(response.status).json({ error: responseData.error?.message || 'AI service returned an error.' });
    }
    res.json({ text: responseData.content?.[0]?.text || '' });
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
