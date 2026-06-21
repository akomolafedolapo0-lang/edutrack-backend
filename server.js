// ════════════════════════════════════════════
// EduTrack AI — Backend Proxy Server
// ════════════════════════════════════════════
// What this does:
//   EduTrack (the HTML file each school uses) sends AI requests to THIS
//   server instead of talking to Anthropic directly. This server holds
//   your Anthropic API key (as an environment variable, never written
//   in any file) and forwards the request on the school's behalf.
//
// Why this matters:
//   If the key lived inside the HTML file, anyone at the school could
//   open their browser's dev tools and read it straight out of the page,
//   then use it to rack up charges on YOUR account. Routing through this
//   server means the key never reaches the school's computer at all.
//
// You do not need to fully understand this file to use it — see
// DEPLOY_README.md for the actual steps. This comment block is here so
// future-you (or anyone you hire later) can see what it does at a glance.
// ════════════════════════════════════════════

const express = require('express');
const cors = require('cors');

const app = express();

// ── CONFIG ──
// Your Anthropic key is read from an environment variable, set on
// whatever hosting platform you use (Render, Railway, etc). It is
// NEVER written into this file. See DEPLOY_README.md, step "Add your API key".
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Comma-separated list of school domains/URLs allowed to call this server.
// Example: "https://greenfield-college.netlify.app,https://stmarys-edutrack.netlify.app"
// Leave as "*" while testing, but lock it down once schools are live —
// otherwise anyone could point their own page at your server and spend
// your API budget.
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '*';

const PORT = process.env.PORT || 3000;

if (!ANTHROPIC_API_KEY) {
  console.error('❌ ANTHROPIC_API_KEY is not set. The server will start, but every AI request will fail until you set it.');
}

// ── MIDDLEWARE ──
app.use(express.json({ limit: '2mb' }));

app.use(cors({
  origin: ALLOWED_ORIGINS === '*' ? '*' : ALLOWED_ORIGINS.split(',').map(s => s.trim()),
}));

// ── BASIC RATE LIMITING ──
// Keeps one school (or one bad actor) from burning through your whole
// Anthropic budget. This is intentionally simple — an in-memory counter,
// reset every minute. Good enough for a handful of schools; if you scale
// to dozens, swap this for a proper rate-limiting library.
const requestLog = new Map(); // ip -> [timestamps]
const MAX_REQUESTS_PER_MINUTE = 20;

function isRateLimited(ip) {
  const now = Date.now();
  const windowStart = now - 60_000;
  const timestamps = (requestLog.get(ip) || []).filter(t => t > windowStart);
  timestamps.push(now);
  requestLog.set(ip, timestamps);
  return timestamps.length > MAX_REQUESTS_PER_MINUTE;
}

// Clean up old entries every 5 minutes so memory doesn't grow forever
setInterval(() => {
  const windowStart = Date.now() - 60_000;
  for (const [ip, timestamps] of requestLog.entries()) {
    const recent = timestamps.filter(t => t > windowStart);
    if (recent.length === 0) requestLog.delete(ip);
    else requestLog.set(ip, recent);
  }
}, 5 * 60_000);

// ── HEALTH CHECK ──
// Visit https://your-server-url/ in a browser to confirm the server is
// running at all, separate from whether the API key works.
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'EduTrack AI backend',
    apiKeyConfigured: Boolean(ANTHROPIC_API_KEY),
  });
});

// ── MAIN ENDPOINT ──
// EduTrack's frontend calls this instead of api.anthropic.com directly.
// Expects: { prompt: string, max_tokens?: number }
// Returns: { text: string } on success, or { error: string } on failure.
app.post('/api/generate', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';

  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many requests right now. Please wait a moment and try again.' });
  }

  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is not configured with an API key yet. Contact your EduTrack provider.' });
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
        max_tokens: Math.min(Math.max(Number(max_tokens) || 1000, 1), 2000), // clamp 1–2000
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Anthropic API error:', data);
      return res.status(response.status).json({ error: data.error?.message || 'AI service returned an error.' });
    }

    const text = data.content?.[0]?.text || '';
    return res.json({ text });

  } catch (err) {
    console.error('Request to Anthropic failed:', err);
    return res.status(502).json({ error: 'Could not reach the AI service. Please try again shortly.' });
  }
});

app.listen(PORT, () => {
  console.log(`EduTrack AI backend running on port ${PORT}`);
  console.log(`API key configured: ${Boolean(ANTHROPIC_API_KEY)}`);
});
