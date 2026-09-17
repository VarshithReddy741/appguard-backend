// AppGuard backend
//
// Purpose: the Android app never has the power to unlock itself. Whenever it
// wants to unlock a blocked app/site, it asks this server for a code. The
// server generates the code and sends it ONLY to the trusted contact (your
// friend) via email or SMS. The phone has to be told the code by the friend
// before /verify-unlock will accept it.
//
// Storage is a single JSON blob in Upstash Redis (free tier) -- fine for one
// user / one friend. This matters specifically because most free hosts
// (Render included) run on an ephemeral filesystem: anything written to a
// local file (device pairing, the Google Tasks refresh token, ...) gets
// silently wiped on every redeploy and on free-tier idle spin-down. Redis
// here is a managed, persistent key-value store reached over HTTPS, so it
// survives restarts. Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN
// in .env (see .env.example for where to get them).
//
// Do not expose this server to the public internet without at least putting
// a reverse proxy + HTTPS in front of it (Render/Railway do this for you
// automatically).

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());

// The Android app isn't subject to browser CORS rules, but the Chrome
// extension's fetch() calls are -- without this, the browser blocks the
// response (and the preflight OPTIONS request for JSON POSTs) before it ever
// reaches the extension's code. This is a personal single-user/one-friend
// backend, so allowing any origin is fine here.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const redis = Redis.fromEnv(); // reads UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
const DB_KEY = 'appguard:db';
const CODE_TTL_MS = 10 * 60 * 1000; // code expires 10 minutes after being sent
const DEFAULT_UNLOCK_MINUTES = 15;

async function loadDb() {
  const db = await redis.get(DB_KEY);
  return db || { devices: {}, requests: {} };
}
async function saveDb(db) {
  await redis.set(DB_KEY, db);
}

// Express 4 doesn't catch rejected promises from async route handlers on its
// own -- an await that throws would otherwise just hang the request instead
// of producing a response. This forwards it to the error-handling middleware
// at the bottom instead.
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function randomToken() {
  return crypto.randomBytes(24).toString('hex');
}
function randomCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

// --- notification senders -------------------------------------------------

// Sent over Brevo's HTTPS API rather than raw SMTP -- most free hosts
// (Render included) block outbound SMTP ports (25/465/587) to stop abuse,
// which makes SMTP sending hang until it times out.
async function sendEmail(to, subject, text) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      sender: { email: process.env.SMTP_FROM, name: 'AppGuard' },
      to: [{ email: to }],
      subject,
      textContent: text,
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Brevo send failed (${res.status}): ${body}`);
  }
}

async function sendSms(to, body) {
  const twilio = require('twilio');
  const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
  await client.messages.create({
    from: process.env.TWILIO_FROM,
    to,
    body,
  });
}

async function notifyFriend(device, subject, message) {
  const method = process.env.NOTIFY_METHOD || 'email';
  if (method === 'sms') {
    await sendSms(device.friendContact, message);
  } else {
    await sendEmail(device.friendContact, subject, message);
  }
}

// --- auth middleware -------------------------------------------------------

const requireDevice = asyncHandler(async (req, res, next) => {
  const { deviceId, token } = req.body.deviceId ? req.body : req.query;
  if (!deviceId || !token) return res.status(400).json({ error: 'deviceId and token required' });
  const db = await loadDb();
  const device = db.devices[deviceId];
  if (!device || device.token !== token) return res.status(401).json({ error: 'unauthorized' });
  req.db = db;
  req.device = device;
  req.deviceId = deviceId;
  next();
});

// --- routes ------------------------------------------------------------

// One-time pairing: run this once during setup. Returns a token the phone
// must store and send with every future request.
app.post('/api/register-device', asyncHandler(async (req, res) => {
  const { friendContact, label } = req.body;
  if (!friendContact) return res.status(400).json({ error: 'friendContact required (email or phone in E.164 format)' });

  const db = await loadDb();
  const deviceId = crypto.randomUUID();
  const token = randomToken();
  db.devices[deviceId] = { friendContact, label: label || 'my phone', token, createdAt: Date.now() };
  await saveDb(db);

  res.json({ deviceId, token });
}));

// Phone asks: "I want to unlock <target> for <minutes> minutes" -> a code is
// generated and sent to the friend, never returned to the phone.
app.post('/api/request-unlock', requireDevice, asyncHandler(async (req, res) => {
  const { target, minutes } = req.body;
  if (!target) return res.status(400).json({ error: 'target required' });

  const requestId = crypto.randomUUID();
  const code = randomCode();
  const grantMinutes = Math.min(Math.max(Number(minutes) || DEFAULT_UNLOCK_MINUTES, 1), 120);

  req.db.requests[requestId] = {
    deviceId: req.deviceId,
    target,
    code,
    grantMinutes,
    createdAt: Date.now(),
    used: false,
  };
  await saveDb(req.db);

  try {
    await notifyFriend(
      req.device,
      'AppGuard unlock request',
      `${req.device.label} wants to unlock "${target}" for ${grantMinutes} minutes.\n` +
      `Code: ${code}\n(valid for 10 minutes; only share it if you approve)`
    );
  } catch (err) {
    delete req.db.requests[requestId];
    await saveDb(req.db);
    console.error('notify failed', err);
    return res.status(502).json({ error: 'failed to notify trusted contact' });
  }

  res.json({ requestId, expiresInSeconds: CODE_TTL_MS / 1000 });
}));

// Phone submits the code it was told by the friend.
app.post('/api/verify-unlock', requireDevice, asyncHandler(async (req, res) => {
  const { requestId, code } = req.body;
  const request = req.db.requests[requestId];
  if (!request || request.deviceId !== req.deviceId) {
    return res.status(404).json({ error: 'unknown request' });
  }
  if (request.used) return res.status(409).json({ error: 'code already used' });
  if (Date.now() - request.createdAt > CODE_TTL_MS) return res.status(410).json({ error: 'code expired' });
  if (request.code !== String(code).trim()) return res.status(401).json({ error: 'incorrect code' });

  request.used = true;
  const unlockUntil = Date.now() + request.grantMinutes * 60 * 1000;
  await saveDb(req.db);

  res.json({ granted: true, target: request.target, unlockUntil });
}));

// Phone reports it's had Accessibility (app blocking) turned off long enough
// that the watchdog gave up waiting -- tell the trusted contact directly,
// since nothing else stops the phone's owner from just leaving it off.
app.post('/api/notify-accessibility-off', requireDevice, asyncHandler(async (req, res) => {
  try {
    await notifyFriend(
      req.device,
      'AppGuard protection is off',
      `${req.device.label} turned off app blocking (Accessibility) and hasn't turned it back on, even after being reminded.`
    );
  } catch (err) {
    console.error('notify failed', err);
    return res.status(502).json({ error: 'failed to notify trusted contact' });
  }
  res.json({ notified: true });
}));

// --- Google Tasks (used to gate unlocks on pending tasks) ------------------
//
// One-time setup: create OAuth credentials at
// https://console.cloud.google.com/apis/credentials (type "Web application"),
// enable the Tasks API for that project, and set GOOGLE_CLIENT_ID,
// GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI (https://<your-host>/auth/google/callback)
// and ADMIN_TOKEN in .env. Then visit /auth/google?token=<ADMIN_TOKEN> in a
// browser once to grant access; the refresh token is stored in Redis. This is
// *your own* Google account (whoever holds ADMIN_TOKEN) -- the lock screen
// shows your own open tasks, not your trusted contact's.

const { google } = require('googleapis');

function requireAdmin(req, res, next) {
  if (!process.env.ADMIN_TOKEN || req.query.token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function googleOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

app.get('/auth/google', requireAdmin, (req, res) => {
  const oauth2Client = googleOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent', // forces a refresh_token even on repeat authorizations
    scope: ['https://www.googleapis.com/auth/tasks.readonly'],
    state: process.env.ADMIN_TOKEN,
  });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!process.env.ADMIN_TOKEN || state !== process.env.ADMIN_TOKEN) {
    return res.status(401).send('unauthorized');
  }
  try {
    const oauth2Client = googleOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    const db = await loadDb();
    db.google = { ...db.google, ...tokens };
    await saveDb(db);
    res.send('Google Tasks connected. You can close this tab.');
  } catch (err) {
    console.error('google oauth callback failed', err);
    res.status(500).send('failed to connect Google Tasks');
  }
});

async function googleTasksClient() {
  const db = await loadDb();
  if (!db.google || !db.google.refresh_token) {
    throw new Error('Google Tasks not connected yet -- visit /auth/google first');
  }
  const oauth2Client = googleOAuthClient();
  oauth2Client.setCredentials(db.google);
  oauth2Client.on('tokens', (tokens) => {
    loadDb().then((freshDb) => {
      freshDb.google = { ...freshDb.google, ...tokens };
      return saveDb(freshDb);
    }).catch((err) => console.error('failed to persist refreshed google tokens', err));
  });
  return google.tasks({ version: 'v1', auth: oauth2Client });
}

async function fetchTaskLists() {
  const tasks = await googleTasksClient();
  const { data: listsData } = await tasks.tasklists.list();
  const lists = listsData.items || [];
  return Promise.all(
    lists.map(async (list) => {
      const { data } = await tasks.tasks.list({ tasklist: list.id, showCompleted: false });
      return { id: list.id, title: list.title, tasks: (data.items || []).map((t) => t.title) };
    })
  );
}

// Test route: confirms the connection works by returning your task lists and
// their (incomplete) tasks.
app.get('/api/tasks', requireAdmin, async (req, res) => {
  try {
    res.json({ taskLists: await fetchTaskLists() });
  } catch (err) {
    console.error('fetch tasks failed', err);
    res.status(502).json({ error: err.message });
  }
});

// Phone asks: "what's still pending?" -- shown on the lock screen so the
// user sees their open tasks before deciding whether to request an unlock.
// Device-authenticated (not ADMIN_TOKEN) since the phone itself calls this.
// If Google Tasks was never connected, respond with an empty list rather
// than an error so the lock screen just skips the section.
app.post('/api/pending-tasks', requireDevice, asyncHandler(async (req, res) => {
  try {
    const taskLists = await fetchTaskLists();
    const titles = taskLists.flatMap((list) => list.tasks);
    res.json({ tasks: titles });
  } catch (err) {
    console.error('pending-tasks failed:', err.message);
    res.json({ tasks: [] });
  }
}));

// Catches anything asyncHandler forwarded, plus synchronous throws Express
// already handles on its own -- without this, an unhandled rejection here
// would otherwise just hang the request.
app.use((err, req, res, next) => {
  console.error('unhandled error:', err);
  res.status(500).json({ error: 'internal error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AppGuard backend listening on :${PORT}`));
