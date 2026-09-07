// AppGuard backend
//
// Purpose: the Android app never has the power to unlock itself. Whenever it
// wants to unlock a blocked app/site, it asks this server for a code. The
// server generates the code and sends it ONLY to the trusted contact (your
// friend) via email or SMS. The phone has to be told the code by the friend
// before /verify-unlock will accept it.
//
// Storage is a single JSON file (data.json) -- fine for one user / one
// friend. Do not expose this server to the public internet without at least
// putting a reverse proxy + HTTPS in front of it (Render/Railway do this for
// you automatically).

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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

const DB_PATH = path.join(__dirname, 'data.json');
const CODE_TTL_MS = 10 * 60 * 1000; // code expires 10 minutes after being sent
const DEFAULT_UNLOCK_MINUTES = 15;

function loadDb() {
  if (!fs.existsSync(DB_PATH)) return { devices: {}, requests: {} };
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
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

function requireDevice(req, res, next) {
  const { deviceId, token } = req.body.deviceId ? req.body : req.query;
  if (!deviceId || !token) return res.status(400).json({ error: 'deviceId and token required' });
  const db = loadDb();
  const device = db.devices[deviceId];
  if (!device || device.token !== token) return res.status(401).json({ error: 'unauthorized' });
  req.db = db;
  req.device = device;
  req.deviceId = deviceId;
  next();
}

// --- routes ------------------------------------------------------------

// One-time pairing: run this once during setup. Returns a token the phone
// must store and send with every future request.
app.post('/api/register-device', async (req, res) => {
  const { friendContact, label } = req.body;
  if (!friendContact) return res.status(400).json({ error: 'friendContact required (email or phone in E.164 format)' });

  const db = loadDb();
  const deviceId = crypto.randomUUID();
  const token = randomToken();
  db.devices[deviceId] = { friendContact, label: label || 'my phone', token, createdAt: Date.now() };
  saveDb(db);

  res.json({ deviceId, token });
});

// Phone asks: "I want to unlock <target> for <minutes> minutes" -> a code is
// generated and sent to the friend, never returned to the phone.
app.post('/api/request-unlock', requireDevice, async (req, res) => {
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
  saveDb(req.db);

  try {
    await notifyFriend(
      req.device,
      'AppGuard unlock request',
      `${req.device.label} wants to unlock "${target}" for ${grantMinutes} minutes.\n` +
      `Code: ${code}\n(valid for 10 minutes; only share it if you approve)`
    );
  } catch (err) {
    delete req.db.requests[requestId];
    saveDb(req.db);
    console.error('notify failed', err);
    return res.status(502).json({ error: 'failed to notify trusted contact' });
  }

  res.json({ requestId, expiresInSeconds: CODE_TTL_MS / 1000 });
});

// Phone submits the code it was told by the friend.
app.post('/api/verify-unlock', requireDevice, (req, res) => {
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
  saveDb(req.db);

  res.json({ granted: true, target: request.target, unlockUntil });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AppGuard backend listening on :${PORT}`));
