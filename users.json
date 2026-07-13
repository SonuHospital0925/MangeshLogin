require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const USERS_FILE = path.join(__dirname, 'users.json');

if (!process.env.JWT_SECRET) {
  console.warn('[warning] JWT_SECRET not set in .env — using an insecure default. Do not use in production.');
}

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Simple file-backed user store (swap for a real database in production) ---
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8') || '[]');
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// --- Basic in-memory rate limiting for login attempts (per email) ---
const attempts = new Map(); // email -> { count, firstAttempt }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function isRateLimited(email) {
  const record = attempts.get(email);
  if (!record) return false;
  if (Date.now() - record.firstAttempt > WINDOW_MS) {
    attempts.delete(email);
    return false;
  }
  return record.count >= MAX_ATTEMPTS;
}
function recordFailedAttempt(email) {
  const record = attempts.get(email) || { count: 0, firstAttempt: Date.now() };
  record.count += 1;
  attempts.set(email, record);
}
function clearAttempts(email) {
  attempts.delete(email);
}

function validEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function signToken(user, remember) {
  const expiresIn = remember ? '30d' : '1d';
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn });
}

function setAuthCookie(res, token, remember) {
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: (remember ? 30 : 1) * 24 * 60 * 60 * 1000
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not signed in.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Sign in again.' });
  }
}

// --- Routes ---

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body || {};

  if (!validEmail(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const users = readUsers();
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2),
    email,
    passwordHash,
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeUsers(users);

  const token = signToken(user, false);
  setAuthCookie(res, token, false);
  res.status(201).json({ email: user.email });
});

app.post('/api/login', async (req, res) => {
  const { email, password, remember } = req.body || {};

  if (!validEmail(email) || !password) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }

  if (isRateLimited(email)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  // Always run bcrypt.compare (even on a missing user) to avoid leaking
  // account existence through response timing.
  const hashToCheck = user ? user.passwordHash : '$2a$12$invalidsaltinvalidsaltinvalidsaltinvalidsalt';
  const match = await bcrypt.compare(password, hashToCheck);

  if (!user || !match) {
    recordFailedAttempt(email);
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }

  clearAttempts(email);
  const token = signToken(user, !!remember);
  setAuthCookie(res, token, !!remember);
  res.json({ email: user.email });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
