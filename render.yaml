# Login backend (Node + Express)

A working authentication backend for the login page, using bcrypt password
hashing and JWT session cookies. Users are stored in `users.json` — swap
this for a real database (Postgres, MongoDB, etc.) before going to production.

## Setup

```bash
npm install
cp .env.example .env
```

Open `.env` and set `JWT_SECRET` to a long random string, for example:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Run

```bash
npm start
```

Then open http://localhost:3000/login.html in your browser.

- `/login.html` — sign in
- `/signup.html` — create an account
- `/dashboard.html` — protected page, redirects to login if not signed in

## How it works

- Passwords are hashed with bcrypt (12 rounds) before being stored — the
  plaintext password is never saved.
- On successful login/signup, the server issues a JWT in an `httpOnly` cookie
  (not readable by JavaScript, which protects against XSS token theft).
- `remember me` sets a 30-day cookie; otherwise the session lasts 1 day.
- Failed logins are rate-limited per email (5 attempts / 15 minutes) to slow
  down brute-force guessing.
- `GET /api/me` is a protected route that reads the cookie, verifies the JWT,
  and returns the signed-in user's email — this is the pattern to copy for
  any other route you want to require a login for.

## Before using this in production

- Replace the `users.json` file store with a real database.
- Set `NODE_ENV=production` so cookies require HTTPS.
- Set a strong, unique `JWT_SECRET` and keep it out of source control.
- Consider adding email verification and a real "forgot password" flow
  (send a reset link with a short-lived token, rather than resetting in-app).
- Add HTTPS (e.g. behind a reverse proxy like nginx or Caddy).
- The rate limiter here is in-memory and per-process — for multiple server
  instances, use a shared store like Redis instead.

## Project structure

```
server.js            Express app: signup, login, logout, me, and the middleware
users.json            File-based user store (email + bcrypt hash) — demo only
.env.example          Copy to .env and fill in your own JWT_SECRET
public/login.html     Sign-in page
public/signup.html     Account creation page
public/dashboard.html Protected page that calls /api/me
```
