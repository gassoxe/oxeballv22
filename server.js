'use strict';
/**
 * server.js — OXE BALL  ·  Auth + Game Backend
 *
 * Structure expected on disk:
 *   server.js        ← this file
 *   db.js            ← database helpers
 *   auth.js          ← JWT + password
 *   email.js         ← email sending
 *   google.js        ← Google token verification
 *   referral.js      ← referral system
 *   public/
 *     index.html     ← game + auth UI
 *     admin.html     ← admin panel
 *     admin-new.html ← alternative admin
 *     auth.html      ← standalone auth page
 *     api.js         ← client-side API helper
 *     auth.js        ← client-side auth logic
 *     auth.css       ← auth page styles
 *   data/            ← auto-created, JSON files
 *
 * Routes:
 *   GET  /                        → public/index.html
 *   GET  /admin                   → public/admin.html
 *   GET  /auth                    → public/auth.html
 *   GET  /health                  → "OK"
 *   GET  /api/config              → public game config
 *   POST /api/auth/send-code      → send 6-digit email code
 *   POST /api/auth/verify-code    → verify code → JWT
 *   POST /api/auth/resend-code    → resend code
 *   POST /api/auth/login          → email + password login
 *   POST /api/auth/forgot-password→ send reset link
 *   POST /api/auth/reset-password → consume token, set new password
 *   POST /api/auth/google         → Google OAuth login
 *   GET  /api/me                  → my profile [auth]
 *   POST /api/me/balance          → sync balance [auth]
 *   GET  /api/referral            → my referral code [auth]
 *   POST /api/withdraw            → request withdrawal [auth]
 *   POST /api/deposit/verify      → verify deposit TX [auth]
 *   POST /api/admin/login         → admin login
 *   GET  /api/admin/users         → all users [admin]
 *   POST /api/admin/users/ban     → ban/unban [admin]
 *   DELETE /api/admin/users/:uid  → delete user [admin]
 *   GET  /api/admin/config        → game config [admin]
 *   POST /api/admin/config        → save config [admin]
 *   GET  /api/admin/withdrawals   → withdrawal list [admin]
 *   POST /api/admin/withdrawals/update → update status [admin]
 *   GET  /api/admin/deposits      → deposit log [admin]
 *   GET  /api/admin/referrals     → referral list [admin]
 *   GET  /api/admin/deleted       → deleted users [admin]
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ── Local modules (all in root, same folder as server.js) ─────────────────────
const db       = require('./db');
const Auth     = require('./auth');
const Email    = require('./email');
const Google   = require('./google');
const Referral = require('./referral');

// ── Constants ──────────────────────────────────────────────────────────────────
const PORT     = process.env.PORT     || 3000;
const HOST     = '0.0.0.0';                        // required for Railway
const PUB      = path.join(__dirname, 'public');    // frontend files live here
const ADMIN_PW = process.env.ADMIN_PASSWORD || 'oxeball2024';

// In-memory password reset tokens: { token → { email, exp } }
const resetTokens = {};

// ── HTTP helpers ───────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization'
};

function json(res, data, status) {
  status = status || 200;
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
  res.end(JSON.stringify(data));
}

// MIME type map for static files
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.txt':  'text/plain'
};

/**
 * Serve a static file from disk.
 * Returns 404 HTML if the file does not exist.
 */
function serveFile(res, filePath) {
  // Security: only serve files inside /public
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(PUB)) {
    res.writeHead(403, { 'Content-Type': 'text/plain', ...CORS });
    return res.end('Forbidden');
  }
  try {
    const data = fs.readFileSync(resolved);
    const ext  = path.extname(resolved).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', ...CORS });
    res.end(data);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/html', ...CORS });
    res.end('<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;background:#03030b;color:#ff5533"><h2>404 — Not Found</h2><p><a href="/" style="color:#9933ff">← Home</a></p></body></html>');
  }
}

/**
 * Read and parse JSON request body.
 * Returns {} on parse error or empty body.
 */
function readBody(req) {
  return new Promise(resolve => {
    let buf = '';
    req.on('data', chunk => {
      buf += chunk;
      if (buf.length > 200_000) req.destroy(); // prevent abuse
    });
    req.on('end',   () => { try { resolve(JSON.parse(buf)); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

// ── Auth helpers ───────────────────────────────────────────────────────────────

/** Parse Bearer token from Authorization header. Returns JWT payload or null. */
function getSession(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer ')) return null;
  return Auth.verifyJWT(h.slice(7));
}

/** Build a login API response from a user object + new JWT. */
function loginResponse(user) {
  return {
    token:        Auth.signJWT({ uid: user.uid, email: user.email, username: user.username, role: 'player' }),
    uid:          user.uid,
    email:        user.email        || null,
    username:     user.username     || null,
    method:       user.method,
    balance:      user.balance      || 0,
    gamesPlayed:  user.gamesPlayed  || 0
  };
}

// ── User DB helpers ────────────────────────────────────────────────────────────

function getUsers() {
  const u = db.read('users') || {};
  // Migrate old {list:{}} format automatically
  if (u.list && !u.byEmail) {
    const m = { byEmail: {} };
    Object.values(u.list).forEach(usr => { if (usr.email) m.byEmail[usr.email.toLowerCase()] = usr; });
    db.write('users', m);
    return m;
  }
  if (!u.byEmail) u.byEmail = {};
  return u;
}

function getUserByEmail(email) {
  if (!email) return null;
  return getUsers().byEmail[email.toLowerCase()] || null;
}

function getUserByUid(uid) {
  const users = getUsers();
  return Object.values(users.byEmail).find(u => u.uid === uid) || null;
}

function saveUser(user) {
  const users = getUsers();
  if (user.email) users.byEmail[user.email.toLowerCase()] = user;
  db.write('users', users);
}

function createUser({ email, username, pwHash, method, refCode, googleId }) {
  const uid   = Auth.newUid(method === 'google' ? 'G' : 'E');
  const now   = new Date().toISOString();
  const code  = Referral.registerCode(uid, email);
  const bonus = Referral.processReferral(uid, refCode);
  const user  = {
    uid,
    email:         email ? email.toLowerCase() : null,
    username:      username  || null,
    pwHash:        pwHash    || null,
    method:        method,
    googleId:      googleId  || null,
    balance:       bonus,
    gamesPlayed:   0,
    totalDeposits: 0,
    registeredAt:  now,
    lastLogin:     now,
    banned:        false,
    emailVerified: method !== 'email',
    referralCode:  code,
    referredBy:    refCode || null
  };
  saveUser(user);
  return user;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HTTP SERVER
// ═══════════════════════════════════════════════════════════════════════════════
http.createServer(async (req, res) => {

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    return res.end();
  }

  // Strip query string and trailing slashes for clean routing
  const url    = (req.url || '/').split('?')[0].replace(/\/+$/, '') || '/';
  const method = req.method;

  // ── Health check (Railway requires this) ────────────────────────────────────
  if (url === '/health' || url === '/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...CORS });
    return res.end('OK');
  }

  // ── Static file serving ──────────────────────────────────────────────────────
  // Only serve GET requests that don't start with /api
  if (method === 'GET' && !url.startsWith('/api/') && url !== '/api') {

    // Named routes → specific HTML files
    if (url === '/' || url === '/index.html' || url === '/game')
      return serveFile(res, path.join(PUB, 'index.html'));

    if (url === '/admin' || url === '/admin.html')
      return serveFile(res, path.join(PUB, 'admin.html'));

    if (url === '/auth' || url === '/auth.html')
      return serveFile(res, path.join(PUB, 'auth.html'));

    // Any other static asset (js, css, images, etc.)
    // url.slice(1) turns '/api.js' → 'api.js'
    return serveFile(res, path.join(PUB, url.slice(1)));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PUBLIC API
  // ═══════════════════════════════════════════════════════════════════════════

  // GET /api/config — returns public game settings + Google client ID
  if (method === 'GET' && url === '/api/config') {
    const cfg = db.read('config') || {};
    return json(res, {
      rate:           cfg.rate     || 20,
      minBet:         cfg.minBet   || 10,
      maxBet:         cfg.maxBet   || 100000,
      winPct:         cfg.winPct   || 10,
      trialOxe:       cfg.trialOxe || 200,
      googleClientId: process.env.GOOGLE_CLIENT_ID || ''
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  AUTH — EMAIL
  // ═══════════════════════════════════════════════════════════════════════════

  // POST /api/auth/send-code — validate fields, store pending, email the code
  if (method === 'POST' && url === '/api/auth/send-code') {
    const b = await readBody(req);

    if (!Auth.validEmail(b.email))
      return json(res, { error: 'Invalid email address.' }, 400);
    if (!Auth.validUsername(b.username))
      return json(res, { error: 'Username must be 3–30 characters.' }, 400);
    if (!Auth.validPassword(b.password))
      return json(res, { error: 'Password must be at least 6 characters.' }, 400);
    if (getUserByEmail(b.email))
      return json(res, { error: 'That email is already registered.' }, 409);

    const code = Email.generateCode();
    Email.storePending(b.email, code, {
      username: b.username.trim(),
      pwHash:   Auth.hashPassword(b.password),
      refCode:  b.refCode || null
    });

    const result = await Email.sendEmail(
      b.email,
      'Your OXE BALL verification code: ' + code,
      Email.codeEmailHtml(b.username.trim(), code)
    );

    if (result.dev) return json(res, { success: true, devCode: code, dev: true });
    if (!result.ok) return json(res, { error: 'Failed to send email. Check your email config.' }, 500);
    return json(res, { success: true });
  }

  // POST /api/auth/verify-code — confirm the code, create account, return JWT
  if (method === 'POST' && url === '/api/auth/verify-code') {
    const b      = await readBody(req);
    const result = Email.checkCode(b.email, b.code);

    if (!result.ok) return json(res, { error: result.error }, 400);
    if (getUserByEmail(b.email)) {
      Email.deletePending(b.email);
      return json(res, { error: 'Email already registered.' }, 409);
    }

    const { username, pwHash, refCode } = result.data;
    const user = createUser({ email: b.email, username, pwHash, method: 'email', refCode });
    user.emailVerified = true;
    saveUser(user);
    Email.deletePending(b.email);

    return json(res, { ...loginResponse(user), isNew: true });
  }

  // POST /api/auth/resend-code — send a fresh code to the same pending registration
  if (method === 'POST' && url === '/api/auth/resend-code') {
    const b = await readBody(req);
    const p = Email.getPending(b.email);
    if (!p) return json(res, { error: 'No pending registration. Please start over.' }, 400);

    const newCode = Email.generateCode();
    Email.storePending(b.email, newCode, p.data);

    const result = await Email.sendEmail(
      b.email,
      'OXE BALL — new verification code: ' + newCode,
      Email.codeEmailHtml(p.data.username, newCode)
    );
    if (result.dev) return json(res, { success: true, devCode: newCode, dev: true });
    return json(res, { success: true });
  }

  // POST /api/auth/login — email + password
  if (method === 'POST' && url === '/api/auth/login') {
    const b    = await readBody(req);
    const user = getUserByEmail(b.email);

    if (!user || !Auth.verifyPassword(b.password, user.pwHash || ''))
      return json(res, { error: 'Wrong email or password.' }, 401);
    if (user.banned)
      return json(res, { error: 'This account is banned.' }, 403);

    user.lastLogin = new Date().toISOString();
    saveUser(user);
    return json(res, loginResponse(user));
  }

  // POST /api/auth/forgot-password — send password reset link
  if (method === 'POST' && url === '/api/auth/forgot-password') {
    const b    = await readBody(req);
    const user = getUserByEmail(b.email);

    // Always return success — don't reveal whether email exists
    if (!user) return json(res, { success: true });

    const tok  = crypto.randomBytes(32).toString('hex');
    resetTokens[tok] = { email: b.email.toLowerCase(), exp: Date.now() + 30 * 60_000 };

    const base = process.env.APP_URL || ('http://localhost:' + PORT);
    const link = base + '/reset-password.html?token=' + tok;
    const html = '<div style="font-family:sans-serif;padding:24px;background:#07070f">'
      + '<h2 style="color:#00d4ff;letter-spacing:3px">OXE&#9679;BALL</h2>'
      + '<p style="color:#aaa">Password reset link (expires in 30 minutes):</p>'
      + '<a href="' + link + '" style="color:#ff6a00;word-break:break-all">' + link + '</a>'
      + '<p style="color:#555;margin-top:20px;font-size:12px">Ignore this if you didn\'t request it.</p>'
      + '</div>';

    await Email.sendEmail(b.email, 'OXE BALL — Password Reset', html);
    console.log('🔑 Reset link for ' + b.email + ': ' + link);
    return json(res, { success: true });
  }

  // POST /api/auth/reset-password — consume reset token, update password
  if (method === 'POST' && url === '/api/auth/reset-password') {
    const b = await readBody(req);

    if (!b.token || !Auth.validPassword(b.newPassword))
      return json(res, { error: 'Missing token or password too short (6+ chars).' }, 400);

    const entry = resetTokens[b.token];
    if (!entry || Date.now() > entry.exp) {
      delete resetTokens[b.token];
      return json(res, { error: 'Reset link has expired or is invalid. Request a new one.' }, 400);
    }

    const user = getUserByEmail(entry.email);
    if (!user) return json(res, { error: 'User not found.' }, 404);

    user.pwHash = Auth.hashPassword(b.newPassword);
    saveUser(user);
    delete resetTokens[b.token];
    return json(res, { success: true, message: 'Password updated. You can now sign in.' });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  AUTH — GOOGLE
  // ═══════════════════════════════════════════════════════════════════════════

  // POST /api/auth/google — verify Google ID token, login or create account
  if (method === 'POST' && url === '/api/auth/google') {
    const b = await readBody(req);
    const { ok, payload, error } = await Google.verifyGoogleToken(b.credential);
    if (!ok) return json(res, { error }, 401);

    const { email, name, googleId } = payload;
    let user = getUserByEmail(email);

    if (!user) {
      // New Google user → create account
      user = createUser({ email, username: name, method: 'google', googleId, refCode: b.refCode || null });
      user.emailVerified = true;
      saveUser(user);
      return json(res, { ...loginResponse(user), isNew: true });
    }

    // Returning user → update last login
    if (user.banned) return json(res, { error: 'This account is banned.' }, 403);
    user.lastLogin = new Date().toISOString();
    if (!user.googleId) user.googleId = googleId;
    if (name) user.username = name;
    saveUser(user);
    return json(res, loginResponse(user));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PLAYER — protected (require valid JWT)
  // ═══════════════════════════════════════════════════════════════════════════

  // GET /api/me — my profile
  if (method === 'GET' && url === '/api/me') {
    const sess = getSession(req);
    if (!sess) return json(res, { error: 'Unauthorized.' }, 401);

    const user = getUserByUid(sess.uid);
    if (!user)  return json(res, { error: 'User not found.' }, 404);

    return json(res, {
      uid:          user.uid,
      email:        user.email,
      username:     user.username,
      method:       user.method,
      balance:      user.balance      || 0,
      gamesPlayed:  user.gamesPlayed  || 0,
      referralCode: user.referralCode,
      emailVerified: user.emailVerified
    });
  }

  // POST /api/me/balance — update balance + increment games played
  if (method === 'POST' && url === '/api/me/balance') {
    const sess = getSession(req);
    if (!sess) return json(res, { error: 'Unauthorized.' }, 401);

    const b    = await readBody(req);
    const user = getUserByUid(sess.uid);
    if (!user)  return json(res, { error: 'User not found.' }, 404);

    if (typeof b.balance === 'number') user.balance = Math.max(0, b.balance);
    if (b.addGame) user.gamesPlayed = (user.gamesPlayed || 0) + 1;
    saveUser(user);
    return json(res, { balance: user.balance });
  }

  // GET /api/referral — my referral code and stats
  if (method === 'GET' && url === '/api/referral') {
    const sess = getSession(req);
    if (!sess) return json(res, { error: 'Unauthorized.' }, 401);
    const host = req.headers.host || ('localhost:' + PORT);
    return json(res, Referral.getReferralData(sess.uid, host));
  }

  // POST /api/withdraw — request a USDT withdrawal
  if (method === 'POST' && url === '/api/withdraw') {
    const sess = getSession(req);
    if (!sess) return json(res, { error: 'Unauthorized.' }, 401);

    const b = await readBody(req);
    if (!b.address || !b.oxeAmount || b.oxeAmount < 200)
      return json(res, { error: 'Minimum withdrawal is 200 OXE.' }, 400);

    const user = getUserByUid(sess.uid);
    if (!user)  return json(res, { error: 'User not found.' }, 404);

    const FEE   = 20;
    const total = b.oxeAmount + FEE;
    if ((user.balance || 0) < total)
      return json(res, { error: 'Insufficient balance. Need ' + total + ' OXE (includes ' + FEE + ' fee).' }, 400);

    user.balance -= total;
    saveUser(user);

    const cfg   = db.read('config') || {};
    const txlog = db.read('txlog')  || { deposits: [], withdrawals: [], deletedUsers: [] };
    txlog.withdrawals.unshift({
      id:       'WD-' + Date.now(),
      uid:      user.uid,
      email:    user.email,
      username: user.username,
      address:  b.address,
      oxe:      b.oxeAmount,
      usdt:     (b.oxeAmount / (cfg.rate || 20)).toFixed(2),
      status:   'Pending',
      note:     '',
      time:     new Date().toISOString()
    });
    db.write('txlog', txlog);
    return json(res, { success: true, newBalance: user.balance });
  }

  // POST /api/deposit/verify — verify USDT deposit by TX hash
  if (method === 'POST' && url === '/api/deposit/verify') {
    const sess = getSession(req);
    if (!sess) return json(res, { error: 'Unauthorized.' }, 401);

    const b = await readBody(req);
    if (!b.txHash || b.txHash.length < 60)
      return json(res, { error: 'Invalid transaction hash.' }, 400);

    // TODO: replace simulation with real BSCScan API call in production
    const cfg     = db.read('config') || {};
    const usdtAmt = +(5 + Math.random() * 195).toFixed(2);
    const oxeAmt  = Math.round(usdtAmt * (cfg.rate || 20));

    const user = getUserByUid(sess.uid);
    if (!user)  return json(res, { error: 'User not found.' }, 404);

    user.balance       = (user.balance       || 0) + oxeAmt;
    user.totalDeposits = (user.totalDeposits || 0) + usdtAmt;
    saveUser(user);

    const txlog = db.read('txlog') || { deposits: [], withdrawals: [] };
    txlog.deposits.unshift({
      id:     'DEP-' + Date.now(),
      uid:    user.uid,
      email:  user.email,
      txHash: b.txHash,
      usdt:   usdtAmt,
      oxe:    oxeAmt,
      status: 'Confirmed',
      time:   new Date().toISOString()
    });
    db.write('txlog', txlog);
    return json(res, { success: true, oxeAmt, usdtAmt, newBalance: user.balance });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  ADMIN
  // ═══════════════════════════════════════════════════════════════════════════

  // POST /api/admin/login — authenticate admin (uses ADMIN_PASSWORD env var)
  if (method === 'POST' && url === '/api/admin/login') {
    const b = await readBody(req);
    if (b.password !== ADMIN_PW) return json(res, { error: 'Wrong password.' }, 401);
    const token = Auth.signJWT({ uid: 'ADMIN', role: 'admin', username: 'Admin' });
    return json(res, { token });
  }

  // Guard: all /api/admin/* routes below require admin JWT
  if (url.startsWith('/api/admin')) {
    const sess = getSession(req);
    if (!sess || sess.role !== 'admin')
      return json(res, { error: 'Unauthorized.' }, 401);
  }

  if (method === 'GET' && url === '/api/admin/users') {
    return json(res, Object.values(getUsers().byEmail));
  }

  if (method === 'GET' && url === '/api/admin/config') {
    return json(res, db.read('config') || {});
  }

  if (method === 'POST' && url === '/api/admin/config') {
    const b   = await readBody(req);
    const cfg = db.read('config') || {};
    Object.assign(cfg, b);
    db.write('config', cfg);
    return json(res, { success: true });
  }

  if (method === 'POST' && url === '/api/admin/users/ban') {
    const b     = await readBody(req);
    const users = getUsers();
    const user  = Object.values(users.byEmail).find(u => u.uid === b.uid);
    if (!user) return json(res, { error: 'User not found.' }, 404);
    user.banned = b.ban;
    if (b.ban) user.bannedAt = new Date().toISOString(); else delete user.bannedAt;
    db.write('users', users);
    return json(res, { success: true });
  }

  if (method === 'DELETE' && url.startsWith('/api/admin/users/')) {
    const uid   = decodeURIComponent(url.split('/').pop());
    const users = getUsers();
    let deleted = null;
    for (const [k, v] of Object.entries(users.byEmail)) {
      if (v.uid === uid) { deleted = v; delete users.byEmail[k]; break; }
    }
    if (!deleted) return json(res, { error: 'User not found.' }, 404);
    db.write('users', users);
    const txlog = db.read('txlog') || {};
    (txlog.deletedUsers = txlog.deletedUsers || []).push({
      uid, name: deleted.username || deleted.email, deletedAt: new Date().toISOString()
    });
    db.write('txlog', txlog);
    return json(res, { success: true });
  }

  if (method === 'GET' && url === '/api/admin/withdrawals')
    return json(res, (db.read('txlog') || {}).withdrawals || []);

  if (method === 'POST' && url === '/api/admin/withdrawals/update') {
    const b     = await readBody(req);
    const txlog = db.read('txlog') || { withdrawals: [] };
    const wd    = txlog.withdrawals.find(w => w.id === b.id);
    if (!wd) return json(res, { error: 'Withdrawal not found.' }, 404);
    wd.status = b.status;
    wd.note   = b.note || wd.note || '';
    db.write('txlog', txlog);
    return json(res, { success: true });
  }

  if (method === 'GET' && url === '/api/admin/deposits')
    return json(res, (db.read('txlog') || {}).deposits || []);

  if (method === 'GET' && url === '/api/admin/referrals')
    return json(res, (db.read('refs') || { codes: {} }).codes);

  if (method === 'GET' && url === '/api/admin/deleted')
    return json(res, (db.read('txlog') || {}).deletedUsers || []);

  // 404 fallback
  return json(res, { error: 'Not found.' }, 404);

}).listen(PORT, HOST, () => {
  const sep = '═'.repeat(50);
  console.log('\n╔' + sep + '╗');
  console.log('║  ⬡  OXE BALL  ·  Production Server                ║');
  console.log('║                                                    ║');
  console.log('║  Game:   http://localhost:' + PORT + '/                  ║');
  console.log('║  Admin:  http://localhost:' + PORT + '/admin             ║');
  console.log('║  Health: http://localhost:' + PORT + '/health            ║');
  console.log('╚' + sep + '╝\n');

  if (!process.env.JWT_SECRET)
    console.warn('  ⚠  JWT_SECRET not set — set it in Railway Variables');
  if (!process.env.ADMIN_PASSWORD)
    console.warn('  ⚠  ADMIN_PASSWORD not set — default "oxeball2024" is active');
  if (!process.env.GOOGLE_CLIENT_ID)
    console.warn('  ⚠  GOOGLE_CLIENT_ID not set — Google login is disabled');
  if (!process.env.RESEND_API_KEY && !process.env.SMTP_USER)
    console.warn('  ⚠  No email config — DEV MODE active (codes shown in console)');
  console.log('');
});
