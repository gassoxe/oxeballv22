'use strict';
/**
 * auth.js — JWT signing/verification + password hashing
 * Pure Node.js built-ins — no npm packages needed.
 */
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_CHANGE_IN_PRODUCTION';
const TOKEN_TTL  = 7 * 24 * 60 * 60; // 7 days in seconds

if (!process.env.JWT_SECRET) {
  console.warn('⚠  JWT_SECRET not set — using insecure default. Set it in Railway Variables.');
}

// ── Password hashing (PBKDF2) ─────────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const attempt = crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(attempt), Buffer.from(hash));
  } catch {
    return false;
  }
}

// ── JWT (HS256, no npm) ───────────────────────────────────────────────────────
function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlDecode(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function signJWT(payload) {
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body   = b64url(Buffer.from(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL
  })));
  const sig = b64url(
    crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest()
  );
  return header + '.' + body + '.' + sig;
}

function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return null;
    const expected = b64url(
      crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest()
    );
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(b64urlDecode(body).toString('utf8'));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ── Validation ────────────────────────────────────────────────────────────────
function validEmail(e)    { return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function validUsername(u) { return typeof u === 'string' && u.trim().length >= 3 && u.trim().length <= 30; }
function validPassword(p) { return typeof p === 'string' && p.length >= 6; }

// ── UID generator ─────────────────────────────────────────────────────────────
function newUid(prefix) {
  return (prefix || 'U') + Date.now() + crypto.randomBytes(4).toString('hex');
}

module.exports = {
  hashPassword, verifyPassword,
  signJWT, verifyJWT,
  validEmail, validUsername, validPassword,
  newUid
};
