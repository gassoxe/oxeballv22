/**
 * public/api.js — OXE BALL Client API Helper
 *
 * Automatically uses the same origin as the page.
 * No configuration needed — works on localhost and Railway.
 *
 * Usage:
 *   <script src="/api.js"></script>
 *   API.login(email, password).then(r => console.log(r.token))
 */
const API = (() => {
  'use strict';

  // ── Token storage (sessionStorage — cleared on tab close) ─────────────────
  let tok = sessionStorage.getItem('oxe_token') || '';

  function setToken(t)   { tok = t; sessionStorage.setItem('oxe_token', t); }
  function clearToken()  { tok = ''; sessionStorage.removeItem('oxe_token'); }
  function hasToken()    { return !!tok; }
  function getToken()    { return tok; }

  // ── Fetch helpers with 8-second timeout ───────────────────────────────────
  function _fetch(path, opts) {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + tok
    };
    return fetch(path, { ...opts, headers, signal: ctrl.signal })
      .then(r => r.json())
      .finally(() => clearTimeout(timer));
  }

  function get(path) {
    return _fetch(path, { method: 'GET' });
  }

  function post(path, body) {
    return _fetch(path, { method: 'POST', body: JSON.stringify(body || {}) });
  }

  function del(path) {
    return _fetch(path, { method: 'DELETE' });
  }

  // ── Auth ───────────────────────────────────────────────────────────────────
  return {
    // Expose token helpers
    setToken, clearToken, hasToken, getToken,

    // Expose raw fetch for custom calls
    post, get, del,

    // ── Email auth ────────────────────────────────────────────────────────────
    /** Send 6-digit verification code to email */
    sendCode: (email, password, username, refCode) =>
      post('/api/auth/send-code', { email, password, username, refCode: refCode || null }),

    /** Verify the code → returns { token, uid, email, username, balance } */
    verifyCode: (email, code) =>
      post('/api/auth/verify-code', { email, code }),

    /** Resend a new verification code */
    resendCode: (email) =>
      post('/api/auth/resend-code', { email }),

    /** Email + password login → returns { token, uid, email, username, balance } */
    login: (email, password) =>
      post('/api/auth/login', { email, password }),

    /** Send password reset email */
    forgotPassword: (email) =>
      post('/api/auth/forgot-password', { email }),

    /** Reset password with token from email */
    resetPassword: (token, newPassword) =>
      post('/api/auth/reset-password', { token, newPassword }),

    // ── Google auth ──────────────────────────────────────────────────────────
    /** Google OAuth — pass the credential from google.accounts.id callback */
    googleAuth: (credential, refCode) =>
      post('/api/auth/google', { credential, refCode: refCode || null }),

    // ── Player ────────────────────────────────────────────────────────────────
    /** Get my profile */
    me: () => get('/api/me'),

    /** Sync balance after a game round */
    setBalance: (balance, addGame) =>
      post('/api/me/balance', { balance, addGame: addGame || false }),

    /** Get my referral code and stats */
    referral: () => get('/api/referral'),

    /** Request a withdrawal */
    withdraw: (address, oxeAmount) =>
      post('/api/withdraw', { address, oxeAmount }),

    /** Verify a USDT deposit by TX hash */
    verifyDeposit: (txHash) =>
      post('/api/deposit/verify', { txHash }),

    // ── Config ────────────────────────────────────────────────────────────────
    /** Get public game config (rate, bet limits, googleClientId, etc.) */
    config: () => get('/api/config'),

    // ── Admin ─────────────────────────────────────────────────────────────────
    adminLogin:       (password)           => post('/api/admin/login',                  { password }),
    adminUsers:       ()                   => get('/api/admin/users'),
    adminBan:         (uid, ban)           => post('/api/admin/users/ban',              { uid, ban }),
    adminDelete:      (uid)                => del('/api/admin/users/' + uid),
    adminConfig:      ()                   => get('/api/admin/config'),
    adminSaveConfig:  (cfg)                => post('/api/admin/config',                 cfg),
    adminWithdrawals: ()                   => get('/api/admin/withdrawals'),
    adminUpdateWd:    (id, status, note)   => post('/api/admin/withdrawals/update',     { id, status, note }),
    adminDeposits:    ()                   => get('/api/admin/deposits'),
    adminReferrals:   ()                   => get('/api/admin/referrals'),
    adminDeleted:     ()                   => get('/api/admin/deleted'),
  };
})();
