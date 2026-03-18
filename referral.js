'use strict';
/**
 * referral.js — Referral code system
 * Each user gets a unique OXE-prefixed code.
 * Referrers earn OXE when someone registers with their code.
 */
const crypto = require('crypto');
const db     = require('./db');

const REWARD = parseInt(process.env.REFERRAL_REWARD_OXE || '15', 10);

/** Deterministic code from uid — same uid always gets same code. */
function generateCode(uid) {
  return 'OXE' + crypto.createHash('sha256').update(uid).digest('hex').slice(0, 5).toUpperCase();
}

/** Register a new user's code. Called once at account creation. */
function registerCode(uid, email) {
  const refs = db.read('refs') || { codes: {} };
  const code = generateCode(uid);
  if (!refs.codes[code]) {
    refs.codes[code] = { uid, email: email || '', count: 0, earned: 0, referrals: [] };
    db.write('refs', refs);
  }
  return code;
}

/**
 * Process a referral when a new user registers.
 * Returns the OXE bonus for the new user (0 if no valid refCode).
 */
function processReferral(newUid, refCode) {
  if (!refCode) return 0;
  const refs = db.read('refs') || { codes: {} };
  const ref  = refs.codes[(refCode || '').toUpperCase()];
  if (!ref || ref.referrals.includes(newUid)) return 0;

  // Reward referrer
  ref.count++;
  ref.earned += REWARD;
  ref.referrals.push(newUid);

  // Credit balance
  const users = db.read('users') || { byEmail: {} };
  const referrer = Object.values(users.byEmail).find(u => u.uid === ref.uid);
  if (referrer) {
    referrer.balance = (referrer.balance || 0) + REWARD;
    db.write('users', users);
  }

  db.write('refs', refs);
  console.log('🎁 Referral reward: ' + REWARD + ' OXE → ' + ref.uid + ' (referred ' + newUid + ')');
  return REWARD; // bonus for new user too
}

/** Return referral stats for a user. */
function getReferralData(uid, host) {
  const refs  = db.read('refs') || { codes: {} };
  const code  = generateCode(uid);
  const data  = refs.codes[code] || { count: 0, earned: 0 };
  const proto = (host || '').includes('localhost') ? 'http' : 'https';
  return {
    code,
    count:  data.count,
    earned: data.earned,
    url:    proto + '://' + host + '/?ref=' + code
  };
}

module.exports = { generateCode, registerCode, processReferral, getReferralData };
