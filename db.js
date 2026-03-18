'use strict';
/**
 * db.js — Simple flat-file JSON database
 * Swap this file for MongoDB/PostgreSQL later without touching server.js
 */
const fs   = require('fs');
const path = require('path');

const DATA = path.join(__dirname, 'data');

// Auto-create data folder if missing — safe on Railway
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

function filePath(name) {
  return path.join(DATA, name + '.json');
}

function read(name) {
  try {
    return JSON.parse(fs.readFileSync(filePath(name), 'utf8'));
  } catch {
    return null;
  }
}

function write(name, data) {
  // Atomic write: write to .tmp first, then rename
  const tmp = filePath(name) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, filePath(name));
}

// Seed defaults on first run
if (!read('users'))  write('users',  { byEmail: {} });
if (!read('refs'))   write('refs',   { codes: {} });
if (!read('txlog'))  write('txlog',  { deposits: [], withdrawals: [], deletedUsers: [] });
if (!read('config')) write('config', {
  rate: 20, minBet: 10, maxBet: 100000, winPct: 10, trialOxe: 200
});

module.exports = { read, write };
