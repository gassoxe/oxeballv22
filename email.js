'use strict';
/**
 * email.js — Send emails via Resend API or SMTP
 * Dev mode: if no credentials are set, code prints to console and is
 * returned in the API response so you can test without email setup.
 *
 * Priority:
 *   1. RESEND_API_KEY  → uses Resend (resend.com, free 3000/month)
 *   2. SMTP_USER       → uses SMTP (Gmail, etc.)
 *   3. Neither set     → DEV mode (code shown in console + API response)
 */
const https  = require('https');
const crypto = require('crypto');

// ── In-memory pending registrations ──────────────────────────────────────────
const pending = {};
const CODE_TTL_MS  = 10 * 60 * 1000; // 10 minutes
const MAX_ATTEMPTS = 5;

function generateCode() {
  return String(100000 + Math.floor(Math.random() * 900000));
}

function storePending(email, code, data) {
  pending[email] = { code, exp: Date.now() + CODE_TTL_MS, attempts: 0, data: data || {} };
}

function getPending(email) {
  const p = pending[email];
  if (!p) return null;
  if (Date.now() > p.exp) { delete pending[email]; return null; }
  return p;
}

function deletePending(email) {
  delete pending[email];
}

function checkCode(email, submitted) {
  const p = getPending(email);
  if (!p) return { ok: false, error: 'No pending verification. Please register again.' };
  p.attempts++;
  if (p.attempts > MAX_ATTEMPTS) {
    deletePending(email);
    return { ok: false, error: 'Too many attempts. Please register again.' };
  }
  if (String(submitted).trim() !== p.code) {
    const left = MAX_ATTEMPTS - p.attempts + 1;
    return { ok: false, error: 'Wrong code. ' + left + ' attempt' + (left === 1 ? '' : 's') + ' left.' };
  }
  return { ok: true, data: p.data };
}

// ── Email HTML template ───────────────────────────────────────────────────────
function codeEmailHtml(username, code) {
  return '<!DOCTYPE html><html><body style="margin:0;background:#07070f;font-family:\'Segoe UI\',sans-serif;">'
    + '<div style="max-width:480px;margin:0 auto;padding:32px 20px">'
    + '<h1 style="color:#00d4ff;font-size:24px;letter-spacing:4px;text-align:center;margin:0 0 4px">OXE<span style="color:#cc44ff">&#9679;</span>BALL</h1>'
    + '<p style="color:#3344aa;font-size:10px;text-align:center;letter-spacing:2px;margin:0 0 28px">CRYPTO PLINKO</p>'
    + '<div style="background:#0a0a1e;border:1px solid #2a2a55;border-radius:16px;padding:28px">'
    + '<p style="color:#aabbcc;font-size:15px;margin:0 0 6px">Hi <b style="color:#fff">' + username + '</b>,</p>'
    + '<p style="color:#6677aa;font-size:13px;margin:0 0 22px">Your OXE BALL verification code:</p>'
    + '<div style="background:#04040e;border:2px solid #9933ff;border-radius:12px;padding:20px;text-align:center;margin:0 0 22px">'
    + '<div style="font-size:42px;font-weight:900;letter-spacing:12px;color:#cc44ff;font-family:monospace">' + code + '</div>'
    + '<div style="color:#3344aa;font-size:11px;margin-top:6px">Expires in 10 minutes</div>'
    + '</div>'
    + '<p style="color:#6677aa;font-size:12px;margin:0">Didn\'t request this? Ignore this email.</p>'
    + '</div>'
    + '<p style="color:#1a1a44;font-size:10px;text-align:center;margin:20px 0 0">&#169; OXE BALL</p>'
    + '</div></body></html>';
}

// ── Send via Resend API ───────────────────────────────────────────────────────
function sendViaResend(to, subject, html, key) {
  return new Promise(resolve => {
    const from    = process.env.SMTP_FROM || 'OXE BALL <onboarding@resend.dev>';
    const payload = Buffer.from(JSON.stringify({ from, to: [to], subject, html }));
    const req = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: {
        'Authorization':  'Bearer ' + key,
        'Content-Type':   'application/json',
        'Content-Length': payload.length
      }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          console.log('📧 Email sent via Resend to', to);
          resolve({ ok: true });
        } else {
          console.error('Resend error', res.statusCode, body.slice(0, 200));
          resolve({ ok: false, error: 'Resend error ' + res.statusCode });
        }
      });
    });
    req.on('error', e => { console.error('Resend network error:', e.message); resolve({ ok: false, error: e.message }); });
    req.setTimeout(12000, () => { req.destroy(); resolve({ ok: false, error: 'Email timeout' }); });
    req.end(payload);
  });
}

// ── Send via SMTP (STARTTLS) ──────────────────────────────────────────────────
function sendViaSMTP(to, subject, html) {
  return new Promise(resolve => {
    const net  = require('net');
    const tls  = require('tls');
    const host = process.env.SMTP_HOST || 'smtp.gmail.com';
    const port = parseInt(process.env.SMTP_PORT || '587');
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    const from = process.env.SMTP_FROM || user;
    const b64  = s => Buffer.from(s).toString('base64');
    const CRLF = '\r\n';
    const msg  = ['From: ' + from, 'To: ' + to, 'Subject: ' + subject,
                  'MIME-Version: 1.0', 'Content-Type: text/html; charset=UTF-8', '', html].join(CRLF);

    let sock, step = 0;
    const cmds = [
      () => sock.write('EHLO oxeball' + CRLF),
      () => sock.write('AUTH LOGIN' + CRLF),
      () => sock.write(b64(user) + CRLF),
      () => sock.write(b64(pass) + CRLF),
      () => sock.write('MAIL FROM:<' + user + '>' + CRLF),
      () => sock.write('RCPT TO:<' + to + '>' + CRLF),
      () => sock.write('DATA' + CRLF),
      () => sock.write(msg + CRLF + '.' + CRLF),
      () => { sock.write('QUIT' + CRLF); sock.destroy(); console.log('📧 Email sent via SMTP to', to); resolve({ ok: true }); }
    ];
    function advance(data) {
      if (data && (data.includes('535') || data.includes('550') || data.includes('554'))) {
        console.error('SMTP error:', data.slice(0, 100));
        try { sock.destroy(); } catch {}
        resolve({ ok: false, error: 'SMTP auth/delivery error' });
        return;
      }
      if (step < cmds.length) cmds[step++]();
    }
    const raw = net.connect({ host, port }, () => {});
    raw.once('data', () => {
      raw.write('STARTTLS' + CRLF);
      raw.once('data', d => {
        if (d.toString().includes('220')) {
          sock = tls.connect({ socket: raw, host }, () => {
            sock.on('data', d2 => advance(d2.toString()));
            advance();
          });
        } else advance();
      });
    });
    raw.on('error', e => { console.error('SMTP error:', e.message); resolve({ ok: false, error: e.message }); });
    raw.setTimeout(15000, () => { raw.destroy(); resolve({ ok: false, error: 'SMTP timeout' }); });
  });
}

// ── Main sendEmail ────────────────────────────────────────────────────────────
async function sendEmail(to, subject, html) {
  const resendKey = process.env.RESEND_API_KEY || '';
  if (resendKey) return sendViaResend(to, subject, html, resendKey);

  const smtpUser = process.env.SMTP_USER || '';
  const smtpPass = process.env.SMTP_PASS || '';
  if (smtpUser && smtpPass) return sendViaSMTP(to, subject, html);

  // DEV MODE — no email credentials configured
  console.log('\n' + '─'.repeat(44));
  console.log('📧  DEV MODE — set RESEND_API_KEY to send real emails');
  console.log('    To:', to);
  console.log('    Subject:', subject);
  console.log('─'.repeat(44) + '\n');
  return { ok: true, dev: true };
}

module.exports = {
  generateCode, storePending, getPending, deletePending, checkCode,
  sendEmail, codeEmailHtml
};
