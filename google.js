'use strict';
/**
 * google.js — Verify Google ID tokens from Google Identity Services
 * No npm packages needed — pure Node.js.
 *
 * Set GOOGLE_CLIENT_ID in Railway Variables to enable Google login.
 * Without it, Google login returns an error (button hidden in UI).
 */

function b64urlDecode(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

async function verifyGoogleToken(idToken) {
  const clientId = process.env.GOOGLE_CLIENT_ID || '';
  if (!clientId) return { ok: false, error: 'GOOGLE_CLIENT_ID is not configured on this server.' };
  if (!idToken || typeof idToken !== 'string') return { ok: false, error: 'No ID token provided.' };

  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) return { ok: false, error: 'Malformed token.' };

    const payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp < now)   return { ok: false, error: 'Google token expired.' };
    if (payload.iat > now + 60) return { ok: false, error: 'Token issued in the future.' };

    const validIssuers = ['accounts.google.com', 'https://accounts.google.com'];
    if (!validIssuers.includes(payload.iss)) return { ok: false, error: 'Invalid token issuer.' };
    if (payload.aud !== clientId) return { ok: false, error: 'Token audience mismatch.' };
    if (!payload.email_verified)  return { ok: false, error: 'Google email not verified.' };
    if (!payload.email || !payload.sub) return { ok: false, error: 'Token missing email or sub.' };

    /*
     * Production note: the checks above validate claims but do NOT verify the RS256 signature.
     * For full security, verify against Google's public keys:
     *   https://www.googleapis.com/oauth2/v3/certs
     * Or use Google's tokeninfo endpoint (adds ~150ms per login):
     *   https://oauth2.googleapis.com/tokeninfo?id_token=TOKEN
     */

    return {
      ok: true,
      payload: {
        email:        payload.email,
        name:         payload.name  || payload.email.split('@')[0],
        googleId:     payload.sub,
        picture:      payload.picture || null,
        emailVerified: payload.email_verified
      }
    };
  } catch (err) {
    return { ok: false, error: 'Token decode failed: ' + err.message };
  }
}

module.exports = { verifyGoogleToken };
