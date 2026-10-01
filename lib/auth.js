'use strict';
const crypto = require('crypto');
const { parseCookies } = require('./http');

const COOKIE = 'wg_admin';
const TTL_SECONDS = 60 * 60 * 24 * 14; // 14 days

function secret() {
  // Derived from the admin password: changing the password signs everyone out.
  return crypto.createHash('sha256').update('wg-admin-v1:' + (process.env.ADMIN_PASSWORD || '')).digest();
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(payload) {
  const body = b64url(JSON.stringify(payload));
  const mac = b64url(crypto.createHmac('sha256', secret()).update(body).digest());
  return body + '.' + mac;
}

function verify(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const body = parts[0];
  const mac = parts[1];
  const expected = b64url(crypto.createHmac('sha256', secret()).update(body).digest());
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function passwordMatches(input) {
  const real = process.env.ADMIN_PASSWORD || '';
  if (!real) return false;
  const a = crypto.createHash('sha256').update(String(input || '')).digest();
  const b = crypto.createHash('sha256').update(real).digest();
  return crypto.timingSafeEqual(a, b);
}

function issueToken() {
  return sign({ exp: Math.floor(Date.now() / 1000) + TTL_SECONDS });
}

function isAuthed(req) {
  if (!process.env.ADMIN_PASSWORD) return false;
  return !!verify(parseCookies(req)[COOKIE]);
}

module.exports = { COOKIE, TTL_SECONDS, passwordMatches, issueToken, isAuthed };
