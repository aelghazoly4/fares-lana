'use strict';
const crypto = require('crypto');

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!k) return;
    try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; }
  });
  return out;
}

function isHttps(req) {
  return (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}

function setCookie(req, res, name, value, opts) {
  opts = opts || {};
  const parts = [name + '=' + encodeURIComponent(value), 'Path=/', 'HttpOnly'];
  parts.push('SameSite=' + (opts.sameSite || 'Lax'));
  if (typeof opts.maxAge === 'number') parts.push('Max-Age=' + Math.floor(opts.maxAge));
  if (isHttps(req)) parts.push('Secure');
  const prev = res.getHeader('Set-Cookie');
  const list = prev ? (Array.isArray(prev) ? prev : [String(prev)]) : [];
  list.push(parts.join('; '));
  res.setHeader('Set-Cookie', list);
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Cache-Control', 'no-store');
  if (body === undefined) { res.end(); return; }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function readBody(req) {
  let b = req.body;
  if (b == null || b === '') return {};
  if (Buffer.isBuffer(b)) b = b.toString('utf8');
  if (typeof b === 'string') {
    try { return JSON.parse(b); } catch (e) { return {}; }
  }
  return typeof b === 'object' ? b : {};
}

function clientIp(req) {
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || 'unknown';
}

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

// Reject cross-site browser requests (basic CSRF / drive-by spam protection).
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // same-origin GET/navigation requests may omit it
  try {
    return new URL(origin).host === req.headers.host;
  } catch (e) {
    return false;
  }
}

// Simple per-IP throttle stored in MongoDB (works across serverless instances).
async function throttle(db, kind, req, limit, windowMs) {
  const key = kind + ':' + hash(clientIp(req));
  const since = new Date(Date.now() - windowMs);
  const count = await db.collection('attempts').countDocuments({ key, at: { $gte: since } });
  if (count >= limit) return false;
  await db.collection('attempts').insertOne({ key, at: new Date() });
  return true;
}

function cleanText(value, max, allowNewlines) {
  if (typeof value !== 'string') return '';
  let s = value.normalize('NFC');
  // strip control characters (keep \n when allowed)
  s = allowNewlines
    ? s.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, '')
    : s.replace(/[\u0000-\u001F\u007F]/g, ' ');
  s = allowNewlines ? s.replace(/\r\n?/g, '\n').replace(/\n{3,}/g, '\n\n') : s.replace(/\s+/g, ' ');
  s = s.trim();
  return s.length > max ? s.slice(0, max) : s;
}

module.exports = { parseCookies, setCookie, send, readBody, clientIp, hash, sameOrigin, throttle, cleanText };
