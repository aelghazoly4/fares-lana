'use strict';
const { ObjectId } = require('mongodb');
const { getDb, eventId } = require('../lib/db');
const { COOKIE, TTL_SECONDS, passwordMatches, issueToken, isAuthed } = require('../lib/auth');
const { setCookie, send, readBody, sameOrigin, clientIp, hash } = require('../lib/http');

const TZ = process.env.TZ_NAME || 'Africa/Cairo';
const DAYS = 14;

function dayKey(date) {
  // YYYY-MM-DD in the configured timezone
  return new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(date);
}

function stamp(date) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false
  }).formatToParts(date).reduce((a, p) => { a[p.type] = p.value; return a; }, {});
  return parts.year + '-' + parts.month + '-' + parts.day + ' ' + parts.hour + ':' + parts.minute;
}

function csvCell(v) {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formula injection
  return '"' + s.replace(/"/g, '""') + '"';
}

async function login(req, res, db) {
  if (!process.env.ADMIN_PASSWORD) return send(res, 503, { error: 'not_configured' });

  const key = 'login:' + hash(clientIp(req));
  const since = new Date(Date.now() - 15 * 60 * 1000);
  const fails = await db.collection('attempts').countDocuments({ key, at: { $gte: since } });
  if (fails >= 8) return send(res, 429, { error: 'too_many_attempts' });

  const body = readBody(req);
  if (!passwordMatches(body.password)) {
    await db.collection('attempts').insertOne({ key, at: new Date() });
    return send(res, 401, { error: 'wrong_password' });
  }
  setCookie(req, res, COOKIE, issueToken(), { maxAge: TTL_SECONDS, sameSite: 'Strict' });
  return send(res, 200, { ok: true });
}

async function data(req, res, db) {
  const ev = eventId();
  const since = new Date(Date.now() - (DAYS + 1) * 24 * 3600 * 1000);

  const [visitors, viewsAgg, opened, byAttending, list, visitsByDay, rsvpsByDay] = await Promise.all([
    db.collection('visitors').countDocuments({ eventId: ev }),
    db.collection('visitors').aggregate([
      { $match: { eventId: ev } },
      { $group: { _id: null, v: { $sum: '$views' } } }
    ]).toArray(),
    db.collection('visitors').countDocuments({ eventId: ev, opened: true }),
    db.collection('rsvps').aggregate([
      { $match: { eventId: ev } },
      { $group: { _id: '$attending', n: { $sum: 1 } } }
    ]).toArray(),
    db.collection('rsvps').find({ eventId: ev }).sort({ createdAt: -1 }).limit(2000).toArray(),
    db.collection('visitors').find({ eventId: ev, firstSeen: { $gte: since } }, { projection: { firstSeen: 1 } }).toArray(),
    db.collection('rsvps').find({ eventId: ev, createdAt: { $gte: since } }, { projection: { createdAt: 1 } }).toArray()
  ]);

  const count = (val) => { const r = byAttending.find((x) => x._id === val); return r ? r.n : 0; };
  const attending = count(true);
  const declined = count(false);
  const responses = attending + declined;

  // bucket per calendar day in the configured timezone (done in JS so it works on any MongoDB)
  const vMap = {}; visitsByDay.forEach((x) => { const k = dayKey(x.firstSeen); vMap[k] = (vMap[k] || 0) + 1; });
  const rMap = {}; rsvpsByDay.forEach((x) => { const k = dayKey(x.createdAt); rMap[k] = (rMap[k] || 0) + 1; });
  const daily = [];
  for (let i = DAYS - 1; i >= 0; i--) {
    const k = dayKey(new Date(Date.now() - i * 24 * 3600 * 1000));
    daily.push({ date: k, visitors: vMap[k] || 0, responses: rMap[k] || 0 });
  }

  return send(res, 200, {
    event: { title: process.env.EVENT_TITLE || 'فارس & لانا' },
    stats: {
      visitors,
      views: viewsAgg[0] ? viewsAgg[0].v : 0,
      opened,
      responses,
      attending,
      declined
    },
    daily,
    rsvps: list.map((d) => ({
      id: String(d._id),
      name: d.name,
      attending: !!d.attending,
      message: d.message || '',
      createdAt: d.createdAt
    }))
  });
}

async function remove(req, res, db) {
  const id = String((req.query && req.query.id) || '');
  if (!/^[a-f0-9]{24}$/i.test(id) || !ObjectId.isValid(id)) return send(res, 400, { error: 'bad_id' });
  const r = await db.collection('rsvps').deleteOne({ _id: new ObjectId(id), eventId: eventId() });
  return send(res, 200, { ok: true, deleted: r.deletedCount });
}

async function exportCsv(req, res, db) {
  const list = await db.collection('rsvps').find({ eventId: eventId() }).sort({ createdAt: 1 }).toArray();
  const rows = [['الاسم', 'الحضور', 'الرسالة', 'التاريخ']];
  list.forEach((d) => rows.push([d.name, d.attending ? 'سيحضر' : 'لن يحضر', d.message || '', stamp(d.createdAt)]));
  const csv = '\uFEFF' + rows.map((r) => r.map(csvCell).join(',')).join('\r\n');
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="rsvp-' + dayKey(new Date()) + '.csv"');
  res.setHeader('Cache-Control', 'no-store');
  res.end(csv);
}

// /api/admin?action=login|logout|data|delete|export
module.exports = async (req, res) => {
  try {
    const action = String((req.query && req.query.action) || '');

    if (req.method !== 'GET' && !sameOrigin(req)) return send(res, 403, { error: 'forbidden' });

    if (action === 'logout' && req.method === 'POST') {
      setCookie(req, res, COOKIE, '', { maxAge: 0, sameSite: 'Strict' });
      return send(res, 200, { ok: true });
    }

    const db = await getDb();

    if (action === 'login' && req.method === 'POST') return await login(req, res, db);

    if (!isAuthed(req)) return send(res, 401, { error: 'unauthorized' });

    if (action === 'data' && req.method === 'GET') return await data(req, res, db);
    if (action === 'export' && req.method === 'GET') return await exportCsv(req, res, db);
    if (action === 'delete' && req.method === 'DELETE') return await remove(req, res, db);

    return send(res, 404, { error: 'not_found' });
  } catch (err) {
    console.error('admin error:', err && err.message);
    return send(res, 500, { error: 'server_error' });
  }
};
