'use strict';
const crypto = require('crypto');
const { getDb, eventId } = require('../lib/db');
const { parseCookies, setCookie, send, readBody, sameOrigin, throttle, cleanText } = require('../lib/http');

const VID_COOKIE = 'wg_vid';
const ONE_YEAR = 60 * 60 * 24 * 365;

function getVid(req) {
  const v = parseCookies(req)[VID_COOKIE];
  return /^[a-f0-9]{32}$/.test(v || '') ? v : null;
}

// GET  /api/rsvp  -> has this browser already answered?
// POST /api/rsvp  { name, attending: boolean, message?, website? (honeypot) }
module.exports = async (req, res) => {
  try {
    if (req.method === 'GET') {
      const vid = getVid(req);
      if (!vid) return send(res, 200, { submitted: false });
      const db = await getDb();
      const doc = await db.collection('rsvps').findOne(
        { eventId: eventId(), visitorId: vid },
        { projection: { name: 1, attending: 1 } }
      );
      if (!doc) return send(res, 200, { submitted: false });
      return send(res, 200, { submitted: true, name: doc.name, attending: !!doc.attending });
    }

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return send(res, 405, { error: 'method_not_allowed' });
    }
    if (!sameOrigin(req)) return send(res, 403, { error: 'forbidden' });

    const body = readBody(req);

    // Honeypot: real people never fill this hidden field. Pretend success, store nothing.
    if (typeof body.website === 'string' && body.website.trim() !== '') {
      return send(res, 201, { ok: true });
    }

    const name = cleanText(body.name, 80, false);
    const message = cleanText(body.message, 500, true);
    if (name.length < 2) {
      return send(res, 400, { error: 'invalid_name', message: 'من فضلك اكتب اسمك.' });
    }
    if (typeof body.attending !== 'boolean') {
      return send(res, 400, { error: 'invalid_attending', message: 'من فضلك اختر هل ستحضر أم لا.' });
    }

    const db = await getDb();

    if (!(await throttle(db, 'rsvp', req, 25, 15 * 60 * 1000))) {
      return send(res, 429, { error: 'too_many_requests' });
    }

    let vid = getVid(req);
    if (!vid) vid = crypto.randomBytes(16).toString('hex');
    setCookie(req, res, VID_COOKIE, vid, { maxAge: ONE_YEAR });

    const doc = {
      eventId: eventId(),
      visitorId: vid,
      name,
      attending: body.attending,
      message,
      createdAt: new Date()
    };

    try {
      await db.collection('rsvps').insertOne(doc);
    } catch (err) {
      if (err && err.code === 11000) {
        // This browser already answered: do not allow a second submission.
        const existing = await db.collection('rsvps').findOne(
          { eventId: doc.eventId, visitorId: vid },
          { projection: { name: 1, attending: 1 } }
        );
        return send(res, 409, {
          error: 'already_submitted',
          name: existing ? existing.name : name,
          attending: existing ? !!existing.attending : body.attending
        });
      }
      throw err;
    }

    return send(res, 201, { ok: true });
  } catch (err) {
    console.error('rsvp error:', err && err.message);
    return send(res, 500, { error: 'server_error' });
  }
};
