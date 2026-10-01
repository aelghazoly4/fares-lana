'use strict';
const crypto = require('crypto');
const { getDb, eventId } = require('../lib/db');
const { parseCookies, setCookie, send, readBody, sameOrigin } = require('../lib/http');

const VID_COOKIE = 'wg_vid';
const ONE_YEAR = 60 * 60 * 24 * 365;
const BOTS = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|curl|wget|headless/i;

// POST /api/visit  { type: "view" | "open" }
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(res, 405, { error: 'method_not_allowed' });
  }
  if (!sameOrigin(req)) return send(res, 403, { error: 'forbidden' });
  if (BOTS.test(req.headers['user-agent'] || '')) return send(res, 204);

  try {
    const body = readBody(req);
    const type = body.type === 'open' ? 'open' : 'view';

    let vid = parseCookies(req)[VID_COOKIE];
    if (!/^[a-f0-9]{32}$/.test(vid || '')) vid = crypto.randomBytes(16).toString('hex');
    setCookie(req, res, VID_COOKIE, vid, { maxAge: ONE_YEAR });

    const now = new Date();
    const update = {
      $setOnInsert: { firstSeen: now },
      $set: { lastSeen: now }
    };
    if (type === 'view') {
      update.$inc = { views: 1 };
    } else {
      update.$set.opened = true;
      update.$min = { openedAt: now };
    }

    const db = await getDb();
    await db.collection('visitors').updateOne(
      { eventId: eventId(), visitorId: vid },
      update,
      { upsert: true }
    );
    return send(res, 204);
  } catch (err) {
    console.error('visit error:', err && err.message);
    return send(res, 500, { error: 'server_error' });
  }
};
