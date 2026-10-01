'use strict';
const { MongoClient } = require('mongodb');

// Re-use the connection between invocations of the same serverless instance.
const cache = global.__wgMongo || (global.__wgMongo = { promise: null, client: null, indexed: false });

function eventId() {
  return (process.env.EVENT_ID || 'faris-lana').trim();
}

async function getDb() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI is not configured');

  if (!cache.promise) {
    cache.client = new MongoClient(uri, { maxPoolSize: 5, serverSelectionTimeoutMS: 8000 });
    cache.promise = cache.client.connect().catch((err) => {
      cache.promise = null; // allow a retry on the next request
      throw err;
    });
  }
  await cache.promise;

  const db = cache.client.db(process.env.MONGODB_DB || 'wedding_invitations');
  if (!cache.indexed) {
    await Promise.all([
      db.collection('rsvps').createIndex({ eventId: 1, visitorId: 1 }, { unique: true }),
      db.collection('rsvps').createIndex({ eventId: 1, createdAt: -1 }),
      db.collection('visitors').createIndex({ eventId: 1, visitorId: 1 }, { unique: true }),
      db.collection('visitors').createIndex({ eventId: 1, firstSeen: 1 }),
      db.collection('attempts').createIndex({ at: 1 }, { expireAfterSeconds: 900 }),
      db.collection('attempts').createIndex({ key: 1, at: 1 })
    ]);
    cache.indexed = true;
  }
  return db;
}

module.exports = { getDb, eventId };
