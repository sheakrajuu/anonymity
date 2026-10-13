'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');

const scrypt = promisify(crypto.scrypt);
const passwordLength = 128;
const defaultMaxMediaBytes = 50 * 1024 * 1024;
const sessionCookie = 'stay_connected_session';
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function fail(status, message) {
  throw new HttpError(status, message);
}

function createApp(options = {}) {
  const dataDir = path.resolve(options.dataDir || process.env.DATA_DIR || path.join(__dirname, 'data'));
  const mediaDir = path.join(dataDir, 'media');
  fs.mkdirSync(mediaDir, { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path.join(dataDir, 'stay-connected.sqlite'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      username_norm TEXT NOT NULL UNIQUE,
      password_salt BLOB NOT NULL,
      password_hash BLOB NOT NULL,
      public_key TEXT NOT NULL,
      private_bundle TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      max_members INTEGER NOT NULL,
      clear_on_end INTEGER NOT NULL DEFAULT 1,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      ended_at INTEGER,
      is_active INTEGER NOT NULL DEFAULT 1,
      is_permanent INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS room_members (
      room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at INTEGER NOT NULL,
      PRIMARY KEY (room_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS invites (
      code TEXT PRIMARY KEY,
      room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      UNIQUE (room_id)
    );
    CREATE TABLE IF NOT EXISTS key_packages (
      room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      epoch INTEGER NOT NULL,
      sender_id TEXT NOT NULL REFERENCES users(id),
      sender_public_key TEXT NOT NULL,
      nonce TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      PRIMARY KEY (room_id, user_id, epoch)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id),
      epoch INTEGER NOT NULL,
      nonce TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS messages_room_time ON messages(room_id, created_at);
    CREATE TABLE IF NOT EXISTS media (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id),
      epoch INTEGER NOT NULL,
      file_name TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS contacts (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      contact_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, contact_id),
      CHECK (user_id != contact_id)
    );
    CREATE TABLE IF NOT EXISTS blocks (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, blocked_id),
      CHECK (user_id != blocked_id)
    );
  `);

  const maxMediaBytes = Math.min(
    Math.max(Number(options.maxMediaBytes || process.env.MAX_MEDIA_BYTES || defaultMaxMediaBytes), 1024),
    100 * 1024 * 1024
  );
  const maxRoomStorageBytes = Math.min(
    Math.max(Number(options.maxRoomStorageBytes || process.env.MAX_ROOM_STORAGE_BYTES || 512 * 1024 * 1024), maxMediaBytes),
    2 * 1024 * 1024 * 1024
  );
  const maxConcurrentUploads = 4;
  let activeUploads = 0;
  const pendingUploadsByRoom = new Map();
  const sessionTtlMs = Math.min(
    Math.max(Number(options.sessionTtlMs || Number(process.env.SESSION_TTL_HOURS || 168) * 60 * 60 * 1000), 60 * 60 * 1000),
    720 * 60 * 60 * 1000
  );
  const app = express();
  const rateLimits = new Map();
  const now = () => Date.now();
  const randomToken = size => crypto.randomBytes(size).toString('base64url');
  const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
  function transaction(callback) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = callback();
      db.exec('COMMIT');
      return result;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  const statements = {
    user: db.prepare('SELECT * FROM users WHERE id = ?'),
    room: db.prepare('SELECT * FROM rooms WHERE id = ? AND is_active = 1 AND expires_at > ?'),
    member: db.prepare('SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?'),
    package: db.prepare('SELECT 1 FROM key_packages WHERE room_id = ? AND user_id = ? AND epoch = ?'),
    maxEpoch: db.prepare('SELECT COALESCE(MAX(epoch), 0) AS epoch FROM key_packages WHERE room_id = ?'),
    isBlocked: db.prepare('SELECT 1 FROM blocks WHERE (user_id = ? AND blocked_id = ?) OR (user_id = ? AND blocked_id = ?)'),
    roomMembers: db.prepare(`
      SELECT u.id, u.public_key AS publicKey, rm.joined_at
      FROM room_members rm JOIN users u ON u.id = rm.user_id
      WHERE rm.room_id = ? ORDER BY rm.joined_at, u.id
    `)
  };

  function ensureSameOrigin(req) {
    const origin = req.get('origin');
    if (!origin) fail(403, 'A same-origin browser request is required.');
    const forwardedProto = req.get('x-forwarded-proto');
    const protocol = forwardedProto === 'https' ? 'https' : req.protocol;
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      fail(403, 'A same-origin browser request is required.');
    }
    if (parsed.origin !== `${protocol}://${req.get('host')}`) {
      fail(403, 'A same-origin browser request is required.');
    }
  }

  function rateLimit(req, bucket, maximum, windowMs) {
    const key = `${bucket}:${req.ip}`;
    const current = rateLimits.get(key) || [];
    const recent = current.filter(timestamp => timestamp > now() - windowMs);
    if (recent.length >= maximum) fail(429, 'Too many requests. Please wait and try again.');
    recent.push(now());
    rateLimits.set(key, recent);
    if (rateLimits.size > 10000) {
      for (const [entryKey, timestamps] of rateLimits) {
        if (!timestamps.length || timestamps.at(-1) <= now() - 60 * 60 * 1000) rateLimits.delete(entryKey);
      }
    }
  }

  function uploadGate(req, res, next) {
    rateLimit(req, 'media-upload', 120, 60 * 1000);
    if (activeUploads >= maxConcurrentUploads) fail(429, 'The server is handling several uploads. Please retry shortly.');
    const contentLength = Number(req.get('content-length'));
    if (!Number.isSafeInteger(contentLength) || contentLength < 1) fail(411, 'A content length is required for encrypted uploads.');
    if (contentLength > maxMediaBytes) fail(413, 'The encrypted upload exceeds the server limit.');
    const roomId = req.params.id;
    const storedBytes = db.prepare('SELECT COALESCE(SUM(size), 0) AS total FROM media WHERE room_id = ?').get(roomId).total;
    const pendingBytes = pendingUploadsByRoom.get(roomId) || 0;
    if (storedBytes + pendingBytes + contentLength > maxRoomStorageBytes) {
      fail(413, 'This conversation has reached its encrypted media storage limit.');
    }
    activeUploads++;
    pendingUploadsByRoom.set(roomId, pendingBytes + contentLength);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      activeUploads--;
      const remainingBytes = (pendingUploadsByRoom.get(roomId) || 0) - contentLength;
      if (remainingBytes > 0) pendingUploadsByRoom.set(roomId, remainingBytes);
      else pendingUploadsByRoom.delete(roomId);
    };
    res.once('finish', release);
    res.once('close', release);
    next();
  }

  function requireAuth(req, _res, next) {
    try {
      const raw = req.get('cookie') || '';
      const token = raw.split(';').map(item => item.trim()).find(item => item.startsWith(`${sessionCookie}=`))?.slice(sessionCookie.length + 1);
      if (!token) fail(401, 'Sign in to continue.');
      const session = db.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?').get(hashToken(token));
      if (!session || session.expires_at <= now()) {
        if (session) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
        fail(401, 'Your sign-in session has expired.');
      }
      req.user = statements.user.get(session.user_id);
      if (!req.user) fail(401, 'Your sign-in session is no longer valid.');
      next();
    } catch (error) {
      next(error);
    }
  }

  function writeOrigin(req, _res, next) {
    try {
      if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) ensureSameOrigin(req);
      next();
    } catch (error) {
      next(error);
    }
  }

  function setSession(res, userId) {
    const token = randomToken(32);
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
      hashToken(token), userId, now() + sessionTtlMs
    );
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${sessionCookie}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(sessionTtlMs / 1000)}${secure}`);
  }

  function clearSession(req, res) {
    const token = (req.get('cookie') || '').split(';').map(item => item.trim())
      .find(item => item.startsWith(`${sessionCookie}=`))?.slice(sessionCookie.length + 1);
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
    res.setHeader('Set-Cookie', `${sessionCookie}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
  }

  function publicAccount(user) {
    return {
      id: user.id,
      username: user.username,
      publicKey: JSON.parse(user.public_key),
      privateBundle: JSON.parse(user.private_bundle)
    };
  }

  function validatePublicKey(key) {
    return key && typeof key === 'object' && !Array.isArray(key) &&
      key.kty === 'EC' && key.crv === 'P-256' &&
      typeof key.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(key.x) &&
      typeof key.y === 'string' && /^[A-Za-z0-9_-]{43}$/.test(key.y) &&
      !Object.hasOwn(key, 'd');
  }

  function validatePrivateBundle(bundle) {
    return bundle && typeof bundle === 'object' && !Array.isArray(bundle) &&
      ['salt', 'iv', 'ciphertext'].every(field => typeof bundle[field] === 'string' &&
        bundle[field].length > 0 && bundle[field].length <= 8192);
  }

  function isBlocked(firstId, secondId) {
    return Boolean(statements.isBlocked.get(firstId, secondId, secondId, firstId));
  }

  function getRoomForMember(roomId, userId) {
    const room = statements.room.get(roomId, now());
    const contact = room?.is_permanent
      ? db.prepare('SELECT contact_id FROM contacts WHERE user_id = ? AND room_id = ?').get(userId, roomId)
      : null;
    if (!room || !statements.member.get(roomId, userId) ||
        (room.is_permanent && (!contact || isBlocked(userId, contact.contact_id)))) {
      fail(404, 'Conversation not found.');
    }
    return room;
  }

  function ensureCurrentKey(room, userId, epoch) {
    const currentEpoch = statements.maxEpoch.get(room.id).epoch;
    if (epoch !== currentEpoch || !statements.package.get(room.id, userId, epoch)) {
      fail(403, 'A current conversation key is required.');
    }
  }

  function getRoomSummary(room, userId) {
    const members = statements.roomMembers.all(room.id).map(member => ({
      id: member.id,
      publicKey: member.publicKey,
      joined_at: member.joined_at
    }));
    const epoch = statements.maxEpoch.get(room.id).epoch;
    const keyCount = epoch ? db.prepare('SELECT COUNT(*) AS count FROM key_packages WHERE room_id = ? AND epoch = ?').get(room.id, epoch).count : 0;
    const keyPackages = db.prepare(`
      SELECT user_id, epoch, sender_id, sender_public_key, nonce, ciphertext
      FROM key_packages WHERE room_id = ? AND user_id = ? ORDER BY epoch
    `).all(room.id, userId).map(item => ({
      userId: item.user_id,
      epoch: item.epoch,
      sender_id: item.sender_id,
      sender_public_key: item.sender_public_key,
      nonce: item.nonce,
      ciphertext: item.ciphertext
    }));
    const invite = room.owner_id === userId && !room.is_permanent
      ? db.prepare('SELECT code FROM invites WHERE room_id = ?').get(room.id)?.code
      : undefined;
    const contactId = room.is_permanent
      ? db.prepare('SELECT contact_id FROM contacts WHERE user_id = ? AND room_id = ?').get(userId, room.id)?.contact_id
      : null;
    const displayName = contactId ? statements.user.get(contactId)?.username || room.name : room.name;
    return {
      ...room,
      name: displayName,
      members,
      member_count: members.length,
      epoch,
      key_count: keyCount,
      keyPackages,
      ...(invite ? { inviteCode: invite } : {})
    };
  }

  function validatePackages(packages, room, userId, expectedEpoch, currentMemberIds) {
    if (!Array.isArray(packages) || packages.length < 1 || packages.length > room.max_members) {
      fail(400, 'Invalid conversation key packages.');
    }
    const activeIds = currentMemberIds || statements.roomMembers.all(room.id).map(member => member.id);
    const seen = new Set();
    for (const item of packages) {
      if (!item || !activeIds.includes(item.userId) || seen.has(item.userId) ||
          item.epoch !== expectedEpoch || typeof item.nonce !== 'string' ||
          item.nonce.length > 64 || typeof item.ciphertext !== 'string' ||
          item.ciphertext.length < 4 || item.ciphertext.length > 8192 ||
          !validatePublicKey(item.senderPublicKey)) {
        fail(400, 'Invalid conversation key package.');
      }
      seen.add(item.userId);
    }
    if (seen.size !== activeIds.length || !seen.has(userId)) {
      fail(400, 'A key package is required for each current participant.');
    }
    return packages;
  }

  function savePackages(room, userId, packages, expectedEpoch) {
    const insert = db.prepare(`
      INSERT INTO key_packages (room_id, user_id, epoch, sender_id, sender_public_key, nonce, ciphertext)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    try {
      transaction(() => {
      for (const item of packages) {
        insert.run(room.id, item.userId, expectedEpoch, userId, JSON.stringify(item.senderPublicKey), item.nonce, item.ciphertext);
      }
      });
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) fail(409, 'This conversation key epoch already exists.');
      throw error;
    }
  }

  function removeRoomFiles(roomId) {
    const files = db.prepare('SELECT file_name FROM media WHERE room_id = ?').all(roomId);
    for (const file of files) {
      try {
        fs.unlinkSync(path.join(mediaDir, file.file_name));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
  }

  function deleteRoom(roomId) {
    removeRoomFiles(roomId);
    db.prepare('DELETE FROM rooms WHERE id = ?').run(roomId);
  }

  function cleanup() {
    const expired = db.prepare('SELECT id FROM rooms WHERE expires_at <= ?').all(now());
    for (const room of expired) deleteRoom(room.id);
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now());
    const referenced = new Set(db.prepare('SELECT file_name FROM media').all().map(item => item.file_name));
    for (const file of fs.readdirSync(mediaDir)) {
      const filePath = path.join(mediaDir, file);
      const oldUnreferencedFile = !referenced.has(file) &&
        now() - fs.statSync(filePath).mtimeMs > 60 * 60 * 1000;
      if (file.endsWith('.part') || oldUnreferencedFile) {
        try { fs.unlinkSync(path.join(mediaDir, file)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      }
    }
  }

  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    next();
  });
  app.use(express.json({ limit: '1mb', strict: true }));
  app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'anonymity.html')));
  app.get('/anonymity.html', (_req, res) => res.sendFile(path.join(__dirname, 'anonymity.html')));
  app.get('/app.js', (_req, res) => res.sendFile(path.join(__dirname, 'app.js')));
  app.get('/style.css', (_req, res) => res.sendFile(path.join(__dirname, 'style.css')));
  app.use('/api', writeOrigin);

  app.post('/api/register', (req, res, next) => {
    rateLimit(req, 'register', 40, 60 * 60 * 1000);
    const { username, password, publicKey, privateBundle } = req.body || {};
    if (typeof username !== 'string' || !/^[A-Za-z0-9_.-]{3,24}$/.test(username) ||
        typeof password !== 'string' || password.length < 12 || password.length > passwordLength ||
        !validatePublicKey(publicKey) || !validatePrivateBundle(privateBundle)) {
      fail(400, 'Enter a valid username and strong, distinct account and encryption credentials.');
    }
    (async () => {
      try {
        const salt = crypto.randomBytes(16);
        const passwordHash = await scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
        const id = crypto.randomUUID();
        try {
          db.prepare(`
            INSERT INTO users (id, username, username_norm, password_salt, password_hash, public_key, private_bundle, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).run(id, username, username.toLowerCase(), salt, passwordHash, JSON.stringify(publicKey), JSON.stringify(privateBundle), now());
        } catch (error) {
          if (String(error.message).includes('UNIQUE')) fail(409, 'That username is already registered.');
          throw error;
        }
        const user = statements.user.get(id);
        setSession(res, id);
        res.status(201).json(publicAccount(user));
      } catch (error) {
        next(error);
      }
    })();
  });

  app.post('/api/login', (req, res) => {
    rateLimit(req, 'login', 20, 15 * 60 * 1000);
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') fail(400, 'Username and password are required.');
    const user = db.prepare('SELECT * FROM users WHERE username_norm = ?').get(username.toLowerCase());
    if (!user) fail(401, 'Username or password is incorrect.');
    const candidate = crypto.scryptSync(password, user.password_salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    if (!crypto.timingSafeEqual(candidate, user.password_hash)) fail(401, 'Username or password is incorrect.');
    setSession(res, user.id);
    res.json(publicAccount(user));
  });

  app.get('/api/me', requireAuth, (req, res) => res.json(publicAccount(req.user)));
  app.post('/api/logout', requireAuth, (req, res) => {
    clearSession(req, res);
    res.status(204).end();
  });

  app.get('/api/rooms', requireAuth, (req, res) => {
    const rows = db.prepare(`
      SELECT r.* FROM rooms r
      JOIN room_members m ON m.room_id = r.id
      WHERE m.user_id = ? AND r.is_active = 1 AND r.expires_at > ?
      ORDER BY r.created_at DESC
    `).all(req.user.id, now());
    res.json(rows.filter(room => {
      if (!room.is_permanent) return true;
      const contact = db.prepare('SELECT contact_id FROM contacts WHERE user_id = ? AND room_id = ?').get(req.user.id, room.id);
      return contact && !isBlocked(req.user.id, contact.contact_id);
    })
      .map(room => getRoomSummary(room, req.user.id)));
  });

  app.post('/api/rooms', requireAuth, (req, res) => {
    rateLimit(req, 'room-create', 20, 60 * 60 * 1000);
    const { maxMembers = 10 } = req.body || {};
    const name = req.body?.name ?? 'Temporary conversation';
    if (typeof name !== 'string' || !name.trim() || name.trim().length > 48 ||
        !Number.isSafeInteger(maxMembers) || maxMembers < 2 || maxMembers > 20 ||
        (req.body?.clearOnEnd !== undefined && typeof req.body.clearOnEnd !== 'boolean')) {
      fail(400, 'Choose a name and a participant limit from 2 to 20.');
    }
    const id = crypto.randomUUID();
    const inviteCode = randomToken(18);
    const createdAt = now();
    transaction(() => {
      db.prepare(`
        INSERT INTO rooms (id, owner_id, name, max_members, clear_on_end, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, req.user.id, name.trim(), maxMembers, 1, Number.MAX_SAFE_INTEGER, createdAt);
      db.prepare('INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)').run(id, req.user.id, createdAt);
      db.prepare('INSERT INTO invites (code, room_id, created_at) VALUES (?, ?, ?)').run(inviteCode, id, createdAt);
    });
    res.status(201).json(getRoomSummary(statements.room.get(id, now()), req.user.id));
  });

  app.post('/api/invites/:code/join', requireAuth, (req, res) => {
    rateLimit(req, 'room-join', 60, 60 * 60 * 1000);
    const room = db.prepare(`
      SELECT r.* FROM rooms r JOIN invites i ON i.room_id = r.id WHERE i.code = ? AND r.is_active = 1 AND r.expires_at > ?
    `).get(req.params.code, now());
    if (!room || room.is_permanent) fail(404, 'That temporary conversation ID is unavailable.');
    if (isBlocked(req.user.id, room.owner_id)) fail(404, 'That temporary conversation ID is unavailable.');
    if (statements.member.get(room.id, req.user.id)) {
      return res.json({ roomId: room.id, waitingForKeyRotation: false });
    }
    const count = db.prepare('SELECT COUNT(*) AS count FROM room_members WHERE room_id = ?').get(room.id).count;
    if (count >= room.max_members) fail(409, 'This conversation has reached its participant limit.');
    db.prepare('INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)').run(room.id, req.user.id, now());
    res.status(201).json({ roomId: room.id, waitingForKeyRotation: true });
  });

  app.post('/api/rooms/:id/keys', requireAuth, (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    if (room.owner_id !== req.user.id || statements.maxEpoch.get(room.id).epoch !== 0) {
      fail(404, 'Conversation not found.');
    }
    const packages = validatePackages(req.body?.packages, room, req.user.id, 1);
    savePackages(room, req.user.id, packages, 1);
    res.json({ epoch: 1 });
  });

  app.post('/api/rooms/:id/rotate', requireAuth, (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    if (room.owner_id !== req.user.id) fail(404, 'Conversation not found.');
    const oldEpoch = statements.maxEpoch.get(room.id).epoch;
    if (!oldEpoch) fail(409, 'Create the first conversation key before rotating it.');
    const removals = req.body?.removeUserIds;
    if (!Array.isArray(removals) || removals.some(id => typeof id !== 'string' || id === req.user.id) ||
        new Set(removals).size !== removals.length) fail(400, 'Invalid participant removal request.');
    for (const userId of removals) {
      if (!statements.member.get(room.id, userId)) fail(400, 'Participant is not in this conversation.');
    }
    const nextMemberIds = statements.roomMembers.all(room.id)
      .map(member => member.id)
      .filter(id => !removals.includes(id));
    if (!nextMemberIds.length) fail(400, 'A conversation must keep at least one participant.');
    const packages = validatePackages(req.body?.packages, room, req.user.id, oldEpoch + 1, nextMemberIds);
    transaction(() => {
      for (const userId of removals) db.prepare('DELETE FROM room_members WHERE room_id = ? AND user_id = ?').run(room.id, userId);
      if (removals.length && !room.is_permanent) {
        db.prepare('DELETE FROM invites WHERE room_id = ?').run(room.id);
        db.prepare('INSERT INTO invites (code, room_id, created_at) VALUES (?, ?, ?)').run(randomToken(18), room.id, now());
      }
      const insert = db.prepare(`
        INSERT INTO key_packages (room_id, user_id, epoch, sender_id, sender_public_key, nonce, ciphertext)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      for (const item of packages) {
        insert.run(room.id, item.userId, oldEpoch + 1, req.user.id, JSON.stringify(item.senderPublicKey), item.nonce, item.ciphertext);
      }
    });
    const inviteCode = room.is_permanent
      ? undefined : db.prepare('SELECT code FROM invites WHERE room_id = ?').get(room.id)?.code;
    res.json({ epoch: oldEpoch + 1, ...(inviteCode ? { inviteCode } : {}) });
  });

  app.patch('/api/rooms/:id/settings', requireAuth, (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    if (room.owner_id !== req.user.id) fail(404, 'Conversation not found.');
    if (req.body?.clearOnEnd !== true) fail(400, 'Temporary conversations always delete server-held data immediately when ended.');
    res.json({ clear_on_end: 1 });
  });

  app.delete('/api/rooms/:id', requireAuth, (req, res) => {
    const room = db.prepare('SELECT * FROM rooms WHERE id = ? AND is_active = 1').get(req.params.id);
    if (!room || room.owner_id !== req.user.id || !statements.member.get(room.id, req.user.id)) fail(404, 'Conversation not found.');
    db.prepare('DELETE FROM invites WHERE room_id = ?').run(room.id);
    deleteRoom(room.id);
    res.status(204).end();
  });

  app.get('/api/rooms/:id/messages', requireAuth, (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    ensureCurrentKey(room, req.user.id, statements.maxEpoch.get(room.id).epoch);
    const rows = db.prepare(`
      SELECT id, user_id, epoch, nonce, ciphertext, created_at
      FROM messages WHERE room_id = ? ORDER BY created_at, id
    `).all(room.id);
    res.json(rows.map(row => ({ ...row, sender_id: row.user_id })));
  });

  app.post('/api/rooms/:id/messages', requireAuth, (req, res) => {
    rateLimit(req, 'message-send', 120, 60 * 1000);
    const room = getRoomForMember(req.params.id, req.user.id);
    const { id, epoch, nonce, ciphertext } = req.body || {};
    if (typeof id !== 'string' || !uuidPattern.test(id) || !Number.isSafeInteger(epoch) ||
        typeof nonce !== 'string' || nonce.length < 12 || nonce.length > 64 ||
        typeof ciphertext !== 'string' || ciphertext.length < 16 || ciphertext.length > 2 * 1024 * 1024) {
      fail(400, 'Invalid encrypted message.');
    }
    ensureCurrentKey(room, req.user.id, epoch);
    try {
      db.prepare(`
        INSERT INTO messages (id, room_id, user_id, epoch, nonce, ciphertext, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, room.id, req.user.id, epoch, nonce, ciphertext, now());
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) fail(409, 'That message has already been sent.');
      throw error;
    }
    res.status(201).json({ id });
  });

  app.post('/api/rooms/:id/media', requireAuth, uploadGate, express.raw({
    type: 'application/octet-stream',
    limit: maxMediaBytes
  }), (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    const id = req.get('x-media-id');
    const epoch = Number(req.get('x-media-epoch'));
    if (!uuidPattern.test(id || '') || !Number.isSafeInteger(epoch) || !Buffer.isBuffer(req.body) ||
        req.body.length < 1 || req.body.length > maxMediaBytes) fail(400, 'Invalid encrypted media upload.');
    ensureCurrentKey(room, req.user.id, epoch);
    const roomUsage = db.prepare('SELECT COALESCE(SUM(size), 0) AS total FROM media WHERE room_id = ?').get(room.id).total;
    if (roomUsage + req.body.length > maxRoomStorageBytes) {
      fail(413, 'This conversation has reached its encrypted media storage limit.');
    }
    const fileName = `${crypto.randomUUID()}.bin`;
    fs.writeFileSync(path.join(mediaDir, fileName), req.body, { flag: 'wx', mode: 0o600 });
    try {
      db.prepare(`
        INSERT INTO media (id, room_id, user_id, epoch, file_name, size, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, room.id, req.user.id, epoch, fileName, req.body.length, now());
    } catch (error) {
      fs.unlinkSync(path.join(mediaDir, fileName));
      if (String(error.message).includes('UNIQUE')) fail(409, 'That media item already exists.');
      throw error;
    }
    res.status(201).json({ id });
  });

  app.get('/api/rooms/:id/media/:mediaId', requireAuth, (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    const item = db.prepare('SELECT * FROM media WHERE id = ? AND room_id = ?').get(req.params.mediaId, room.id);
    if (!item) fail(404, 'Encrypted media not found.');
    if (!statements.package.get(room.id, req.user.id, item.epoch)) fail(404, 'Encrypted media not found.');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', item.size);
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.join(mediaDir, item.file_name));
  });

  app.delete('/api/rooms/:id/media/:mediaId', requireAuth, (req, res) => {
    const room = getRoomForMember(req.params.id, req.user.id);
    const item = db.prepare('SELECT * FROM media WHERE id = ? AND room_id = ? AND user_id = ?')
      .get(req.params.mediaId, room.id, req.user.id);
    if (!item) fail(404, 'Encrypted media not found.');
    try {
      fs.unlinkSync(path.join(mediaDir, item.file_name));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    db.prepare('DELETE FROM media WHERE id = ?').run(item.id);
    res.status(204).end();
  });

  app.post('/api/contacts', requireAuth, (req, res) => {
    rateLimit(req, 'contact-create', 50, 60 * 60 * 1000);
    const contactId = req.body?.userId;
    if (typeof contactId !== 'string' || !uuidPattern.test(contactId) || contactId === req.user.id) {
      fail(400, 'Enter another person’s valid account ID.');
    }
    const contact = statements.user.get(contactId);
    if (!contact) fail(404, 'No account matches that ID.');
    if (isBlocked(req.user.id, contactId)) fail(403, 'This contact is blocked.');
    if (db.prepare('SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?').get(req.user.id, contactId)) {
      fail(409, 'This account is already a contact.');
    }
    const id = crypto.randomUUID();
    const createdAt = now();
    transaction(() => {
      db.prepare(`
        INSERT INTO rooms (id, owner_id, name, max_members, clear_on_end, expires_at, created_at, is_permanent)
        VALUES (?, ?, 'Permanent contact', 2, 1, ?, ?, 1)
      `).run(id, req.user.id, Number.MAX_SAFE_INTEGER, createdAt);
      db.prepare('INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)').run(id, req.user.id, createdAt);
      db.prepare('INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)').run(id, contactId, createdAt);
      db.prepare('INSERT INTO contacts (user_id, contact_id, room_id, created_at) VALUES (?, ?, ?, ?)').run(req.user.id, contactId, id, createdAt);
      db.prepare('INSERT INTO contacts (user_id, contact_id, room_id, created_at) VALUES (?, ?, ?, ?)').run(contactId, req.user.id, id, createdAt);
    });
    const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(id);
    res.status(201).json(getRoomSummary(room, req.user.id));
  });

  app.get('/api/contacts', requireAuth, (req, res) => {
    const rows = db.prepare(`
      SELECT c.contact_id AS id, u.username, c.created_at
      FROM contacts c JOIN users u ON u.id = c.contact_id
      WHERE c.user_id = ? ORDER BY c.created_at DESC
    `).all(req.user.id);
    res.json(rows);
  });

  app.delete('/api/contacts/:id', requireAuth, (req, res) => {
    const relation = db.prepare('SELECT room_id FROM contacts WHERE user_id = ? AND contact_id = ?')
      .get(req.user.id, req.params.id);
    if (!relation) fail(404, 'Contact not found.');
    deleteRoom(relation.room_id);
    res.status(204).end();
  });

  app.get('/api/blocks', requireAuth, (req, res) => {
    res.json(db.prepare(`
      SELECT b.blocked_id AS id, u.username, b.created_at
      FROM blocks b JOIN users u ON u.id = b.blocked_id
      WHERE b.user_id = ? ORDER BY b.created_at DESC
    `).all(req.user.id));
  });

  app.post('/api/blocks/:id', requireAuth, (req, res) => {
    const target = statements.user.get(req.params.id);
    if (!target || target.id === req.user.id) fail(404, 'Account not found.');
    db.prepare('INSERT OR IGNORE INTO blocks (user_id, blocked_id, created_at) VALUES (?, ?, ?)')
      .run(req.user.id, target.id, now());
    res.status(204).end();
  });

  app.delete('/api/blocks/:id', requireAuth, (req, res) => {
    db.prepare('DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?').run(req.user.id, req.params.id);
    res.status(204).end();
  });

  app.use((error, _req, res, _next) => {
    if (res.headersSent) return;
    if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
    if (error.type === 'entity.too.large') return res.status(413).json({ error: 'The encrypted upload exceeds the server limit.' });
    if (error instanceof SyntaxError && Object.hasOwn(error, 'body')) return res.status(400).json({ error: 'Invalid JSON request.' });
    console.error('Request failed:', error.message);
    res.status(500).json({ error: 'The server could not complete the request.' });
  });

  const cleanupTimer = setInterval(() => {
    try {
      cleanup();
    } catch (error) {
      console.error('Scheduled cleanup failed:', error.message);
    }
  }, 60 * 60 * 1000);
  cleanupTimer.unref();
  app.locals.db = db;
  app.locals.mediaDir = mediaDir;
  app.locals.cleanup = cleanup;
  app.locals.close = () => {
    clearInterval(cleanupTimer);
    db.close();
  };
  app.locals.dataDir = dataDir;
  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const app = createApp();
  const server = app.listen(port, '0.0.0.0', () => console.log(`Annonimity listening on port ${port}`));
  const shutdown = () => {
    server.close(() => {
      app.locals.close();
      process.exit(0);
    });
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

module.exports = { createApp };
