const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const db = require('./db');
const { seed } = require('./seed');

const app = express();
const PORT = process.env.PORT || 3000;

seed();

// Security headers via helmet:
//  - CSP allows Leaflet (unpkg.com) for the SPA's map and blocks framing the app.
//  - sandbox-style headers prevent uploaded files from ever executing in our origin.
app.options('*', (req, res) => { res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS'); res.sendStatus(204); });

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        // Leaflet + the SPA itself are the only script sources; inline handlers
        // and eval are refused so a stored-XSS payload can't run.
        'script-src': ["'self'", 'https://unpkg.com'],
        // Critical: 'unsafe-inline' is intentionally NOT present for style-src-attr
        // defaults; allow style attributes only where the SPA injects them.
        'style-src': ["'self'", 'https://unpkg.com', 'https://fonts.googleapis.com'],
        'font-src': ["'self'", 'https://fonts.gstatic.com', 'data:'],
        'img-src': ["'self'", 'data:', 'blob:', 'https://unpkg.com', 'https://*.basemaps.cartocdn.com', 'https://*.tile.openstreetmap.org'],
        'connect-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'frame-ancestors': ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);
app.disable('x-powered-by');

// ---- CSRF mitigation: enforce a same-origin check on any state-changing request.
// Requests without an Origin/Referer header (e.g. curl) are allowed through; any
// Origin/Referer that does not match the app's own origin is rejected with 403.
const ALLOWED_ORIGINS = new Set(['http://localhost:3000']);
if (process.env.APP_ORIGIN) ALLOWED_ORIGINS.add(String(process.env.APP_ORIGIN).replace(/\/+$/, ''));
function originAllowed(rawOrigin) {
  try {
    return ALLOWED_ORIGINS.has(new URL(String(rawOrigin)).origin);
  } catch { return false; }
}
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  if (origin && String(origin).trim() !== '' && !originAllowed(origin)) {
    return res.status(403).json({ error: 'Cross-origin request blocked.' });
  }
  if (referer && String(referer).trim() !== '' && !originAllowed(referer)) {
    return res.status(403).json({ error: 'Cross-origin request blocked.' });
  }
  next();
});

app.use(express.json());
// No-cache for static assets: theme/CSS changes must reach the browser
// immediately (versioned ?v= is a belt-and-braces backup).
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, setHeaders: (res) => res.setHeader('Cache-Control', 'no-store') }));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

const SESSION_SECRET = (() => {
  // Hard block in production: run with a real secret or refuse to boot.
  // 'dev-secret-change-me' is HMAC'd into every session cookie — shipping a
  // known public value lets an attacker forge sessions for any account.
  const configured = process.env.SESSION_SECRET;
  if (process.env.NODE_ENV === 'production' && (!configured || configured === 'dev-secret-change-me' || configured === 'dev-secret-change-me-v2')) {
    throw new Error('SESSION_SECRET must be set to a strong unique value in production (and not the dev placeholder). Refusing to start with a forgeable session secret.');
  }
  return configured || 'dev-secret-change-me';
})();
const sessions = new Map();

// Brute-force guard for authentication endpoints. A session cookie is only as
// strong as the password behind it, so signup/login get a strict per-IP limit:
// 20 requests per 15-minute window. This blocks mass account-creation and
// password-spraying without hurting normal flow (nobody signs up 20x/min).
// express-rate-limit v8: 'max' was removed — 'limit' is the option name.
// The error body is deliberately generic (same for both routes) so attackers
// cannot probe which endpoint is gated.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20, // max 20 requests / window / IP
  standardHeaders: 'draft-7', // Retry-After + standard X-RateLimit-* headers
  legacyHeaders: false, // drop the legacy non-standard X- headers
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
});

// Social actions (follows, reactions, shares, saves, comment edits, events).
// Generous per-IP budget — real surges are small; this only stops scripted
// bulk writes (mass-follow bots, reaction spam). authLimiter stays on
// signup/login where the bar is deliberately stricter.
const socialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 120, // max 120 mutation requests / window / IP
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again shortly.' },
});

function sign(data) {
  return data + '.' + crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
}
function setSession(res, userId) {
  const token = crypto.randomBytes(24).toString('hex');
  // Store an object so getUserId's session-TTL check (sess.expiresAt) and the
  // userId read (sess.userId) work. Previously the raw id was stored and every
  // authenticated request resolved to "anonymous".
  sessions.set(token, { userId, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  res.setHeader('Set-Cookie', `sid=${sign(token)}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax`);
}
function clearSession(res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
}
function getUserId(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const [payload, sig] = m[1].split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  // Constant-time comparison — never use plain !== on HMACs (timing oracle).
  try {
    const a = Buffer.from(String(sig || ''), 'utf8');
    const b = Buffer.from(expected, 'utf8');
    const len = Math.min(a.length, b.length);
    if (a.length !== b.length || !crypto.timingSafeEqual(a.subarray(0, len), b.subarray(0, len))) return null;
  } catch {
    return null;
  }
  const sess = sessions.get(payload);
  if (!sess) return null;
  // Session TTL: 7 days, matching the cookie Max-Age.
  if (sess.expiresAt && Date.now() > sess.expiresAt) {
    sessions.delete(payload);
    return null;
  }
  return sess.userId;
}

function now() { return new Date().toISOString(); }

// ---- Settings / preferences helpers ---------------------------------------
const THEMES = new Set(['', 'light', 'dark', 'high-contrast']);
const NOTIFY_PREF_KEYS = ['likes', 'comments', 'messages', 'applications'];
const MAX_LOCATION_LENGTH = 200;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isPlausibleEmail(value) {
  return typeof value === 'string' && value.length <= 254 && EMAIL_RE.test(value);
}

// Accepts true/false, 0/1, '0'/'1', 'true'/'false'; returns null on anything else.
function coerceBool(value) {
  if (typeof value === 'boolean') return value;
  if (value === 0 || value === 1) return value === 1;
  if (value === '0' || value === '1') return value === '1';
  if (typeof value === 'string' && (value.toLowerCase() === 'true' || value.toLowerCase() === 'false')) return value.toLowerCase() === 'true';
  return null;
}

// Canned default flags so fresh accounts / unparseable rows still return the
// full shape the UI expects.
function defaultNotifyPrefs() {
  return { likes: false, comments: false, messages: false, applications: false };
}

function parseNotifyPrefs(raw) {
  const out = defaultNotifyPrefs();
  let obj;
  try { obj = JSON.parse(raw || '{}'); } catch { obj = {}; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) obj = {};
  for (const key of NOTIFY_PREF_KEYS) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) out[key] = !!obj[key];
  }
  return out;
}

// Accepts an object (or a JSON string) with whitelisted keys only. Unknown
// keys are rejected — we never silently persist fields we do not understand.
// `base` is the user's current prefs; unsubmitted keys are preserved so a
// partial update like { messages: true } never wipes likes/comments/applications.
// Returns { json } on success or { error } on failure.
function validateNotifyPrefsInput(value, base) {
  let obj = value;
  if (typeof value === 'string') {
    try { obj = JSON.parse(value); } catch { return { error: 'notifyPrefs must be a JSON object.' }; }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { error: 'notifyPrefs must be an object.' };
  const unknown = Object.keys(obj).filter((k) => !NOTIFY_PREF_KEYS.includes(k));
  if (unknown.length) return { error: 'Unknown notifyPrefs key(s): ' + unknown.join(', ') + '.' };
  const out = base && typeof base === 'object' && !Array.isArray(base) ? { ...defaultNotifyPrefs(), ...base } : defaultNotifyPrefs();
  for (const key of NOTIFY_PREF_KEYS) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) out[key] = !!obj[key];
  }
  return { json: JSON.stringify(out) };
}

function publicUser(u) {
  // email/notifyPrefs/theme are deliberately NOT included here — PII and
  // private preferences are only returned to the account owner via selfUser()
  // (used by /api/me, login/signup responses, PATCH profile, and settings).
  return {
    id: u.id, name: u.name, role: u.role, bio: u.bio, photo: u.photo,
    skills: (u.skills || '').split(',').map((s) => s.trim()).filter(Boolean),
    location: u.location || '',
    private: !!u.privateProfile,
    createdAt: u.createdAt,
  };
}

// Owner-only view: publicUser plus the fields the profile/settings UI needs.
function selfUser(u) {
  return {
    ...publicUser(u),
    email: u.email || '',
    theme: THEMES.has(u.theme) ? u.theme : '',
    notifyPrefs: parseNotifyPrefs(u.notifyPrefs),
  };
}

// Privacy-aware profile view: a private-profile user is reduced to
// { id, name, photo, role, private: true } unless the viewer is the owner.
function profileForViewer(target, viewerId) {
  const isOwner = viewerId != null && Number(viewerId) === Number(target.id);
  if (!isOwner && target.privateProfile) {
    return { id: target.id, name: target.name, photo: target.photo || '', role: target.role, private: true };
  }
  return publicUser(target);
}

// ---- Social feed helpers ---------------------------------------------------
// The same post serializer feeds every list endpoint so the post JSON contract
// is identical across /api/posts, /api/posts/:id, /api/users/:id,
// /api/my/saved and /api/tags/:tag. `reactionsMap` and `originalsMap` are
// batched lookups produced by reactionSummaries()/sharedOriginals().
function serializePost(row, reactionsMap, originalsMap) {
  let sharedFrom = null;
  if (row.shareOfId) {
    const o = originalsMap && originalsMap.get(row.shareOfId);
    if (o) sharedFrom = { id: o.id, body: o.body, author: { id: o.authorId, name: o.authorName, photo: o.authorPhoto } };
  }
  return {
    id: row.id, body: row.body, image: row.image, type: row.type, createdAt: row.createdAt,
    author: { id: row.authorId, name: row.authorName, photo: row.authorPhoto },
    likeCount: row.likeCount, commentCount: row.commentCount, likedByMe: !!row.likedByMe,
    reactions: (reactionsMap && reactionsMap.get(row.id)) || [],
    savedByMe: !!row.savedByMe,
    sharesCount: row.sharesCount || 0,
    sharedFrom,
  };
}

// Aggregated reaction tallies for a set of posts in ONE query (avoids an N+1
// per post). Returns a Map of postId -> [{ emoji, count, active }] ordered by
// count desc (ties broken by emoji so the output is deterministic).
function reactionSummaries(postIds, viewerId) {
  const out = new Map();
  if (!postIds.length) return out;
  const marks = postIds.map(() => '?').join(',');
  const rows = db.prepare(`
    SELECT postId, emoji, COUNT(*) AS cnt,
           SUM(CASE WHEN userId = ? THEN 1 ELSE 0 END) AS mine
    FROM post_reactions
    WHERE postId IN (${marks})
    GROUP BY postId, emoji
    ORDER BY cnt DESC, emoji ASC
  `).all(viewerId, ...postIds);
  for (const r of rows) {
    const arr = out.get(r.postId) || [];
    arr.push({ emoji: r.emoji, count: r.cnt, active: (r.mine || 0) > 0 });
    out.set(r.postId, arr);
  }
  return out;
}

// Resolves the "sharedFrom" originals for a set of feed rows in one query.
function sharedOriginals(rows) {
  const out = new Map();
  const ids = [...new Set(rows.map((r) => r.shareOfId).filter(Boolean))];
  if (!ids.length) return out;
  const marks = ids.map(() => '?').join(',');
  const originals = db.prepare(`
    SELECT p.id, p.body, u.id AS authorId, u.name AS authorName, u.photo AS authorPhoto
    FROM posts p JOIN users u ON u.id = p.authorId
    WHERE p.id IN (${marks})
  `).all(...ids);
  for (const o of originals) out.set(o.id, o);
  return out;
}

// Shared feed loader — every feed/list endpoint routes through this so the
// post JSON shape is identical. `me` is bound twice (likedByMe + savedByMe in
// POST_SELECT) before any endpoint-supplied WHERE arguments.
function loadPosts(me, whereSql, whereArgs, orderSql) {
  const rows = db.prepare(POST_SELECT + (whereSql ? ' ' + whereSql : '') + ' ' + (orderSql || 'ORDER BY p.createdAt DESC')).all(me, me, ...(whereArgs || []));
  const reactions = reactionSummaries(rows.map((r) => r.id), me);
  const originals = sharedOriginals(rows);
  return rows.map((r) => serializePost(r, reactions, originals));
}

// Comment row -> JSON (used by list, create, edit routes).
function serializeComment(c) {
  return { id: c.id, body: c.body, createdAt: c.createdAt, parentId: c.parentId || null, author: { id: c.authorId, name: c.authorName, photo: c.authorPhoto } };
}

// Follow stats for a user profile (both directions of the follows edge).
function followCounts(userId) {
  return {
    followersCount: db.prepare('SELECT COUNT(*) AS c FROM follows WHERE followingId = ?').get(userId).c,
    followingCount: db.prepare('SELECT COUNT(*) AS c FROM follows WHERE followerId = ?').get(userId).c,
  };
}
function isFollowing(followerId, followingId) {
  if (!followerId || !followingId) return false;
  return !!db.prepare('SELECT 1 FROM follows WHERE followerId = ? AND followingId = ?').get(followerId, followingId);
}

// Pulls #Hashtags out of post text into a comma-separated list (deduped
// case-insensitively, original casing preserved): "#Tech,#jobs".
function extractHashtags(text) {
  const seen = new Set();
  const out = [];
  const re = /#([A-Za-z0-9][A-Za-z0-9_]*)/g;
  let m;
  while ((m = re.exec(String(text || '')))) {
    const key = m[1].toLowerCase();
    if (!seen.has(key)) { seen.add(key); out.push('#' + m[1]); }
  }
  return out.join(',');
}

// ---- Events helpers --------------------------------------------------------
const EVENT_SELECT = `
  SELECT e.*, u.name AS hostName, u.photo AS hostPhoto,
         (SELECT COUNT(*) FROM event_participants ep WHERE ep.eventId = e.id) AS attendeeCount,
         EXISTS(SELECT 1 FROM event_participants ep2 WHERE ep2.eventId = e.id AND ep2.userId = ?) AS attending
  FROM events e JOIN users u ON u.id = e.hostId
`;
function serializeEvent(row) {
  return {
    id: row.id, title: row.title, description: row.description || '', location: row.location || '',
    startAt: row.startAt, createdAt: row.createdAt,
    host: { id: row.hostId, name: row.hostName, photo: row.hostPhoto || '' },
    attending: !!row.attending,
    attendeeCount: row.attendeeCount,
  };
}

function serializeJob(row) {
  return {
    id: row.id, title: row.title, description: row.description, category: row.category,
    wage: row.wage, lat: row.lat, lng: row.lng, locationText: row.locationText,
    filled: !!row.filled, createdAt: row.createdAt,
    giver: { id: row.giverId, name: row.giverName, photo: row.giverPhoto },
    applicantCount: row.applicantCount, myStatus: row.myStatus || null,
  };
}

function notify(userId, actorId, type, entityId, text, link) {
  if (!userId || userId === actorId) return;
  db.prepare('INSERT INTO notifications (userId, actorId, type, entityId, text, link, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)').run(userId, actorId, type, entityId || null, text, link || '', now());
}

function getOrCreateConversation(userId, otherId) {
  const a = Math.min(userId, otherId);
  const b = Math.max(userId, otherId);
  const existing = db.prepare('SELECT id FROM conversations WHERE userA = ? AND userB = ?').get(a, b);
  if (existing) return existing.id;
  const info = db.prepare('INSERT INTO conversations (userA, userB, createdAt) VALUES (?, ?, ?)').run(a, b, now());
  return info.lastInsertRowid;
}

function isBlocked(by, of) {
  // Blocks are directional: (blockerId, blockedId) rows store who blocked whom.
  // A blocking B must NOT be treated as B blocking A (that alternated min/max
  // "both ways" bug let a blocked user keep messaging the blocker).
  return !!db.prepare('SELECT id FROM blocks WHERE blockerId = ? AND blockedId = ?').get(by, of);
}

// Deletes every row that references a user in one transaction. The schema's
// FKs are all ON DELETE CASCADE, but the shipped data/announce.db may
// predate those definitions — explicit deletes make account deletion correct
// on every copy of the DB.
function deleteUserData(userId) {
  db.exec('BEGIN');
  try {
    // Conversations involving the user, and their messages (spec: delete
    // conversations + their messages).
    const convos = db.prepare('SELECT id FROM conversations WHERE userA = ? OR userB = ?').all(userId, userId);
    for (const c of convos) {
      db.prepare('DELETE FROM messages WHERE conversationId = ?').run(c.id);
      db.prepare('DELETE FROM conversations WHERE id = ?').run(c.id);
    }
    // Messages the user sent (defensive; normally covered above) + reactions.
    db.prepare('DELETE FROM messages WHERE senderId = ?').run(userId);
    db.prepare('DELETE FROM message_reactions WHERE userId = ?').run(userId);
    // Posts authored by the user + their likes/comments.
    const posts = db.prepare('SELECT id FROM posts WHERE authorId = ?').all(userId);
    for (const p of posts) {
      db.prepare('DELETE FROM likes WHERE postId = ?').run(p.id);
      db.prepare('DELETE FROM comments WHERE postId = ?').run(p.id);
    }
    db.prepare('DELETE FROM posts WHERE authorId = ?').run(userId);
    // Likes/comments the user made on other people's posts.
    db.prepare('DELETE FROM likes WHERE userId = ?').run(userId);
    db.prepare('DELETE FROM comments WHERE authorId = ?').run(userId);
    // Social tables that shipped after the original schema (their FKs cascade,
    // but explicit deletes keep copies of the DB that predate the FKs correct).
    db.prepare('DELETE FROM follows WHERE followerId = ? OR followingId = ?').run(userId, userId);
    db.prepare('DELETE FROM post_reactions WHERE userId = ?').run(userId);
    db.prepare('DELETE FROM saved_posts WHERE userId = ?').run(userId);
    db.prepare('DELETE FROM event_participants WHERE userId = ?').run(userId);
    db.prepare('DELETE FROM events WHERE hostId = ?').run(userId);
    // Shares whose original post belonged to the user (removes dangling rows).
    db.prepare('DELETE FROM posts WHERE shareOfId IN (SELECT id FROM posts WHERE authorId = ?)').run(userId);
    // Jobs the user posted + their applications.
    const jobs = db.prepare('SELECT id FROM jobs WHERE giverId = ?').all(userId);
    for (const j of jobs) db.prepare('DELETE FROM applications WHERE jobId = ?').run(j.id);
    db.prepare('DELETE FROM jobs WHERE giverId = ?').run(userId);
    // Applications the user submitted.
    db.prepare('DELETE FROM applications WHERE seekerId = ?').run(userId);
    // Notifications addressed to or originating from the user.
    db.prepare('DELETE FROM notifications WHERE userId = ? OR actorId = ?').run(userId, userId);
    // Block relationships.
    db.prepare('DELETE FROM blocks WHERE blockerId = ? OR blockedId = ?').run(userId, userId);
    // Finally the user row itself — the whole deletion is one atomic transaction.
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // SECURITY: extension must be derived from the validated MIME type, NOT
    // from client-controlled file.originalname. originalname-based extensions
    // allowed .html/.svg uploads that became stored-XSS sinks.
    const ext = ({ 'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif', 'image/webp': '.webp', 'image/avif': '.avif' })[file.mimetype] || file.mimetype === 'image/svg+xml' ? fallbackExt(file) : (file.mimetypeMap && file.mimetypeMap[file.mimetype]) || '.jpg';
    cb(null, Date.now() + '-' + crypto.randomBytes(6).toString('hex') + ext);
  },
});
// Whitelist: raster image formats only. SVG/HTML are REJECTED (XSS vectors).
const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif']);
function fallbackExt(file) { return '.bin'; }
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME.has(file.mimetype)) return cb(null, true);
    cb(new Error('Unsupported file type. Only JPG, PNG, GIF, WebP, and AVIF images are allowed.'));
  },
});

// ---- Auth ----
app.post('/api/signup', authLimiter, async (req, res) => {
  const { name, email, password, skills, location } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const locationVal = String(location || '').trim();
  if (locationVal.length > MAX_LOCATION_LENGTH) return res.status(400).json({ error: 'Location must be 200 characters or fewer.' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(String(email).toLowerCase());
  if (existing) return res.status(400).json({ error: 'An account with that email already exists.' });
  const hash = bcrypt.hashSync(String(password), 10);
  const skillsStr = Array.isArray(skills) ? skills.map((s) => s.trim()).filter(Boolean).join(', ') : String(skills || '');
  const res2 = db.prepare('INSERT INTO users (name, email, password, role, bio, photo, skills, location, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(String(name), String(email).toLowerCase(), hash, 'member', '', '', skillsStr, locationVal, now());
  setSession(res, res2.lastInsertRowid);
  db.prepare('UPDATE users SET online = 1, lastSeen = ? WHERE id = ?').run(now(), res2.lastInsertRowid);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(res2.lastInsertRowid);
  res.json({ user: selfUser(user) });
});

app.post('/api/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ''), user.password)) return res.status(401).json({ error: 'Invalid email or password.' });
  setSession(res, user.id);
  db.prepare('UPDATE users SET online = 1, lastSeen = ? WHERE id = ?').run(now(), user.id);
  res.json({ user: selfUser(user) });
});

app.post('/api/logout', (req, res) => {
  const me = getUserId(req);
  if (me) db.prepare('UPDATE users SET online = 0, lastSeen = ? WHERE id = ?').run(now(), me);
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)sid=([^;]+)/);
  if (m) sessions.delete(m[1].split('.')[0]);
  clearSession(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const id = getUserId(req);
  if (!id) return res.json({ user: null });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.json({ user: null });
  const counts = followCounts(id);
  res.json({ user: { ...selfUser(user), followersCount: counts.followersCount, followingCount: counts.followingCount } });
});

// ---- Settings ----
app.get('/api/me/settings', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  if (!user) return res.status(401).json({ error: 'Please sign in.' });
  res.json({
    theme: THEMES.has(user.theme) ? user.theme : '',
    notifyPrefs: parseNotifyPrefs(user.notifyPrefs),
    profile: {
      name: user.name,
      email: user.email,
      bio: user.bio || '',
      skills: publicUser(user).skills,
      location: user.location || '',
    },
  });
});

app.post('/api/me/settings', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  if (!user) return res.status(401).json({ error: 'Please sign in.' });
  const { theme, notifyPrefs, privateProfile } = req.body || {};
  const sets = [];
  const args = [];
  if (theme !== undefined) {
    if (!THEMES.has(theme)) return res.status(400).json({ error: 'Invalid theme. Use "", "light", "dark", or "high-contrast".' });
    sets.push('theme = ?');
    args.push(theme);
  }
  if (notifyPrefs !== undefined) {
    const parsed = validateNotifyPrefsInput(notifyPrefs, parseNotifyPrefs(user.notifyPrefs));
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    sets.push('notifyPrefs = ?');
    args.push(parsed.json);
  }
  if (privateProfile !== undefined) {
    const v = coerceBool(privateProfile);
    if (v === null) return res.status(400).json({ error: 'privateProfile must be true or false.' });
    sets.push('privateProfile = ?');
    args.push(v ? 1 : 0);
  }
  if (sets.length) {
    args.push(me);
    db.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?').run(...args);
  }
  res.json({ ok: true });
});

// Canonical change-password route (PATCH /api/users/:id accepts the same body).
app.post('/api/me/password', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  if (!user) return res.status(401).json({ error: 'Please sign in.' });
  const { currentPassword, password } = req.body || {};
  if (!currentPassword || typeof currentPassword !== 'string' || !String(currentPassword)) {
    return res.status(400).json({ error: 'Current password is required.' });
  }
  if (!bcrypt.compareSync(String(currentPassword), user.password)) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }
  if (!password || String(password).length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync(String(password), 10), me);
  res.json({ ok: true });
});

app.delete('/api/me', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  if (!user) return res.status(401).json({ error: 'Please sign in.' });
  deleteUserData(me);
  // Drop every in-memory session that belonged to the deleted account.
  for (const [token, sess] of [...sessions.entries()]) {
    if (sess && sess.userId === me) sessions.delete(token);
  }
  clearSession(res);
  res.json({ ok: true });
});

app.post('/api/heartbeat', (req, res) => {
  const me = getUserId(req);
  if (me) db.prepare('UPDATE users SET online = 1, lastSeen = ? WHERE id = ?').run(now(), me);
  res.json({ ok: true });
});

// ---- Posts ----
const POST_SELECT = `
  SELECT p.*, u.name AS authorName, u.photo AS authorPhoto,
         (SELECT COUNT(*) FROM likes l WHERE l.postId = p.id) AS likeCount,
         (SELECT COUNT(*) FROM comments c WHERE c.postId = p.id) AS commentCount,
         EXISTS(SELECT 1 FROM likes l2 WHERE l2.postId = p.id AND l2.userId = ?) AS likedByMe,
         EXISTS(SELECT 1 FROM saved_posts sp WHERE sp.postId = p.id AND sp.userId = ?) AS savedByMe,
         (SELECT COUNT(*) FROM posts pivot WHERE pivot.shareOfId = p.id) AS sharesCount
  FROM posts p JOIN users u ON u.id = p.authorId
`;
app.get('/api/posts', (req, res) => {
  const me = getUserId(req);
  if (req.query.feed === 'following') {
    // Authors I follow plus my own posts.
    return res.json({ posts: loadPosts(me, 'WHERE p.authorId = ? OR EXISTS (SELECT 1 FROM follows f WHERE f.followerId = ? AND f.followingId = p.authorId)', [me, me], 'ORDER BY p.createdAt DESC') });
  }
  res.json({ posts: loadPosts(me) });
});
app.get('/api/posts/:id', (req, res) => {
  const me = getUserId(req);
  const posts = loadPosts(me, 'WHERE p.id = ?', [Number(req.params.id)]);
  if (!posts.length) return res.status(404).json({ error: 'Post not found.' });
  res.json({ post: posts[0] });
});

app.post('/api/posts', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in to post.' });
  const { body, type } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Post cannot be empty.' });
  const t = ['general', 'offer', 'advertisement'].includes(type) ? type : 'general';
  const hashtags = extractHashtags(body);
  const info = db.prepare('INSERT INTO posts (authorId, body, image, type, hashtags, createdAt) VALUES (?, ?, ?, ?, ?, ?)').run(me, String(body).trim(), '', t, hashtags, now());
  res.json({ id: info.lastInsertRowid });
});

app.post('/api/posts/:id/image', upload.single('image'), (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.authorId !== me) return res.status(403).json({ error: 'Not your post.' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  db.prepare('UPDATE posts SET image = ? WHERE id = ?').run('/uploads/' + req.file.filename, post.id);
  res.json({ image: '/uploads/' + req.file.filename });
});

app.put('/api/posts/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.authorId !== me) return res.status(403).json({ error: 'Not your post.' });
  const { body, type } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Post cannot be empty.' });
  const t = ['general', 'offer', 'advertisement'].includes(type) ? type : post.type;
  db.prepare('UPDATE posts SET body = ?, type = ?, hashtags = ? WHERE id = ?').run(String(body).trim(), t, extractHashtags(body), post.id);
  res.json({ ok: true });
});

app.delete('/api/posts/:id/image', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.authorId !== me) return res.status(403).json({ error: 'Not your post.' });
  db.prepare('UPDATE posts SET image = ? WHERE id = ?').run('', post.id);
  res.json({ ok: true });
});

app.delete('/api/posts/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.authorId !== me) return res.status(403).json({ error: 'Not your post.' });
  db.prepare('DELETE FROM posts WHERE id = ?').run(post.id);
  res.json({ ok: true });
});

// ---- Likes ----
app.post('/api/posts/:id/like', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT id, authorId FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const info = db.prepare('INSERT OR IGNORE INTO likes (postId, userId, createdAt) VALUES (?, ?, ?)').run(post.id, me, now());
  if (info.changes > 0) { const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me); notify(post.authorId, me, 'like', post.id, (actor ? actor.name : 'Someone') + ' liked your post.', '/feed'); }
  const count = db.prepare('SELECT COUNT(*) AS c FROM likes WHERE postId = ?').get(post.id).c;
  res.json({ liked: info.changes > 0, likeCount: count });
});
app.post('/api/posts/:id/unlike', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  db.prepare('DELETE FROM likes WHERE postId = ? AND userId = ?').run(Number(req.params.id), me);
  const count = db.prepare('SELECT COUNT(*) AS c FROM likes WHERE postId = ?').get(Number(req.params.id)).c;
  res.json({ liked: false, likeCount: count });
});

// ---- Reactions (the new path; existing like endpoints remain for back-compat) ----
app.post('/api/posts/:id/react', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const postId = Number(req.params.id);
  const post = db.prepare('SELECT id, authorId FROM posts WHERE id = ?').get(postId);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const { emoji, active } = req.body || {};
  if (!emoji || typeof emoji !== 'string' || !emoji.trim() || emoji.length > 32) return res.status(400).json({ error: 'A valid emoji is required.' });
  let activeState = coerceBool(active);
  if (activeState === null) {
    if (active === undefined || active === null) {
      // Unspecified active -> toggle the reaction.
      activeState = !db.prepare('SELECT 1 FROM post_reactions WHERE postId = ? AND userId = ? AND emoji = ?').get(postId, me, emoji);
    } else {
      return res.status(400).json({ error: 'active must be true or false.' });
    }
  }
  if (activeState) {
    const info = db.prepare('INSERT OR IGNORE INTO post_reactions (postId, userId, emoji, createdAt) VALUES (?, ?, ?, ?)').run(postId, me, emoji, now());
    if (info.changes > 0) {
      const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
      notify(post.authorId, me, 'reaction', postId, (actor ? actor.name : 'Someone') + ' reacted to your post.', '/feed');
    }
  } else {
    db.prepare('DELETE FROM post_reactions WHERE postId = ? AND userId = ? AND emoji = ?').run(postId, me, emoji);
  }
  res.json({ reactions: reactionSummaries([postId], me).get(postId) || [] });
});

// ---- Shares ----
app.post('/api/posts/:id/share', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  // New type='shared' row points back at the original; the body is copied but
  // the client renders the original card from sharedFrom. Hashtags stay empty
  // on the share row so shared posts don't flood tag searches.
  const info = db.prepare('INSERT INTO posts (authorId, body, image, type, shareOfId, hashtags, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)').run(me, post.body, '', 'shared', post.id, '', now());
  const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
  notify(post.authorId, me, 'share', post.id, (actor ? actor.name : 'Someone') + ' shared your post.', '/feed');
  res.json({ id: info.lastInsertRowid });
});

// ---- Saved posts ----
app.post('/api/posts/:id/save', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  db.prepare('INSERT OR IGNORE INTO saved_posts (postId, userId, createdAt) VALUES (?, ?, ?)').run(post.id, me, now());
  res.json({ saved: true });
});
app.delete('/api/posts/:id/save', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  db.prepare('DELETE FROM saved_posts WHERE postId = ? AND userId = ?').run(Number(req.params.id), me);
  res.json({ saved: false });
});

// ---- My saved posts ----
app.get('/api/my/saved', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  res.json({ posts: loadPosts(me, 'JOIN saved_posts sp ON sp.postId = p.id WHERE sp.userId = ?', [me], 'ORDER BY sp.createdAt DESC') });
});

// ---- Comments ----
app.get('/api/posts/:id/comments', (req, res) => {
  const rows = db.prepare('SELECT c.*, u.name AS authorName, u.photo AS authorPhoto FROM comments c JOIN users u ON u.id = c.authorId WHERE c.postId = ? ORDER BY c.createdAt ASC').all(Number(req.params.id));
  res.json({ comments: rows.map(serializeComment) });
});
app.post('/api/posts/:id/comments', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const { body, parentId } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Comment cannot be empty.' });
  const post = db.prepare('SELECT id, authorId FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  let parent = null;
  if (parentId !== undefined && parentId !== null && String(parentId).trim() !== '') {
    parent = db.prepare('SELECT * FROM comments WHERE id = ? AND postId = ?').get(Number(parentId), post.id);
    if (!parent) return res.status(400).json({ error: 'Parent comment not found on this post.' });
  }
  const info = db.prepare('INSERT INTO comments (postId, authorId, body, parentId, createdAt) VALUES (?, ?, ?, ?, ?)').run(post.id, me, String(body).trim(), parent ? parent.id : null, now());
  const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
  const actorName = actor ? actor.name : 'Someone';
  notify(post.authorId, me, 'comment', post.id, actorName + ' commented on your post.', '/feed');
  // Reply notifications go to the parent comment's author (only when the reply
  // targets someone other than the post author who was just notified above).
  if (parent && parent.authorId !== post.authorId) {
    notify(parent.authorId, me, 'comment_reply', post.id, actorName + ' replied to your comment.', '/feed');
  }
  const comment = db.prepare('SELECT c.*, u.name AS authorName, u.photo AS authorPhoto FROM comments c JOIN users u ON u.id = c.authorId WHERE c.id = ?').get(info.lastInsertRowid);
  res.json({ comment: serializeComment(comment) });
});

// Edit comment — owner only.
app.patch('/api/comments/:id', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const comment = db.prepare('SELECT * FROM comments WHERE id = ?').get(Number(req.params.id));
  if (!comment) return res.status(404).json({ error: 'Comment not found.' });
  if (comment.authorId !== me) return res.status(403).json({ error: 'Not your comment.' });
  const { body } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Comment cannot be empty.' });
  db.prepare('UPDATE comments SET body = ? WHERE id = ?').run(String(body).trim(), comment.id);
  const updated = db.prepare('SELECT c.*, u.name AS authorName, u.photo AS authorPhoto FROM comments c JOIN users u ON u.id = c.authorId WHERE c.id = ?').get(comment.id);
  res.json({ comment: serializeComment(updated) });
});

// Delete comment — owner of the comment, the post's author, or an 'owner' role.
app.delete('/api/comments/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const comment = db.prepare('SELECT * FROM comments WHERE id = ?').get(Number(req.params.id));
  if (!comment) return res.status(404).json({ error: 'Comment not found.' });
  const post = db.prepare('SELECT authorId FROM posts WHERE id = ?').get(comment.postId);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const viewer = db.prepare('SELECT role FROM users WHERE id = ?').get(me);
  const allowed = comment.authorId === me || post.authorId === me || (viewer && viewer.role === 'owner');
  if (!allowed) return res.status(403).json({ error: 'You are not allowed to delete this comment.' });
  db.prepare('DELETE FROM comments WHERE id = ?').run(comment.id);
  res.json({ ok: true });
});

// ---- Search ----
app.get('/api/search', (req, res) => {
  const q = String(req.query.q || '').trim(); const type = String(req.query.type || 'people');
  if (!q) return res.json({ results: [] });
  const like = '%' + q.replace(/[%_]/g, (c) => '\\' + c) + '%';
  if (type === 'jobs') {
    const rows = db.prepare(`SELECT j.*, u.name AS giverName, u.photo AS giverPhoto, (SELECT COUNT(*) FROM applications a WHERE a.jobId = j.id) AS applicantCount, NULL AS myStatus FROM jobs j JOIN users u ON u.id = j.giverId WHERE j.title LIKE ? ESCAPE '\\' OR j.description LIKE ? ESCAPE '\\' OR j.category LIKE ? ESCAPE '\\' OR j.locationText LIKE ? ESCAPE '\\' ORDER BY j.createdAt DESC`).all(like, like, like, like);
    return res.json({ results: rows.map(serializeJob) });
  }
  const roleFilter = type === 'business' ? " AND role = 'owner'" : (type === 'people' ? " AND role = 'member'" : '');
  const rows = db.prepare(`SELECT * FROM users WHERE (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR bio LIKE ? ESCAPE '\\' OR skills LIKE ? ESCAPE '\\')${roleFilter} ORDER BY name`).all(like, like, like, like);
  const me = getUserId(req);
  // Private profiles still match the search, but only expose the reduced shape.
  res.json({ results: rows.map((u) => profileForViewer(u, me)) });
});

// ---- Hashtags (tag search) ----
app.get('/api/tags/:tag', (req, res) => {
  const me = getUserId(req);
  const tag = String(req.params.tag || '').trim().toLowerCase().replace(/^#/, '');
  if (!tag) return res.json({ posts: [] });
  const like = '%' + tag.replace(/[%_]/g, (c) => '\\' + c) + '%';
  res.json({ posts: loadPosts(me, "WHERE LOWER(p.hashtags) LIKE ? ESCAPE '\\'", [like], 'ORDER BY p.createdAt DESC') });
});

// ---- Profiles ----
// Registered BEFORE /api/users/:id so "suggestions" is not captured as :id.
app.get('/api/users/suggestions', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 8, 1), 50);
  const my = db.prepare('SELECT id, skills FROM users WHERE id = ?').get(me);
  if (!my) return res.status(401).json({ error: 'Please sign in.' });
  const mySkills = (my.skills || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  // People I am NOT already following (self is excluded too). Private profiles
  // are skipped so private bio/skills are never leaked via suggestions.
  const rows = db.prepare(`
    SELECT u.*,
           (SELECT COUNT(*) FROM follows f2 WHERE f2.followingId = u.id) AS followersCount,
           EXISTS(SELECT 1 FROM follows f4 WHERE f4.followerId = ? AND f4.followingId = u.id) AS followedByMe
    FROM users u
    WHERE u.id != ?
      AND u.privateProfile = 0
      AND NOT EXISTS(SELECT 1 FROM follows f1 WHERE f1.followerId = ? AND f1.followingId = u.id)
      AND NOT EXISTS(SELECT 1 FROM blocks b1 WHERE b1.blockerId = ? AND b1.blockedId = u.id)
      AND NOT EXISTS(SELECT 1 FROM blocks b2 WHERE b2.blockerId = u.id AND b2.blockedId = ?)
  `).all(me, me, me, me, me);
  const scored = rows
    .map((u) => ({
      u,
      shared: (u.skills || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean).filter((s) => mySkills.includes(s)).length,
    }))
    .sort((a, b) => b.shared - a.shared || b.u.followersCount - a.u.followersCount)
    .slice(0, limit);
  res.json({ users: scored.map(({ u }) => ({
    id: u.id, name: u.name, photo: u.photo || '', role: u.role, bio: u.bio || '',
    skills: (u.skills || '').split(',').map((s) => s.trim()).filter(Boolean),
    followersCount: u.followersCount, followedByMe: !!u.followedByMe,
  })) });
});

app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const me = getUserId(req);
  const isOwner = me !== null && Number(me) === Number(user.id);
  const counts = followCounts(user.id);
  const following = isFollowing(me, user.id);
  // Privacy: a private-profile account is only fully visible to its owner.
  if (!isOwner && user.privateProfile) {
    return res.json({
      user: { id: user.id, name: user.name, photo: user.photo || '', role: user.role, private: true },
      postCount: 0, likesReceived: 0, commentsReceived: 0, openJobs: 0, jobsDone: 0,
      posts: [],
      blocked: me ? isBlocked(user.id, me) : false,
      followersCount: counts.followersCount, followingCount: counts.followingCount, isFollowing: following,
    });
  }
  const postCount = db.prepare('SELECT COUNT(*) AS c FROM posts WHERE authorId = ?').get(user.id).c;
  const posts = loadPosts(me, 'WHERE p.authorId = ?', [user.id], 'ORDER BY p.createdAt DESC');
  const likesReceived = db.prepare('SELECT COUNT(*) AS c FROM likes l JOIN posts p ON p.id = l.postId WHERE p.authorId = ?').get(user.id).c;
  const commentsReceived = db.prepare('SELECT COUNT(*) AS c FROM comments co JOIN posts p ON p.id = co.postId WHERE p.authorId = ?').get(user.id).c;
  const openJobs = db.prepare('SELECT COUNT(*) AS c FROM jobs WHERE giverId = ? AND filled = 0').get(user.id).c;
  const jobsDone = db.prepare('SELECT COUNT(*) AS c FROM jobs WHERE giverId = ? AND filled = 1').get(user.id).c;
  const blocked = me ? isBlocked(user.id, me) : false;
  res.json({ user: publicUser(user), postCount, likesReceived, commentsReceived, openJobs, jobsDone, posts, blocked, followersCount: counts.followersCount, followingCount: counts.followingCount, isFollowing: following });
});

app.patch('/api/users/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  if (me !== Number(req.params.id)) return res.status(403).json({ error: 'Not your profile.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  if (!user) return res.status(401).json({ error: 'Please sign in.' });

  const { name, bio, skills, location, email, password, currentPassword, theme, notifyPrefs, privateProfile } = req.body || {};
  const sets = [];
  const args = [];

  // name
  if (name !== undefined) {
    const nameVal = String(name || '').trim();
    if (!nameVal) return res.status(400).json({ error: 'Name cannot be empty.' });
    sets.push('name = ?'); args.push(nameVal);
  }
  // bio
  if (bio !== undefined) { sets.push('bio = ?'); args.push(String(bio || '').trim()); }
  // skills
  if (skills !== undefined) {
    const skillsArr = Array.isArray(skills) ? skills : String(skills || '').split(',');
    sets.push('skills = ?'); args.push(skillsArr.map((s) => s.trim()).filter(Boolean).join(', '));
  }
  // location
  if (location !== undefined) {
    const locationVal = String(location || '').trim();
    if (locationVal.length > MAX_LOCATION_LENGTH) return res.status(400).json({ error: 'Location must be 200 characters or fewer.' });
    sets.push('location = ?'); args.push(locationVal);
  }
  // email — only if actually changing, plausible, and not already used by someone else.
  if (email !== undefined) {
    const emailVal = String(email || '').trim().toLowerCase();
    if (emailVal && emailVal !== user.email) {
      if (!isPlausibleEmail(emailVal)) return res.status(400).json({ error: 'Enter a valid email address.' });
      const taken = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(emailVal, me);
      if (taken) return res.status(409).json({ error: 'That email is already in use.' });
      sets.push('email = ?'); args.push(emailVal);
    }
  }
  // password — requires the current password to be verified first.
  if (password !== undefined && String(password) !== '') {
    if (!currentPassword || typeof currentPassword !== 'string' || !String(currentPassword)) {
      return res.status(400).json({ error: 'Current password is required to change your password.' });
    }
    if (!bcrypt.compareSync(String(currentPassword), user.password)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    sets.push('password = ?'); args.push(bcrypt.hashSync(String(password), 10));
  }
  // theme
  if (theme !== undefined) {
    if (!THEMES.has(theme)) return res.status(400).json({ error: 'Invalid theme. Use "", "light", "dark", or "high-contrast".' });
    sets.push('theme = ?'); args.push(theme);
  }
  // notifyPrefs
  if (notifyPrefs !== undefined) {
    const parsed = validateNotifyPrefsInput(notifyPrefs, parseNotifyPrefs(user.notifyPrefs));
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    sets.push('notifyPrefs = ?'); args.push(parsed.json);
  }
  // privateProfile
  if (privateProfile !== undefined) {
    const v = coerceBool(privateProfile);
    if (v === null) return res.status(400).json({ error: 'privateProfile must be true or false.' });
    sets.push('privateProfile = ?'); args.push(v ? 1 : 0);
  }

  if (sets.length) {
    args.push(me);
    db.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?').run(...args);
  }
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  res.json({ user: selfUser(updated) });
});
app.post('/api/users/:id/photo', upload.single('photo'), (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  if (me !== Number(req.params.id)) return res.status(403).json({ error: 'Not your profile.' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const photo = '/uploads/' + req.file.filename;
  db.prepare('UPDATE users SET photo = ? WHERE id = ?').run(photo, me);
  res.json({ photo });
});

// ---- Follows ----
app.post('/api/users/:id/follow', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const targetId = Number(req.params.id);
  if (!targetId || targetId === me) return res.status(400).json({ error: 'You cannot follow yourself.' });
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  const info = db.prepare('INSERT OR IGNORE INTO follows (followerId, followingId, createdAt) VALUES (?, ?, ?)').run(me, targetId, now());
  if (info.changes > 0) {
    const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
    notify(targetId, me, 'follow', targetId, (actor ? actor.name : 'Someone') + ' started following you.', '/users/' + targetId);
  }
  res.json({ ok: true });
});
app.delete('/api/users/:id/follow', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const targetId = Number(req.params.id);
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  db.prepare('DELETE FROM follows WHERE followerId = ? AND followingId = ?').run(me, targetId);
  res.json({ ok: true });
});

// ---- Block/Unblock ----
app.post('/api/users/:id/block', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const targetId = Number(req.params.id); if (targetId === me) return res.status(400).json({ error: 'Cannot block yourself.' });
  const a = Math.min(me, targetId), b = Math.max(me, targetId);
  db.prepare('INSERT OR IGNORE INTO blocks (blockerId, blockedId, createdAt) VALUES (?, ?, ?)').run(a, b, now());
  res.json({ ok: true });
});
app.post('/api/users/:id/unblock', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const targetId = Number(req.params.id);
  const a = Math.min(me, targetId), b = Math.max(me, targetId);
  db.prepare('DELETE FROM blocks WHERE blockerId = ? AND blockedId = ?').run(a, b);
  res.json({ ok: true });
});

// ---- Jobs ----
const JOB_SELECT = `SELECT j.*, u.name AS giverName, u.photo AS giverPhoto, (SELECT COUNT(*) FROM applications a WHERE a.jobId = j.id) AS applicantCount, (SELECT a.status FROM applications a WHERE a.jobId = j.id AND a.seekerId = ?) AS myStatus FROM jobs j JOIN users u ON u.id = j.giverId`;

app.get('/api/jobs', (req, res) => {
  const me = getUserId(req); const { q, nearby, radius, lat, lng } = req.query;
  let sql = JOB_SELECT + ' WHERE j.filled = 0'; const args = [me];
  if (q) { const like = '%' + String(q).replace(/[%_]/g, (c) => '\\' + c) + '%'; sql += " AND (j.title LIKE ? ESCAPE '\\' OR j.description LIKE ? ESCAPE '\\' OR j.category LIKE ? ESCAPE '\\' OR j.locationText LIKE ? ESCAPE '\\')"; args.push(like, like, like, like); }
  sql += ' ORDER BY j.createdAt DESC';
  let rows;
  if (nearby === '1' && lat && lng) {
    rows = db.prepare(sql).all(...args);
    const myLat = Number(lat), myLng = Number(lng), rad = Number(radius || 50);
    rows = rows.filter((r) => r.lat != null && r.lng != null && haversine(myLat, myLng, r.lat, r.lng) <= rad).sort((a, b) => haversine(myLat, myLng, a.lat, a.lng) - haversine(myLat, myLng, b.lat, b.lng));
  } else { rows = db.prepare(sql).all(...args); }
  res.json({ jobs: rows.map(serializeJob) });
});

function haversine(lat1, lng1, lat2, lng2) {
  const R = 6371; const dLat = (lat2 - lat1) * Math.PI / 180; const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

app.get('/api/jobs/map', (req, res) => {
  const { category, radius, lat, lng } = req.query;
  let sql = `SELECT j.id, j.title, j.description, j.category, j.wage, j.lat, j.lng, j.locationText, j.filled, j.createdAt, u.name AS giverName, u.photo AS giverPhoto, u.id AS giverId FROM jobs j JOIN users u ON u.id = j.giverId WHERE j.lat IS NOT NULL AND j.lng IS NOT NULL`;
  const args = [];
  if (category) { sql += ' AND j.category = ?'; args.push(category); }
  sql += ' ORDER BY j.createdAt DESC';
  let rows = db.prepare(sql).all(...args);
  if (lat && lng && radius) { const myLat = Number(lat), myLng = Number(lng), rad = Number(radius); rows = rows.filter((r) => haversine(myLat, myLng, r.lat, r.lng) <= rad); }
  res.json({ jobs: rows.map((r) => ({ id: r.id, title: r.title, description: r.description, category: r.category, wage: r.wage, lat: r.lat, lng: r.lng, locationText: r.locationText, filled: !!r.filled, createdAt: r.createdAt, giver: { id: r.giverId, name: r.giverName, photo: r.giverPhoto } })) });
});

app.get('/api/jobs/:id', (req, res) => { const me = getUserId(req); const row = db.prepare(JOB_SELECT + ' WHERE j.id = ?').get(me, Number(req.params.id)); if (!row) return res.status(404).json({ error: 'Job not found.' }); res.json({ job: serializeJob(row) }); });

app.post('/api/jobs', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in to post a job.' });
  const { title, description, category, wage, lat, lng, locationText } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'Job title is required.' });
  const info = db.prepare('INSERT INTO jobs (giverId, title, description, category, wage, lat, lng, locationText, filled, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)').run(me, String(title).trim(), String(description || '').trim(), String(category || '').trim(), String(wage || '').trim(), lat != null ? Number(lat) : null, lng != null ? Number(lng) : null, String(locationText || '').trim(), now());
  res.json({ id: info.lastInsertRowid });
});

// ---- Applications ----
app.get('/api/jobs/:id/applications', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(Number(req.params.id));
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  if (job.giverId !== me) return res.status(403).json({ error: 'Only the job giver can view applicants.' });
  const rows = db.prepare(`SELECT a.*, u.name AS seekerName, u.photo AS seekerPhoto, u.bio AS seekerBio, u.skills AS seekerSkills FROM applications a JOIN users u ON u.id = a.seekerId WHERE a.jobId = ? ORDER BY a.createdAt DESC`).all(job.id);
  // seeker email is deliberately NOT exposed here — it is PII and only ever
  // returned by /api/me. The job giver can contact the seeker through the
  // in-app messaging features instead.
  res.json({ applications: rows.map((a) => ({ id: a.id, message: a.message, status: a.status, createdAt: a.createdAt, seeker: { id: a.seekerId, name: a.seekerName, photo: a.seekerPhoto, bio: a.seekerBio, skills: (a.seekerSkills || '').split(',').map((s) => s.trim()).filter(Boolean) } })) });
});

app.post('/api/jobs/:id/apply', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in to apply.' });
  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(Number(req.params.id));
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  if (job.filled) return res.status(400).json({ error: 'This job has already been filled.' });
  if (job.giverId === me) return res.status(400).json({ error: 'You cannot apply to your own job.' });
  const { message } = req.body || {};
  const info = db.prepare("INSERT OR IGNORE INTO applications (jobId, seekerId, message, status, createdAt) VALUES (?, ?, ?, 'pending', ?)").run(job.id, me, String(message || '').trim(), now());
  if (info.changes === 0) return res.status(400).json({ error: 'You have already applied to this job.' });
  const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
  notify(job.giverId, me, 'apply', job.id, (actor ? actor.name : 'Someone') + ' applied to your job.', '/jobs');
  res.json({ ok: true });
});

app.post('/api/applications/:id/decide', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const { decision } = req.body || {};
  if (!['accept', 'reject'].includes(decision)) return res.status(400).json({ error: 'Invalid decision.' });
  const appRow = db.prepare('SELECT * FROM applications WHERE id = ?').get(Number(req.params.id));
  if (!appRow) return res.status(404).json({ error: 'Application not found.' });
  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(appRow.jobId);
  if (!job || job.giverId !== me) return res.status(403).json({ error: 'Only the job giver can decide.' });
  db.prepare('UPDATE applications SET status = ? WHERE id = ?').run(decision === 'accept' ? 'accepted' : 'rejected', appRow.id);
  if (decision === 'accept') { db.prepare('UPDATE jobs SET filled = 1 WHERE id = ?').run(job.id); db.prepare("UPDATE applications SET status = 'rejected' WHERE jobId = ? AND id != ? AND status = 'pending'").run(job.id, appRow.id); }
  const giver = db.prepare('SELECT name FROM users WHERE id = ?').get(job.giverId);
  notify(appRow.seekerId, job.giverId, 'application_' + decision, job.id, (giver ? giver.name : 'A giver') + (decision === 'accept' ? ' accepted your application.' : ' reviewed your application.'), '/jobs');
  res.json({ ok: true });
});

app.get('/api/my/applications', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const rows = db.prepare(`SELECT a.status AS appStatus, a.createdAt AS appliedAt, a.message AS appMessage, j.*, u.name AS giverName, u.photo AS giverPhoto FROM applications a JOIN jobs j ON j.id = a.jobId JOIN users u ON u.id = j.giverId WHERE a.seekerId = ? ORDER BY a.createdAt DESC`).all(me);
  res.json({ jobs: rows.map((r) => ({ id: r.id, title: r.title, description: r.description, category: r.category, wage: r.wage, locationText: r.locationText, filled: !!r.filled, appStatus: r.appStatus, appliedAt: r.appliedAt, giver: { id: r.giverId, name: r.giverName, photo: r.giverPhoto } })) });
});

app.get('/api/my/jobs', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const rows = db.prepare(`SELECT j.*, (SELECT COUNT(*) FROM applications a WHERE a.jobId = j.id) AS applicantCount, NULL AS myStatus FROM jobs j WHERE j.giverId = ? ORDER BY j.createdAt DESC`).all(me);
  res.json({ jobs: rows.map((j) => ({ ...serializeJob(j), giver: { id: me }, applicantCount: j.applicantCount })) });
});

// ---- Events ----
app.get('/api/events', (req, res) => {
  const me = getUserId(req);
  const rows = db.prepare(EVENT_SELECT + ' ORDER BY e.startAt ASC').all(me);
  res.json({ events: rows.map(serializeEvent) });
});
app.get('/api/events/:id', (req, res) => {
  const me = getUserId(req);
  const row = db.prepare(EVENT_SELECT + ' WHERE e.id = ?').get(me, Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Event not found.' });
  res.json({ event: serializeEvent(row) });
});
app.post('/api/events', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const { title, description, location, startAt } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'Event title is required.' });
  const start = new Date(String(startAt || ''));
  if (isNaN(start.getTime())) return res.status(400).json({ error: 'A valid startAt date is required.' });
  const info = db.prepare('INSERT INTO events (hostId, title, description, location, startAt, createdAt) VALUES (?, ?, ?, ?, ?, ?)').run(me, String(title).trim(), String(description || '').trim(), String(location || '').trim(), start.toISOString(), now());
  res.json({ id: info.lastInsertRowid });
});
app.post('/api/events/:id/rsvp', socialLimiter, (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const event = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!event) return res.status(404).json({ error: 'Event not found.' });
  const { going } = req.body || {};
  const go = coerceBool(going);
  if (go === null) return res.status(400).json({ error: 'going must be true or false.' });
  if (go) {
    const info = db.prepare('INSERT OR IGNORE INTO event_participants (eventId, userId, createdAt) VALUES (?, ?, ?)').run(event.id, me, now());
    if (info.changes > 0) {
      const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
      notify(event.hostId, me, 'rsvp', event.id, (actor ? actor.name : 'Someone') + ' is attending your event.', '/events');
    }
  } else {
    db.prepare('DELETE FROM event_participants WHERE eventId = ? AND userId = ?').run(event.id, me);
  }
  const count = db.prepare('SELECT COUNT(*) AS c FROM event_participants WHERE eventId = ?').get(event.id).c;
  res.json({ attending: go, attendeeCount: count });
});
app.delete('/api/events/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const event = db.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
  if (!event) return res.status(404).json({ error: 'Event not found.' });
  if (event.hostId !== me) return res.status(403).json({ error: 'Only the host can delete this event.' });
  db.prepare('DELETE FROM events WHERE id = ?').run(event.id);
  res.json({ ok: true });
});

// ---- Notifications ----
app.get('/api/notifications', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const rows = db.prepare(`SELECT n.*, u.name AS actorName, u.photo AS actorPhoto FROM notifications n JOIN users u ON u.id = n.actorId WHERE n.userId = ? ORDER BY n.createdAt DESC LIMIT 50`).all(me);
  const unread = db.prepare('SELECT COUNT(*) AS c FROM notifications WHERE userId = ? AND read = 0').get(me).c;
  res.json({ notifications: rows.map((n) => ({ id: n.id, type: n.type, entityId: n.entityId, text: n.text, link: n.link, read: !!n.read, createdAt: n.createdAt, actor: { id: n.actorId, name: n.actorName, photo: n.actorPhoto } })), unread });
});
app.post('/api/notifications/read', (req, res) => { const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' }); db.prepare('UPDATE notifications SET read = 1 WHERE userId = ? AND read = 0').run(me); res.json({ ok: true }); });

// ============================================================
// MESSAGES — Full Messenger API
// ============================================================

// List conversations
app.get('/api/messages', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const rows = db.prepare(`
    SELECT c.*,
           CASE WHEN c.userA = ? THEN c.userB ELSE c.userA END AS otherId,
           (SELECT body FROM messages m WHERE m.conversationId = c.id AND m.deleted = 0 ORDER BY m.createdAt DESC LIMIT 1) AS lastMessage,
           (SELECT createdAt FROM messages m WHERE m.conversationId = c.id ORDER BY m.createdAt DESC LIMIT 1) AS lastMessageAt,
           (SELECT senderId FROM messages m WHERE m.conversationId = c.id ORDER BY m.createdAt DESC LIMIT 1) AS lastSenderId
    FROM conversations c WHERE c.userA = ? OR c.userB = ? ORDER BY lastMessageAt DESC
  `).all(me, me, me);
  const convos = rows.map((r) => {
    const other = db.prepare('SELECT id, name, photo, online, lastSeen FROM users WHERE id = ?').get(r.otherId);
    const readAt = db.prepare("SELECT readAt FROM messages WHERE conversationId = ? AND senderId = ? ORDER BY createdAt DESC LIMIT 1").get(r.id, me);
    const unread = db.prepare("SELECT COUNT(*) AS c FROM messages WHERE conversationId = ? AND senderId != ? AND deleted = 0 AND (readAt = '' OR readAt IS NULL)").get(r.id, me);
    return { id: r.id, other, lastMessage: r.lastMessage, lastMessageAt: r.lastMessageAt, unreadCount: (unread && unread.c) || 0, muted: !!r.muted };
  });
  res.json({ conversations: convos });
});

// Get messages for a conversation
app.get('/api/messages/:userId', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  if (!otherId || otherId === me) return res.status(400).json({ error: 'Invalid user.' });
  const other = db.prepare('SELECT id, name, photo, online, lastSeen FROM users WHERE id = ?').get(otherId);
  if (!other) return res.status(404).json({ error: 'User not found.' });
  if (isBlocked(me, otherId)) return res.status(403).json({ error: 'You have been blocked by this user.' });
  const convoId = getOrCreateConversation(me, otherId);
  const rows = db.prepare(`SELECT m.*, u.name AS senderName, u.photo AS senderPhoto FROM messages m JOIN users u ON u.id = m.senderId WHERE m.conversationId = ? ORDER BY m.createdAt ASC`).all(convoId);

  db.prepare("UPDATE messages SET readAt = ? WHERE conversationId = ? AND senderId != ? AND (readAt = '' OR readAt IS NULL)").run(now(), convoId, me);

  const messages = rows.map((m) => {
    let replyTo = null;
    if (m.replyToId) {
      const rt = db.prepare('SELECT rm.id, rm.body, rm.senderId, rm.deleted, u.name AS senderName FROM messages rm JOIN users u ON u.id = rm.senderId WHERE rm.id = ?').get(m.replyToId);
      if (rt) replyTo = { id: rt.id, body: rt.deleted ? 'Message deleted' : rt.body, senderName: rt.senderName };
    }
    let forwardedFrom = null;
    if (m.forwardedId) {
      const fw = db.prepare('SELECT rm.body, rm.deleted, u.name AS senderName FROM messages rm JOIN users u ON u.id = rm.senderId WHERE rm.id = ?').get(m.forwardedId);
      if (fw) forwardedFrom = { body: fw.deleted ? 'Message deleted' : fw.body, senderName: fw.senderName };
    }
    const reactions = db.prepare('SELECT mr.emoji, mr.userId, u.name AS userName FROM message_reactions mr JOIN users u ON u.id = mr.userId WHERE mr.messageId = ?').all(m.id);
    return {
      id: m.id, body: m.body, attachment: m.attachment, createdAt: m.createdAt, deleted: m.deleted, edited: m.edited, starred: m.starred, pinned: m.pinned,
      readAt: m.readAt || null, replyTo, forwardedFrom, reactions,
      sender: { id: m.senderId, name: m.senderName, photo: m.senderPhoto },
    };
  });

  const muted = db.prepare('SELECT muted FROM conversations WHERE id = ?').get(convoId);
  res.json({ conversationId: convoId, other, messages, muted: muted ? !!muted.muted : false });
});

// Send message
app.post('/api/messages/:userId', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  if (!otherId || otherId === me) return res.status(400).json({ error: 'Invalid user.' });
  if (isBlocked(me, otherId)) return res.status(403).json({ error: 'Cannot send messages to this user.' });
  const { body, replyToId, forwardedId, attachment } = req.body || {};
  if (!body && !attachment) return res.status(400).json({ error: 'Message cannot be empty.' });
  const convoId = getOrCreateConversation(me, otherId);
  const info = db.prepare('INSERT INTO messages (conversationId, senderId, body, replyToId, forwardedId, attachment, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)').run(convoId, me, String(body || '').trim(), replyToId || null, forwardedId || null, attachment || '', now());
  const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
  notify(otherId, me, 'message', convoId, (actor ? actor.name : 'Someone') + ' sent you a message.', '/messages');
  const msg = db.prepare('SELECT m.*, u.name AS senderName, u.photo AS senderPhoto FROM messages m JOIN users u ON u.id = m.senderId WHERE m.id = ?').get(info.lastInsertRowid);
  let replyTo = null;
  if (msg.replyToId) { const rt = db.prepare('SELECT rm.id, rm.body, rm.senderId, rm.deleted, u.name AS senderName FROM messages rm JOIN users u ON u.id = rm.senderId WHERE rm.id = ?').get(msg.replyToId); if (rt) replyTo = { id: rt.id, body: rt.deleted ? 'Message deleted' : rt.body, senderName: rt.senderName }; }
  let forwardedFrom = null;
  if (msg.forwardedId) { const fw = db.prepare('SELECT rm.body, rm.deleted, u.name AS senderName FROM messages rm JOIN users u ON u.id = rm.senderId WHERE rm.id = ?').get(msg.forwardedId); if (fw) forwardedFrom = { body: fw.deleted ? 'Message deleted' : fw.body, senderName: fw.senderName }; }
  res.json({ message: { id: msg.id, body: msg.body, attachment: msg.attachment, createdAt: msg.createdAt, replyTo, forwardedFrom, reactions: [], sender: { id: msg.senderId, name: msg.senderName, photo: msg.senderPhoto } } });
});

// Edit message
app.patch('/api/messages/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const msgId = Number(req.params.id);
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found.' });
  if (msg.senderId !== me) return res.status(403).json({ error: 'Not your message.' });
  const { body } = req.body || {};
  if (body !== undefined && String(body).trim()) { db.prepare('UPDATE messages SET body = ?, edited = 1 WHERE id = ?').run(String(body).trim(), msgId); }
  const updated = db.prepare('SELECT m.*, u.name AS senderName, u.photo AS senderPhoto FROM messages m JOIN users u ON u.id = m.senderId WHERE m.id = ?').get(msgId);
  res.json({ message: { id: updated.id, body: updated.body, edited: updated.edited, createdAt: updated.createdAt, sender: { id: updated.senderId, name: updated.senderName, photo: updated.senderPhoto } } });
});

// Delete message (soft)
app.delete('/api/messages/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const msgId = Number(req.params.id);
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found.' });
  if (msg.senderId !== me) return res.status(403).json({ error: 'Not your message.' });
  db.prepare('UPDATE messages SET deleted = 1 WHERE id = ?').run(msgId);
  res.json({ ok: true });
});

// Star/unstar message
app.post('/api/messages/:id/star', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(Number(req.params.id));
  if (!msg) return res.status(404).json({ error: 'Message not found.' });
  const newVal = msg.starred ? 0 : 1;
  db.prepare('UPDATE messages SET starred = ? WHERE id = ?').run(newVal, msg.id);
  res.json({ starred: !!newVal });
});

// Pin/unpin message
app.post('/api/messages/:id/pin', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(Number(req.params.id));
  if (!msg) return res.status(404).json({ error: 'Message not found.' });
  const newVal = msg.pinned ? 0 : 1;
  db.prepare('UPDATE messages SET pinned = ? WHERE id = ?').run(newVal, msg.id);
  res.json({ pinned: !!newVal });
});

// React to message
app.post('/api/messages/:id/react', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const msgId = Number(req.params.id);
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'Emoji required.' });
  const existing = db.prepare('SELECT id FROM message_reactions WHERE messageId = ? AND userId = ? AND emoji = ?').get(msgId, me, emoji);
  if (existing) {
    db.prepare('DELETE FROM message_reactions WHERE id = ?').run(existing.id);
  } else {
    db.prepare('INSERT INTO message_reactions (messageId, userId, emoji, createdAt) VALUES (?, ?, ?, ?)').run(msgId, me, emoji, now());
  }
  const reactions = db.prepare('SELECT mr.emoji, mr.userId, u.name AS userName FROM message_reactions mr JOIN users u ON u.id = mr.userId WHERE mr.messageId = ?').all(msgId);
  res.json({ reactions });
});

// Forward message
app.post('/api/messages/:id/forward', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const msgId = Number(req.params.id);
  const { toUserId } = req.body || {};
  if (!toUserId) return res.status(400).json({ error: 'Target user required.' });
  const orig = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  if (!orig) return res.status(404).json({ error: 'Message not found.' });
  const convoId = getOrCreateConversation(me, Number(toUserId));
  const info = db.prepare('INSERT INTO messages (conversationId, senderId, body, forwardedId, createdAt) VALUES (?, ?, ?, ?, ?)').run(convoId, me, orig.body, orig.id, now());
  res.json({ ok: true, messageId: info.lastInsertRowid });
});

// Search messages within conversation
app.get('/api/messages/:userId/search', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  const q = String(req.query.q || '').trim();
  if (!q) return res.json({ messages: [] });
  const convoId = getOrCreateConversation(me, otherId);
  const like = '%' + q.replace(/[%_]/g, (c) => '\\' + c) + '%';
  const rows = db.prepare(`SELECT m.*, u.name AS senderName, u.photo AS senderPhoto FROM messages m JOIN users u ON u.id = m.senderId WHERE m.conversationId = ? AND m.body LIKE ? ESCAPE '\\' AND m.deleted = 0 ORDER BY m.createdAt DESC LIMIT 50`).all(convoId, like);
  res.json({ messages: rows.map((m) => ({ id: m.id, body: m.body, createdAt: m.createdAt, sender: { id: m.senderId, name: m.senderName, photo: m.senderPhoto } })) });
});

// Typing indicator (simple POST endpoint)
app.post('/api/messages/:userId/typing', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  const { typing } = req.body || {};
  const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
  if (typing) notify(otherId, me, 'typing', null, (actor ? actor.name : 'Someone') + ' is typing...', '');
  res.json({ ok: true });
});

// Mark conversation as read
app.post('/api/messages/:userId/read', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  const convoId = getOrCreateConversation(me, otherId);
  db.prepare("UPDATE messages SET readAt = ? WHERE conversationId = ? AND senderId != ? AND (readAt = '' OR readAt IS NULL)").run(now(), convoId, me);
  res.json({ ok: true });
});

// Toggle mute conversation
app.post('/api/messages/:userId/mute', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  const convoId = getOrCreateConversation(me, otherId);
  const convo = db.prepare('SELECT muted FROM conversations WHERE id = ?').get(convoId);
  const newVal = convo && convo.muted ? 0 : 1;
  db.prepare('UPDATE conversations SET muted = ? WHERE id = ?').run(newVal, convoId);
  res.json({ muted: !!newVal });
});

// Get starred messages
app.get('/api/messages/:userId/starred', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const otherId = Number(req.params.userId);
  const convoId = getOrCreateConversation(me, otherId);
  const rows = db.prepare(`SELECT m.*, u.name AS senderName, u.photo AS senderPhoto FROM messages m JOIN users u ON u.id = m.senderId WHERE m.conversationId = ? AND m.starred = 1 ORDER BY m.createdAt DESC`).all(convoId);
  res.json({ messages: rows.map((m) => ({ id: m.id, body: m.body, createdAt: m.createdAt, sender: { id: m.senderId, name: m.senderName, photo: m.senderPhoto } })) });
});

// File upload for messages
app.post('/api/upload', upload.single('file'), (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname });
});

// ============================================================
// DATA EXPORT — "Download my data" (GDPR / account portability)
// ============================================================

// Shared handler: builds the complete personal-data JSON payload for the
// authenticated user. Mounted on both /api/me/data and /api/me/data.json so
// the frontend can trigger a download via <a href="/api/me/data.json" download>.
function buildDataExport(userId) {
  // ---- User profile (NO password hash) ----
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const user = {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    bio: u.bio || '',
    photo: u.photo || '',
    skills: (u.skills || '').split(',').map((s) => s.trim()).filter(Boolean),
    location: u.location || '',
    theme: THEMES.has(u.theme) ? u.theme : '',
    notifyPrefs: parseNotifyPrefs(u.notifyPrefs),
    private: !!u.privateProfile,
    createdAt: u.createdAt,
  };

  // ---- Settings (denormalised for convenience) ----
  const settings = {
    theme: user.theme,
    notifyPrefs: user.notifyPrefs,
    privateProfile: !!u.privateProfile,
  };

  // ---- Posts authored by the user ----
  const postRows = db.prepare(`
    SELECT p.*
    FROM posts p
    WHERE p.authorId = ?
    ORDER BY p.createdAt DESC
  `).all(userId);

  // Batch-fetch reaction tallies for all the user's posts.
  const postIds = postRows.map((r) => r.id);
  const reactionMap = new Map();
  if (postIds.length) {
    const marks = postIds.map(() => '?').join(',');
    const rRows = db.prepare(`
      SELECT postId, emoji, COUNT(*) AS cnt
      FROM post_reactions
      WHERE postId IN (${marks})
      GROUP BY postId, emoji
      ORDER BY cnt DESC, emoji ASC
    `).all(...postIds);
    for (const r of rRows) {
      const arr = reactionMap.get(r.postId) || [];
      arr.push({ emoji: r.emoji, count: r.cnt });
      reactionMap.set(r.postId, arr);
    }
  }

  // Batch-fetch share counts for the user's posts.
  const shareMap = new Map();
  if (postIds.length) {
    const marks = postIds.map(() => '?').join(',');
    const sRows = db.prepare(`
      SELECT shareOfId, COUNT(*) AS cnt
      FROM posts
      WHERE shareOfId IN (${marks})
      GROUP BY shareOfId
    `).all(...postIds);
    for (const r of sRows) shareMap.set(r.shareOfId, r.cnt);
  }

  const posts = postRows.map((r) => ({
    id: r.id,
    body: r.body,
    type: r.type,
    image: r.image || '',
    createdAt: r.createdAt,
    hashtags: r.hashtags || '',
    reactions: reactionMap.get(r.id) || [],
    sharesCount: shareMap.get(r.id) || 0,
  }));

  // ---- Comments authored by the user ----
  const myComments = db.prepare(`
    SELECT id, postId, body, createdAt
    FROM comments
    WHERE authorId = ?
    ORDER BY createdAt DESC
  `).all(userId).map((c) => ({ id: c.id, postId: c.postId, body: c.body, createdAt: c.createdAt }));

  // ---- Jobs offered by the user ----
  const jobsOffered = db.prepare(`
    SELECT j.id, j.title, j.description, j.category, j.wage, j.locationText, j.filled, j.createdAt,
           (SELECT COUNT(*) FROM applications a WHERE a.jobId = j.id) AS applicantCount
    FROM jobs j
    WHERE j.giverId = ?
    ORDER BY j.createdAt DESC
  `).all(userId).map((j) => ({
    id: j.id, title: j.title, description: j.description, category: j.category,
    wage: j.wage, locationText: j.locationText, filled: !!j.filled,
    createdAt: j.createdAt, applicantCount: j.applicantCount,
  }));

  // ---- Applications submitted by the user ----
  const applications = db.prepare(`
    SELECT a.id, a.jobId, j.title, a.message, a.status, a.createdAt
    FROM applications a
    JOIN jobs j ON j.id = a.jobId
    WHERE a.seekerId = ?
    ORDER BY a.createdAt DESC
  `).all(userId).map((a) => ({
    id: a.id, jobId: a.jobId, title: a.title, message: a.message,
    status: a.status, createdAt: a.createdAt,
  }));

  // ---- Events hosted by the user ----
  const eventsHosted = db.prepare(`
    SELECT id, title, description, location, startAt
    FROM events
    WHERE hostId = ?
    ORDER BY startAt ASC
  `).all(userId).map((e) => ({
    id: e.id, title: e.title, description: e.description || '',
    location: e.location || '', startAt: e.startAt,
  }));

  // ---- Events the user is attending ----
  const eventsAttending = db.prepare(`
    SELECT e.id, e.title, e.location, e.startAt
    FROM event_participants ep
    JOIN events e ON e.id = ep.eventId
    WHERE ep.userId = ?
    ORDER BY e.startAt ASC
  `).all(userId).map((e) => ({ id: e.id, title: e.title, location: e.location || '', startAt: e.startAt }));

  // ---- Follow stats ----
  const fc = followCounts(userId);

  // ---- Notifications (all, not just last 50) ----
  const notifications = db.prepare(`
    SELECT id, type, text, read, createdAt
    FROM notifications
    WHERE userId = ?
    ORDER BY createdAt DESC
  `).all(userId).map((n) => ({ id: n.id, type: n.type, text: n.text, read: !!n.read, createdAt: n.createdAt }));

  // ---- Conversations & messages ----
  // Only conversations the user participates in; messages include the full
  // message history. The withUser field identifies the other party.
  const convoRows = db.prepare(`
    SELECT c.*,
           CASE WHEN c.userA = ? THEN c.userB ELSE c.userA END AS otherUserId
    FROM conversations c
    WHERE c.userA = ? OR c.userB = ?
    ORDER BY c.createdAt DESC
  `).all(userId, userId, userId);

  const conversations = convoRows.map((c) => {
    const other = db.prepare('SELECT id, name FROM users WHERE id = ?').get(c.otherUserId);
    const msgs = db.prepare(`
      SELECT id, body, senderId, attachment, createdAt, deleted
      FROM messages
      WHERE conversationId = ?
      ORDER BY createdAt ASC
    `).all(c.id).map((m) => ({
      id: m.id, body: m.body, senderId: m.senderId,
      attachment: m.attachment || '', createdAt: m.createdAt, deleted: !!m.deleted,
    }));
    return {
      id: c.id,
      withUser: { id: other.id, name: other.name },
      messages: msgs,
    };
  });

  return {
    user,
    settings,
    posts,
    myComments,
    jobsOffered,
    applications,
    eventsHosted,
    eventsAttending,
    followersCount: fc.followersCount,
    followingCount: fc.followingCount,
    notifications,
    conversations,
  };
}

app.get('/api/me/data', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in to download your data.' });
  res.json(buildDataExport(me));
});

app.get('/api/me/data.json', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in to download your data.' });
  // Content-Type stays application/json; the frontend triggers download via
  // <a href="..." download> or a Blob + click() pattern.
  res.json(buildDataExport(me));
});

// ---- Account info (minimal) ----
app.get('/api/me/account', (req, res) => {
  const me = getUserId(req);
  if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const u = db.prepare('SELECT email, createdAt, lastSeen FROM users WHERE id = ?').get(me);
  if (!u) return res.status(401).json({ error: 'Please sign in.' });
  res.json({ email: u.email, joined: u.createdAt, lastSeen: u.lastSeen || null });
});

app.listen(PORT, () => {
  console.log(`Announce running at http://localhost:${PORT}`);
});
