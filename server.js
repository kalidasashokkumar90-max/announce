const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const db = require('./db');
const { seed } = require('./seed');

const app = express();
const PORT = process.env.PORT || 3000;

seed();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const sessions = new Map();

function sign(data) {
  return data + '.' + crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
}
function setSession(res, userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
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
  if (!sig || sig !== expected) return null;
  return sessions.get(payload) ?? null;
}

function now() { return new Date().toISOString(); }

function publicUser(u) {
  return {
    id: u.id, name: u.name, email: u.email, role: u.role, bio: u.bio, photo: u.photo,
    skills: (u.skills || '').split(',').map((s) => s.trim()).filter(Boolean),
    createdAt: u.createdAt,
  };
}

function serializePost(row) {
  return {
    id: row.id, body: row.body, image: row.image, type: row.type, createdAt: row.createdAt,
    author: { id: row.authorId, name: row.authorName, photo: row.authorPhoto },
    likeCount: row.likeCount, commentCount: row.commentCount, likedByMe: !!row.likedByMe,
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
  const a = Math.min(by, of), b = Math.max(by, of);
  return !!db.prepare('SELECT id FROM blocks WHERE blockerId = ? AND blockedId = ?').get(a, b);
}

const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase();
    cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
  },
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ---- Auth ----
app.post('/api/signup', async (req, res) => {
  const { name, email, password, skills } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(String(email).toLowerCase());
  if (existing) return res.status(400).json({ error: 'An account with that email already exists.' });
  const hash = bcrypt.hashSync(String(password), 10);
  const skillsStr = Array.isArray(skills) ? skills.map((s) => s.trim()).filter(Boolean).join(', ') : String(skills || '');
  const res2 = db.prepare('INSERT INTO users (name, email, password, role, bio, photo, skills, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(String(name), String(email).toLowerCase(), hash, 'member', '', '', skillsStr, now());
  setSession(res, res2.lastInsertRowid);
  db.prepare('UPDATE users SET online = 1, lastSeen = ? WHERE id = ?').run(now(), res2.lastInsertRowid);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(res2.lastInsertRowid);
  res.json({ user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ''), user.password)) return res.status(401).json({ error: 'Invalid email or password.' });
  setSession(res, user.id);
  db.prepare('UPDATE users SET online = 1, lastSeen = ? WHERE id = ?').run(now(), user.id);
  res.json({ user: publicUser(user) });
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
  res.json({ user: user ? publicUser(user) : null });
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
         EXISTS(SELECT 1 FROM likes l2 WHERE l2.postId = p.id AND l2.userId = ?) AS likedByMe
  FROM posts p JOIN users u ON u.id = p.authorId
`;
app.get('/api/posts', (req, res) => { const me = getUserId(req); const rows = db.prepare(POST_SELECT + ' ORDER BY p.createdAt DESC').all(me); res.json({ posts: rows.map(serializePost) }); });
app.get('/api/posts/:id', (req, res) => { const me = getUserId(req); const row = db.prepare(POST_SELECT + ' WHERE p.id = ?').get(me, Number(req.params.id)); if (!row) return res.status(404).json({ error: 'Post not found.' }); res.json({ post: serializePost(row) }); });

app.post('/api/posts', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in to post.' });
  const { body, type } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Post cannot be empty.' });
  const t = ['general', 'offer', 'advertisement'].includes(type) ? type : 'general';
  const info = db.prepare('INSERT INTO posts (authorId, body, image, type, createdAt) VALUES (?, ?, ?, ?, ?)').run(me, String(body).trim(), '', t, now());
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
  db.prepare('UPDATE posts SET body = ?, type = ? WHERE id = ?').run(String(body).trim(), t, post.id);
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

// ---- Comments ----
app.get('/api/posts/:id/comments', (req, res) => {
  const rows = db.prepare('SELECT c.*, u.name AS authorName, u.photo AS authorPhoto FROM comments c JOIN users u ON u.id = c.authorId WHERE c.postId = ? ORDER BY c.createdAt ASC').all(Number(req.params.id));
  res.json({ comments: rows.map((c) => ({ id: c.id, body: c.body, createdAt: c.createdAt, author: { id: c.authorId, name: c.authorName, photo: c.authorPhoto } })) });
});
app.post('/api/posts/:id/comments', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  const { body } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'Comment cannot be empty.' });
  const post = db.prepare('SELECT id, authorId FROM posts WHERE id = ?').get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const info = db.prepare('INSERT INTO comments (postId, authorId, body, createdAt) VALUES (?, ?, ?, ?)').run(post.id, me, String(body).trim(), now());
  const actor = db.prepare('SELECT name FROM users WHERE id = ?').get(me);
  notify(post.authorId, me, 'comment', post.id, (actor ? actor.name : 'Someone') + ' commented on your post.', '/feed');
  const comment = db.prepare('SELECT c.*, u.name AS authorName, u.photo AS authorPhoto FROM comments c JOIN users u ON u.id = c.authorId WHERE c.id = ?').get(info.lastInsertRowid);
  res.json({ comment: { id: comment.id, body: comment.body, createdAt: comment.createdAt, author: { id: comment.authorId, name: comment.authorName, photo: comment.authorPhoto } } });
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
  res.json({ results: rows.map(publicUser) });
});

// ---- Profiles ----
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const me = getUserId(req);
  const postCount = db.prepare('SELECT COUNT(*) AS c FROM posts WHERE authorId = ?').get(user.id).c;
  const rows = db.prepare(POST_SELECT + ' WHERE p.authorId = ? ORDER BY p.createdAt DESC').all(me, user.id);
  const likesReceived = db.prepare('SELECT COUNT(*) AS c FROM likes l JOIN posts p ON p.id = l.postId WHERE p.authorId = ?').get(user.id).c;
  const commentsReceived = db.prepare('SELECT COUNT(*) AS c FROM comments co JOIN posts p ON p.id = co.postId WHERE p.authorId = ?').get(user.id).c;
  const openJobs = db.prepare('SELECT COUNT(*) AS c FROM jobs WHERE giverId = ? AND filled = 0').get(user.id).c;
  const jobsDone = db.prepare('SELECT COUNT(*) AS c FROM jobs WHERE giverId = ? AND filled = 1').get(user.id).c;
  const blocked = me ? isBlocked(user.id, me) : false;
  res.json({ user: publicUser(user), postCount, likesReceived, commentsReceived, openJobs, jobsDone, posts: rows.map(serializePost), blocked });
});
app.patch('/api/users/:id', (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  if (me !== Number(req.params.id)) return res.status(403).json({ error: 'Not your profile.' });
  const { name, bio, skills } = req.body || {};
  const nameVal = String(name || '').trim();
  if (nameVal) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(nameVal, me);
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(String(bio || '').trim(), me);
  const skillsArr = Array.isArray(skills) ? skills : String(skills || '').split(',');
  db.prepare('UPDATE users SET skills = ? WHERE id = ?').run(skillsArr.map((s) => s.trim()).filter(Boolean).join(', '), me);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(me);
  res.json({ user: publicUser(user) });
});
app.post('/api/users/:id/photo', upload.single('photo'), (req, res) => {
  const me = getUserId(req); if (!me) return res.status(401).json({ error: 'Please sign in.' });
  if (me !== Number(req.params.id)) return res.status(403).json({ error: 'Not your profile.' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const photo = '/uploads/' + req.file.filename;
  db.prepare('UPDATE users SET photo = ? WHERE id = ?').run(photo, me);
  res.json({ photo });
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
  const rows = db.prepare(`SELECT a.*, u.name AS seekerName, u.photo AS seekerPhoto, u.bio AS seekerBio, u.skills AS seekerSkills, u.email AS seekerEmail FROM applications a JOIN users u ON u.id = a.seekerId WHERE a.jobId = ? ORDER BY a.createdAt DESC`).all(job.id);
  res.json({ applications: rows.map((a) => ({ id: a.id, message: a.message, status: a.status, createdAt: a.createdAt, seeker: { id: a.seekerId, name: a.seekerName, photo: a.seekerPhoto, bio: a.seekerBio, email: a.seekerEmail, skills: (a.seekerSkills || '').split(',').map((s) => s.trim()).filter(Boolean) } })) });
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

app.listen(PORT, () => {
  console.log(`SocialFeed running at http://localhost:${PORT}`);
});
