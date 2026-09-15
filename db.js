const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = path.join(__dirname, 'data');
// DB_PATH can be overridden (e.g. a DB_PATH-scoped smoke test) so the real
// data/announce.db is never touched by test runs. The guarded migrations
// below are applied to whichever file is opened.
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'announce.db');

const db = new DatabaseSync(DB_PATH);

db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member',
    bio        TEXT DEFAULT '',
    photo      TEXT DEFAULT '',
    skills     TEXT DEFAULT '',
    location   TEXT NOT NULL DEFAULT '',
    theme      TEXT NOT NULL DEFAULT '',
    notifyPrefs TEXT NOT NULL DEFAULT '{}',
    privateProfile INTEGER NOT NULL DEFAULT 0,
    googleId   TEXT,
    isAdmin    INTEGER NOT NULL DEFAULT 0,
    online     INTEGER NOT NULL DEFAULT 0,
    lastSeen   TEXT DEFAULT '',
    createdAt  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    authorId   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    image      TEXT DEFAULT '',
    type       TEXT NOT NULL DEFAULT 'general',
    shareOfId  INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    hashtags   TEXT DEFAULT '',
    createdAt  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS likes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    postId     INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    userId     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt  TEXT NOT NULL,
    UNIQUE(postId, userId)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    postId     INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    authorId   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    parentId   INTEGER REFERENCES comments(id) ON DELETE CASCADE,
    createdAt  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    giverId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    description TEXT NOT NULL,
    category   TEXT DEFAULT '',
    wage       TEXT DEFAULT '',
    lat        REAL,
    lng        REAL,
    locationText TEXT DEFAULT '',
    filled     INTEGER NOT NULL DEFAULT 0,
    createdAt  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS applications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    jobId      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    seekerId   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message    TEXT DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'pending',
    createdAt  TEXT NOT NULL,
    UNIQUE(jobId, seekerId)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    userId     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actorId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    entityId   INTEGER,
    text       TEXT NOT NULL,
    link       TEXT DEFAULT '',
    read       INTEGER NOT NULL DEFAULT 0,
    createdAt  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    userA    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    userB    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    muted    INTEGER NOT NULL DEFAULT 0,
    createdAt TEXT NOT NULL,
    UNIQUE(userA, userB)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    conversationId INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    senderId       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body           TEXT NOT NULL DEFAULT '',
    attachment     TEXT DEFAULT '',
    replyToId      INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    forwardedId    INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    starred        INTEGER NOT NULL DEFAULT 0,
    pinned         INTEGER NOT NULL DEFAULT 0,
    edited         INTEGER NOT NULL DEFAULT 0,
    deleted        INTEGER NOT NULL DEFAULT 0,
    readAt         TEXT DEFAULT '',
    createdAt      TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS message_reactions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    messageId INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    userId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji     TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    UNIQUE(messageId, userId, emoji)
  );

  CREATE TABLE IF NOT EXISTS blocks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    blockerId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blockedId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt TEXT NOT NULL,
    UNIQUE(blockerId, blockedId)
  );

  CREATE TABLE IF NOT EXISTS follows (
    followerId  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    followingId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt   TEXT NOT NULL,
    PRIMARY KEY (followerId, followingId)
  );

  CREATE TABLE IF NOT EXISTS post_reactions (
    postId    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    userId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji     TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    PRIMARY KEY (postId, userId, emoji)
  );

  CREATE TABLE IF NOT EXISTS saved_posts (
    postId    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    userId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt TEXT NOT NULL,
    PRIMARY KEY (postId, userId)
  );

  CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostId      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    description TEXT DEFAULT '',
    location    TEXT DEFAULT '',
    startAt     TEXT NOT NULL,
    createdAt   TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS event_participants (
    eventId   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    userId    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt TEXT NOT NULL,
    PRIMARY KEY (eventId, userId)
  );
`);

// ---- Guarded migrations ----------------------------------------------------
// Every ALTER TABLE is guarded by a PRAGMA table_info check so it only runs on
// databases whose CREATE TABLE predates the column. Blindly ALTERing a fresh
// DB (where CREATE TABLE IF NOT EXISTS already includes the column) throws
// "duplicate column name"; the PRAGMA check avoids that and makes each
// migration explicit instead of relying on swallowed try/catch errors.
function tableColumnNames(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

function ensureColumn(table, column, ddl) {
  if (tableColumnNames(table).includes(column)) return;
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

// users — Settings feature columns (fresh DBs get them from CREATE TABLE).
ensureColumn('users', 'online', `online INTEGER NOT NULL DEFAULT 0`);
ensureColumn('users', 'lastSeen', `lastSeen TEXT DEFAULT ''`);
ensureColumn('users', 'location', `location TEXT NOT NULL DEFAULT ''`);
ensureColumn('users', 'theme', `theme TEXT NOT NULL DEFAULT ''`);
ensureColumn('users', 'notifyPrefs', `notifyPrefs TEXT NOT NULL DEFAULT '{}'`);
ensureColumn('users', 'privateProfile', `privateProfile INTEGER NOT NULL DEFAULT 0`);
ensureColumn('users', 'googleId', `googleId TEXT`);
ensureColumn('users', 'isAdmin', `isAdmin INTEGER NOT NULL DEFAULT 0`);
// Partial unique index: NULL/'' googleId values are exempt so password users
// never collide, while real Google sub ids stay unique.
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_googleId ON users(googleId) WHERE googleId IS NOT NULL AND googleId != ''`);

// messages + conversations — columns added after the original tables shipped.
ensureColumn('messages', 'replyToId', `replyToId INTEGER REFERENCES messages(id) ON DELETE SET NULL`);
ensureColumn('messages', 'edited', `edited INTEGER NOT NULL DEFAULT 0`);
ensureColumn('messages', 'deleted', `deleted INTEGER NOT NULL DEFAULT 0`);
ensureColumn('messages', 'attachment', `attachment TEXT DEFAULT ''`);
ensureColumn('messages', 'forwardedId', `forwardedId INTEGER REFERENCES messages(id) ON DELETE SET NULL`);
ensureColumn('messages', 'starred', `starred INTEGER NOT NULL DEFAULT 0`);
ensureColumn('messages', 'pinned', `pinned INTEGER NOT NULL DEFAULT 0`);
ensureColumn('messages', 'readAt', `readAt TEXT DEFAULT ''`);
ensureColumn('conversations', 'muted', `muted INTEGER NOT NULL DEFAULT 0`);

// posts + comments — social feed columns added after the original tables shipped.
ensureColumn('posts', 'shareOfId', `shareOfId INTEGER REFERENCES posts(id) ON DELETE CASCADE`);
ensureColumn('posts', 'hashtags', `hashtags TEXT DEFAULT ''`);
ensureColumn('comments', 'parentId', `parentId INTEGER REFERENCES comments(id) ON DELETE CASCADE`);

module.exports = db;
