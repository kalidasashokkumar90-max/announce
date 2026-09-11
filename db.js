const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'socialfeed.db');

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
`);

try { db.exec('ALTER TABLE messages ADD COLUMN replyToId INTEGER REFERENCES messages(id) ON DELETE SET NULL'); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN edited INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN attachment TEXT DEFAULT \'\''); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN forwardedId INTEGER REFERENCES messages(id) ON DELETE SET NULL'); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN starred INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try { db.exec('ALTER TABLE messages ADD COLUMN readAt TEXT DEFAULT \'\''); } catch (_) {}
try { db.exec('ALTER TABLE conversations ADD COLUMN muted INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try { db.exec('ALTER TABLE users ADD COLUMN online INTEGER NOT NULL DEFAULT 0'); } catch (_) {}
try { db.exec('ALTER TABLE users ADD COLUMN lastSeen TEXT DEFAULT \'\''); } catch (_) {}

module.exports = db;
