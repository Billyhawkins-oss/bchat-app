import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbFile = path.join(__dirname, 'bchat.sqlite');
const db = new Database(dbFile);

function initDb() {
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      avatar TEXT,
      role TEXT NOT NULL,
      code TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_online INTEGER DEFAULT 0,
      last_seen TEXT,
      e2ee_public_key TEXT,
      security_questions TEXT DEFAULT '[]',
      device_ids TEXT DEFAULT '[]',
      bio TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      sender TEXT NOT NULL,
      receiver TEXT,
      group_id TEXT,
      text TEXT,
      photo TEXT,
      voice_data TEXT,
      voice_duration TEXT,
      created_at TEXT NOT NULL,
      read INTEGER DEFAULT 0,
      chat_id TEXT,
      forwarded INTEGER DEFAULT 0,
      sender_name TEXT,
      email TEXT,
      reply_to TEXT,
      reactions TEXT
    );

    CREATE TABLE IF NOT EXISTS statuses (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      text TEXT,
      photo TEXT,
      time TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ads (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      title TEXT NOT NULL,
      text TEXT,
      photo TEXT,
      time TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      members TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      text TEXT,
      created_at TEXT NOT NULL
    );
  `);

  const userColumns = db.prepare("PRAGMA table_info(users)").all().map((row) => row.name);
  if (!userColumns.includes('security_questions')) {
    db.prepare("ALTER TABLE users ADD COLUMN security_questions TEXT DEFAULT '[]'").run();
  }
  if (!userColumns.includes('device_ids')) {
    db.prepare("ALTER TABLE users ADD COLUMN device_ids TEXT DEFAULT '[]'").run();
  }
}

initDb();

function safeParseJson(value, fallback = null) {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeUser(user) {
  if (!user) return null;
  return {
    ...user,
    id: user.id,
    username: user.username,
    email: user.email,
    display_name: user.display_name,
    avatar: user.avatar || null,
    role: user.role || 'user',
    code: user.code,
    createdAt: user.created_at,
    passwordHash: user.password_hash,
    is_online: Boolean(user.is_online),
    last_seen: user.last_seen,
    e2ee_public_key: user.e2ee_public_key,
    security_questions: safeParseJson(user.security_questions, []),
    device_ids: safeParseJson(user.device_ids, []),
    bio: user.bio || ''
  };
}

export async function getAllUsers() {
  return db.prepare('SELECT * FROM users').all().map(normalizeUser);
}

export async function getUserByUsername(username) {
  if (!username) return null;
  return normalizeUser(db.prepare('SELECT * FROM users WHERE username = ?').get(username));
}

export async function getUserByEmail(email) {
  if (!email) return null;
  return normalizeUser(db.prepare('SELECT * FROM users WHERE email = ?').get(email));
}

export async function getUserByCode(code) {
  if (!code) return null;
  return normalizeUser(db.prepare('SELECT * FROM users WHERE code = ?').get(code));
}

export async function insertUser(user) {
  const stmt = db.prepare(`
    INSERT INTO users (id, username, email, display_name, avatar, role, code, created_at, password_hash, is_online, last_seen, e2ee_public_key, security_questions, device_ids, bio)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    user.id,
    user.username,
    user.email,
    user.display_name,
    user.avatar || null,
    user.role || 'user',
    user.code,
    user.createdAt,
    user.passwordHash,
    user.is_online ? 1 : 0,
    user.last_seen || null,
    user.e2ee_public_key || null,
    JSON.stringify(user.security_questions || []),
    JSON.stringify(user.device_ids || []),
    user.bio || ''
  );
  return getUserByUsername(user.username);
}

export async function updateUserByUsername(username, fields) {
  const keys = Object.keys(fields);
  if (!keys.length) return null;
  const updates = keys.map((key) => `${key} = ?`).join(', ');
  const stmt = db.prepare(`UPDATE users SET ${updates} WHERE username = ?`);
  stmt.run(...keys.map((key) => {
    if (key === 'is_online') return fields[key] ? 1 : 0;
    if (key === 'security_questions' || key === 'device_ids') return JSON.stringify(fields[key] || []);
    return fields[key];
  }), username);
  return getUserByUsername(username);
}

export async function insertMessage(msg) {
  const stmt = db.prepare(`
    INSERT INTO messages (id, type, sender, receiver, group_id, text, photo, voice_data, voice_duration, created_at, read, chat_id, forwarded, sender_name, email, reply_to, reactions)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    msg.id,
    msg.type || 'text',
    msg.sender,
    msg.receiver || null,
    msg.groupId || msg.group_id || null,
    msg.text || null,
    msg.photo || null,
    msg.voice_data || msg.voiceData || null,
    msg.voice_duration || msg.voiceDuration || null,
    msg.created_at || msg.time || new Date().toISOString(),
    msg.read ? 1 : 0,
    msg.chat_id || null,
    msg.forwarded ? 1 : 0,
    msg.sender_name || null,
    msg.email || null,
    msg.reply_to ? JSON.stringify(msg.reply_to) : null,
    msg.reactions ? JSON.stringify(msg.reactions) : null
  );
  return getMessageById(msg.id);
}

export async function getMessageById(id) {
  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
  return message ? deserializeMessage(message) : null;
}

export async function getMessagesBetween(user1, user2, groupId) {
  if (groupId) {
    return db.prepare('SELECT * FROM messages WHERE group_id = ? ORDER BY datetime(created_at)').all(groupId).map(deserializeMessage);
  }
  return db.prepare(
    'SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY datetime(created_at)'
  ).all(user1, user2, user2, user1).map(deserializeMessage);
}

export async function deleteMessageById(id) {
  return db.prepare('DELETE FROM messages WHERE id = ?').run(id);
}

export async function markMessagesRead({ sender, receiver, groupId, username }) {
  if (groupId) {
    return db.prepare('UPDATE messages SET read = 1 WHERE group_id = ? AND receiver = ? AND sender != ?').run(groupId, username, username);
  }
  return db.prepare('UPDATE messages SET read = 1 WHERE sender = ? AND receiver = ? AND receiver = ?').run(sender, receiver, username);
}

export async function getConversations(username) {
  return db.prepare(
    'SELECT * FROM messages WHERE sender = ? OR receiver = ? OR group_id IS NOT NULL ORDER BY datetime(created_at)'
  ).all(username, username).map(deserializeMessage);
}

export async function getStatuses() {
  return db.prepare('SELECT * FROM statuses ORDER BY datetime(time)').all();
}

export async function insertStatus(status) {
  const stmt = db.prepare('INSERT INTO statuses (id, username, text, photo, time) VALUES (?, ?, ?, ?, ?)');
  const id = status.id || `status_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
  stmt.run(id, status.username, status.text || null, status.photo || null, status.time || new Date().toISOString());
  return db.prepare('SELECT * FROM statuses WHERE id = ?').get(id);
}

export async function getAds() {
  return db.prepare('SELECT * FROM ads ORDER BY datetime(time)').all();
}

export async function insertAd(ad) {
  const stmt = db.prepare('INSERT INTO ads (id, username, title, text, photo, time) VALUES (?, ?, ?, ?, ?, ?)');
  const id = ad.id || `ad_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
  stmt.run(id, ad.username, ad.title || 'Untitled', ad.text || null, ad.photo || null, ad.time || new Date().toISOString());
  return db.prepare('SELECT * FROM ads WHERE id = ?').get(id);
}

function deserializeGroup(group) {
  return {
    ...group,
    members: safeParseJson(group.members, [])
  };
}

export async function getGroups() {
  return db.prepare('SELECT * FROM groups ORDER BY datetime(created_at)').all().map(deserializeGroup);
}

export async function insertGroup(group) {
  const stmt = db.prepare('INSERT INTO groups (id, title, members, created_by, created_at) VALUES (?, ?, ?, ?, ?)');
  const id = group.id || `group_${Date.now()}`;
  stmt.run(id, group.title || 'New Group', JSON.stringify(group.members || []), group.createdBy || group.created_by || '', group.createdAt || new Date().toISOString());
  const row = db.prepare('SELECT * FROM groups WHERE id = ?').get(id);
  return deserializeGroup(row);
}

export async function getNotifications() {
  return db.prepare('SELECT * FROM notifications ORDER BY datetime(created_at)').all();
}

export async function insertNotification(notification) {
  const stmt = db.prepare('INSERT INTO notifications (id, title, text, created_at) VALUES (?, ?, ?, ?)');
  const id = notification.id || `notification_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
  stmt.run(id, notification.title || 'Notification', notification.text || null, notification.created_at || new Date().toISOString());
  return db.prepare('SELECT * FROM notifications WHERE id = ?').get(id);
}

function deserializeMessage(message) {
  return {
    ...message,
    read: Boolean(message.read),
    forwarded: Boolean(message.forwarded),
    reply_to: message.reply_to ? safeParseJson(message.reply_to, message.reply_to) : null,
    reactions: message.reactions ? safeParseJson(message.reactions, null) : null,
    groupId: message.group_id || null,
  };
}
