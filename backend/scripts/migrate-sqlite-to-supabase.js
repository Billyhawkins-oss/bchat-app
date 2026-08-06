import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sqliteFile = process.env.SQLITE_DB_FILE || path.join(__dirname, '..', 'bchat.sqlite');
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

function fail(message) {
  console.error('Migration failed:', message);
  process.exit(1);
}

function parseJson(value, fallback) {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeTimestamp(value) {
  if (!value) return new Date().toISOString();
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString();
  }
  return date.toISOString();
}

if (!supabaseUrl || !supabaseKey) {
  fail('Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your environment. Example:\n  SUPABASE_URL=https://your-project.supabase.co SUPABASE_SERVICE_ROLE_KEY=your-service-role-key node migrate-sqlite-to-supabase.js');
}

const db = new Database(sqliteFile, { readonly: true });
const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false
  }
});

async function migrateUsers() {
  const rows = db.prepare('SELECT * FROM users').all();
  if (!rows.length) {
    console.log('No users found to migrate.');
    return;
  }

  const users = rows.map((row) => ({
    id: row.id,
    username: row.username,
    email: row.email,
    display_name: row.display_name,
    avatar: row.avatar || null,
    role: row.role || 'user',
    code: row.code,
    created_at: normalizeTimestamp(row.created_at),
    password_hash: row.password_hash,
    is_online: Boolean(row.is_online),
    last_seen: row.last_seen ? normalizeTimestamp(row.last_seen) : null,
    e2ee_public_key: row.e2ee_public_key || null,
    security_questions: parseJson(row.security_questions, []),
    device_ids: parseJson(row.device_ids, []),
    bio: row.bio || ''
  }));

  const { error } = await supabase.from('users').upsert(users, { onConflict: ['id'] });
  if (error) fail(error.message);
  console.log(`Migrated ${users.length} users.`);
}

async function migrateMessages() {
  const rows = db.prepare('SELECT * FROM messages').all();
  if (!rows.length) {
    console.log('No messages found to migrate.');
    return;
  }

  const messages = rows.map((row) => ({
    id: row.id,
    type: row.type || 'text',
    sender: row.sender,
    receiver: row.receiver || null,
    group_id: row.group_id || null,
    text: row.text || null,
    photo: row.photo || null,
    voice_data: row.voice_data || null,
    voice_duration: row.voice_duration || null,
    created_at: normalizeTimestamp(row.created_at),
    is_read: Boolean(row.read),
    chat_id: row.chat_id || null,
    forwarded: Boolean(row.forwarded),
    sender_name: row.sender_name || null,
    email: row.email || null,
    reply_to: typeof row.reply_to === 'string' ? row.reply_to : JSON.stringify(row.reply_to || null),
    reactions: parseJson(row.reactions, null)
  }));

  const { error } = await supabase.from('messages').upsert(messages, { onConflict: ['id'] });
  if (error) fail(error.message);
  console.log(`Migrated ${messages.length} messages.`);
}

async function migrateStatuses() {
  const rows = db.prepare('SELECT * FROM statuses').all();
  if (!rows.length) {
    console.log('No statuses found to migrate.');
    return;
  }

  const statuses = rows.map((row) => ({
    id: row.id,
    username: row.username,
    text: row.text || null,
    photo: row.photo || null,
    time: normalizeTimestamp(row.time)
  }));

  const { error } = await supabase.from('statuses').upsert(statuses, { onConflict: ['id'] });
  if (error) fail(error.message);
  console.log(`Migrated ${statuses.length} statuses.`);
}

async function migrateAds() {
  const rows = db.prepare('SELECT * FROM ads').all();
  if (!rows.length) {
    console.log('No ads found to migrate.');
    return;
  }

  const ads = rows.map((row) => ({
    id: row.id,
    username: row.username,
    title: row.title || null,
    text: row.text || null,
    photo: row.photo || null,
    time: normalizeTimestamp(row.time)
  }));

  const { error } = await supabase.from('ads').upsert(ads, { onConflict: ['id'] });
  if (error) fail(error.message);
  console.log(`Migrated ${ads.length} ads.`);
}

async function migrateGroups() {
  const rows = db.prepare('SELECT * FROM groups').all();
  if (!rows.length) {
    console.log('No groups found to migrate.');
    return;
  }

  const groups = rows.map((row) => ({
    id: row.id,
    title: row.title || 'New Group',
    members: parseJson(row.members, []),
    created_by: row.created_by,
    created_at: normalizeTimestamp(row.created_at)
  }));

  const { error } = await supabase.from('groups').upsert(groups, { onConflict: ['id'] });
  if (error) fail(error.message);
  console.log(`Migrated ${groups.length} groups.`);
}

async function migrateNotifications() {
  const rows = db.prepare('SELECT * FROM notifications').all();
  if (!rows.length) {
    console.log('No notifications found to migrate.');
    return;
  }

  const notifications = rows.map((row) => ({
    id: row.id,
    title: row.title || 'Notification',
    text: row.text || null,
    created_at: normalizeTimestamp(row.created_at)
  }));

  const { error } = await supabase.from('notifications').upsert(notifications, { onConflict: ['id'] });
  if (error) fail(error.message);
  console.log(`Migrated ${notifications.length} notifications.`);
}

async function migrate() {
  console.log('Starting SQLite → Supabase migration');
  console.log('SQLite source:', sqliteFile);
  await migrateUsers();
  await migrateGroups();
  await migrateMessages();
  await migrateStatuses();
  await migrateAds();
  await migrateNotifications();
  console.log('Migration completed successfully.');
}

migrate().catch((error) => {
  console.error('Migration error:', error.message || error);
  process.exit(1);
});
