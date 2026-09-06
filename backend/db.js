import { supabase } from './config.js';

console.log('Database: Supabase PostgreSQL');

function tryParseJson(value, fallback = null) {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeMembers(value) {
  if (Array.isArray(value)) return value;
  if (!value) return [];
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function normalizeReplyTo(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
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
    createdAt: user.created_at || user.createdAt,
    passwordHash: user.password_hash || user.passwordHash,
    is_online: Boolean(user.is_online),
    last_seen: user.last_seen,
    security_questions: Array.isArray(user.security_questions)
      ? user.security_questions
      : tryParseJson(user.security_questions, []),
    device_ids: Array.isArray(user.device_ids)
      ? user.device_ids
      : tryParseJson(user.device_ids, []),
    bio: user.bio || ''
  };
}

function normalizeMessage(message) {
  if (!message) return null;
  return {
    ...message,
    read: Boolean(message.is_read || message.read),
    forwarded: Boolean(message.forwarded),
    reply_to: normalizeReplyTo(message.reply_to || null),
    reactions: message.reactions || null,
    groupId: message.group_id || message.groupId || null
  };
}

function normalizeGroup(group) {
  if (!group) return null;
  return {
    ...group,
    members: normalizeMembers(group.members),
    created_at: group.created_at || group.createdAt
  };
}

function convertUserInput(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    display_name: user.display_name,
    avatar: user.avatar || null,
    role: user.role || 'user',
    code: user.code,
    created_at: user.createdAt || user.created_at,
    password_hash: user.passwordHash || user.password_hash,
    is_online: Boolean(user.is_online),
    last_seen: user.last_seen || null,
    security_questions: user.security_questions || [],
    device_ids: user.device_ids || [],
    bio: user.bio || ''
  };
}

function convertMessageInput(msg) {
  return {
    id: msg.id,
    type: msg.type || 'text',
    sender: msg.sender,
    receiver: msg.receiver || null,
    group_id: msg.groupId || msg.group_id || null,
    text: msg.text || null,
    photo: msg.photo || null,
    voice_data: msg.voice_data || msg.voiceData || null,
    voice_duration: msg.voice_duration || msg.voiceDuration || null,
    created_at: msg.created_at || msg.time || new Date().toISOString(),
    is_read: Boolean(msg.read),
    chat_id: msg.chat_id || null,
    forwarded: Boolean(msg.forwarded),
    sender_name: msg.sender_name || null,
    email: msg.email || null,
    reply_to: typeof msg.reply_to === 'string' ? msg.reply_to : msg.reply_to ? JSON.stringify(msg.reply_to) : null,
    reactions: msg.reactions || null
  };
}

async function fromSupabase(table, queryBuilder) {
  if (!supabase) {
    throw new Error('Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
  }
  const builder = queryBuilder(supabase.from(table));
  const { data, error } = await builder;
  if (error) throw error;
  return data;
}

export async function getAllUsers() {
  const data = await fromSupabase('users', (q) => q.select('*'));
  return data.map(normalizeUser);
}

export async function getUserByUsername(username) {
  if (!username) return null;
  const data = await fromSupabase('users', (q) => q.select('*').eq('username', username).maybeSingle());
  return normalizeUser(data);
}

export async function getUserByEmail(email) {
  if (!email) return null;
  const data = await fromSupabase('users', (q) => q.select('*').eq('email', email).maybeSingle());
  return normalizeUser(data);
}

export async function getUserByCode(code) {
  if (!code) return null;
  const data = await fromSupabase('users', (q) => q.select('*').eq('code', code).maybeSingle());
  return normalizeUser(data);
}

export async function insertUser(user) {
  const payload = convertUserInput(user);
  const { data, error } = await supabase.from('users').insert(payload).select().single();
  if (error) throw error;
  return normalizeUser(data);
}

export async function updateUserByUsername(username, fields) {
  if (!username || !fields || !Object.keys(fields).length) return null;
  const updatePayload = { ...fields };
  if (fields.security_questions) updatePayload.security_questions = fields.security_questions;
  if (fields.device_ids) updatePayload.device_ids = fields.device_ids;
  const { data, error } = await supabase
    .from('users')
    .update(updatePayload)
    .eq('username', username)
    .select()
    .maybeSingle();
  if (error) throw error;
  return normalizeUser(data);
}

export async function insertMessage(msg) {
  const payload = convertMessageInput(msg);
  const { data, error } = await supabase.from('messages').insert(payload).select().single();
  if (error) throw error;
  return normalizeMessage(data);
}

export async function getMessageById(id) {
  const data = await fromSupabase('messages', (q) => q.select('*').eq('id', id).maybeSingle());
  return normalizeMessage(data);
}

export async function getMessagesBetween(user1, user2, groupId) {
  if (groupId) {
    const data = await fromSupabase('messages', (q) => q.select('*').eq('group_id', groupId).order('created_at'));
    return data.map(normalizeMessage);
  }
  if (!user1 || !user2) return [];
  const orFilter = `and(sender.eq.${user1},receiver.eq.${user2}),and(sender.eq.${user2},receiver.eq.${user1})`;
  const data = await fromSupabase('messages', (q) => q.select('*').or(orFilter).order('created_at'));
  return data.map(normalizeMessage);
}

export async function deleteMessageById(id) {
  const { error } = await supabase.from('messages').delete().eq('id', id);
  if (error) throw error;
  return true;5
}

export async function markMessagesRead({ sender, receiver, groupId, username }) {
  if (groupId) {
    const { error } = await supabase
      .from('messages')
      .update({ is_read: true })
      .eq('group_id', groupId)
      .eq('receiver', username)
      .neq('sender', username);
    if (error) throw error;
    return true;
  }
  if (!sender || !receiver) return false;
  const { error } = await supabase.from('messages').update({ is_read: true }).eq('sender', sender).eq('receiver', receiver);
  if (error) throw error;
  return true;
}

export async function getConversations(username) {
  const orFilter = `sender.eq.${username},receiver.eq.${username},group_id.not.eq.null`;
  const data = await fromSupabase('messages', (q) => q.select('*').or(orFilter).order('created_at'));
  return data.map(normalizeMessage);
}

export async function getStatuses() {
  const data = await fromSupabase('statuses', (q) => q.select('*').order('time'));
  return data;
}

export async function insertStatus(status) {
  const payload = {
    id: status.id,
    username: status.username,
    text: status.text || null,
    photo: status.photo || null,
    time: status.time || new Date().toISOString()
  };
  const { data, error } = await supabase.from('statuses').insert(payload).select().single();
  if (error) throw error;
  return data;
}

export async function getAds() {
  const data = await fromSupabase('ads', (q) => q.select('*').order('time'));
  return data;
}

export async function insertAd(ad) {
  const payload = {
    id: ad.id,
    username: ad.username,
    title: ad.title || 'Untitled',
    text: ad.text || null,
    photo: ad.photo || null,
    time: ad.time || new Date().toISOString()
  };
  const { data, error } = await supabase.from('ads').insert(payload).select().single();
  if (error) throw error;
  return data;
}

export async function getGroups() {
  const data = await fromSupabase('groups', (q) => q.select('*').order('created_at'));
  return data.map(normalizeGroup);
}

export async function insertGroup(group) {
  const payload = {
    id: group.id,
    title: group.title || 'New Group',
    members: group.members || [],
    created_by: group.created_by || group.createdBy || '',
    created_at: group.created_at || group.createdAt || new Date().toISOString()
  };
  const { data, error } = await supabase.from('groups').insert(payload).select().single();
  if (error) throw error;
  return normalizeGroup(data);
}

export async function getNotifications() {
  const data = await fromSupabase('notifications', (q) => q.select('*').order('created_at'));
  return data;
}

export async function insertNotification(notification) {
  const payload = {
    id: notification.id,
    title: notification.title || 'Notification',
    text: notification.text || null,
    created_at: notification.created_at || notification.createdAt || new Date().toISOString()
  };
  const { data, error } = await supabase.from('notifications').insert(payload).select().single();
  if (error) throw error;
  return data;
}
