import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { assertRequiredEnv, config } from './config.js';
import {
  getAllUsers,
  getUserByUsername,
  getUserByEmail,
  getUserByCode,
  insertUser,
  updateUserByUsername,
  getMessagesBetween,
  insertMessage,
  deleteMessageById,
  markMessagesRead,
  getConversations,
  getStatuses,
  insertStatus,
  getAds,
  insertAd,
  getGroups,
  insertGroup,
  getNotifications,
  insertNotification
} from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const app = express();
const PORT = config.port;
const JWT_SECRET = config.jwtSecret;

try {
  assertRequiredEnv();
} catch (error) {
  console.warn('Environment validation warning:', error.message);
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https:'],
      objectSrc: ["'self'"],
      baseUri: ["'self'"]
    }
  }
}));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const allowed = config.allowedOrigins.includes(origin) || (config.frontendOrigin && origin === config.frontendOrigin);
    if (allowed) return callback(null, true);
    return callback(new Error(`Origin not allowed: ${origin}`));
  },
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, password_hash, ...rest } = user;
  return rest;
}

function generateCode(users) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const code = String(1000 + Math.floor(Math.random() * 9000));
    if (!users.some((u) => u.code === code)) return code;
  }
  return String(Date.now()).slice(-4);
}

function createToken(user) {
  return jwt.sign({ sub: user.id, username: user.username, role: user.role || 'user' }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function sortedMessages(messages) {
  return [...messages].sort((a, b) => new Date(a.created_at || a.time || 0) - new Date(b.created_at || b.time || 0));
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'bchat-backend' });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'bchat-backend' });
});

app.post('/api/auth/signup', asyncHandler(async (req, res) => {
  const { username, password, email, display_name, avatar, security_questions, device_id } = req.body || {};
  if (!username || !password || !email || !display_name || !security_questions || !Array.isArray(security_questions)) {
    return res.status(400).json({ error: 'username, password, email, display_name and security_questions are required' });
  }

  if (security_questions.length < 4 || security_questions.length > 6) {
    return res.status(400).json({ error: 'Please provide between 4 and 6 security questions.' });
  }

  const users = await getAllUsers();
  const normalizedUsername = username.trim().toLowerCase();
  const normalizedEmail = email.trim().toLowerCase();
  const exists = users.some((u) => u.username === normalizedUsername || u.email === normalizedEmail);
  if (exists) {
    return res.status(409).json({ error: 'Username or email already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: `user_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    username: normalizedUsername,
    email: normalizedEmail,
    display_name: display_name.trim(),
    avatar: avatar || null,
    role: 'user',
    code: generateCode(users),
    createdAt: new Date().toISOString(),
    passwordHash,
    security_questions: security_questions.map((q) => ({ id: q.id, question: q.question, answer: String(q.answer || '').trim() })),
    device_ids: device_id ? [String(device_id).trim()] : []
  };

  const saved = await insertUser(user);
  const token = createToken(saved);
  res.status(201).json({ token, user: sanitizeUser(saved) });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { username, password, device_id, security_answers } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const normalizedUsername = username.trim().toLowerCase();
  const user = await getUserByUsername(normalizedUsername);
  if (!user) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const knownIds = user.device_ids || [];
  const incomingDevice = device_id ? String(device_id).trim() : null;
  const isKnownDevice = incomingDevice && knownIds.includes(incomingDevice);

  if (!isKnownDevice) {
    if (!security_answers || !Array.isArray(security_answers) || security_answers.length < 4) {
      return res.status(403).json({
        error: 'New device detected. Please answer your security questions.',
        require_security: true,
        questions: (user.security_questions || []).map((q) => ({ id: q.id, question: q.question }))
      });
    }

    const validAnswers = (user.security_questions || []).every((q, idx) => {
      const answer = String(security_answers[idx] || '').trim().toLowerCase();
      return answer && answer === String(q.answer || '').trim().toLowerCase();
    });

    if (!validAnswers) {
      return res.status(403).json({ error: 'One or more security question answers are incorrect.' });
    }

    const newDeviceIds = Array.from(new Set([...(user.device_ids || []), incomingDevice]));
    await updateUserByUsername(normalizedUsername, { device_ids: newDeviceIds });
  }

  const token = createToken(user);
  res.json({ token, user: sanitizeUser(user) });
}));

app.get('/api/me', verifyToken, asyncHandler(async (req, res) => {
  const user = await getUserByUsername(req.user.username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user: sanitizeUser(user) });
}));

app.get('/api/users', verifyToken, asyncHandler(async (req, res) => {
  const { code, username, email } = req.query;
  if (code) {
    const user = await getUserByCode(String(code));
    return res.json({ user: user ? sanitizeUser(user) : null });
  }
  if (username) {
    const user = await getUserByUsername(String(username).trim().toLowerCase());
    return res.json({ user: user ? sanitizeUser(user) : null });
  }
  if (email) {
    const user = await getUserByEmail(String(email).trim().toLowerCase());
    return res.json({ user: user ? sanitizeUser(user) : null });
  }

  const users = (await getAllUsers()).map(sanitizeUser);
  res.json({ users });
}));

app.post('/api/users/profile', verifyToken, asyncHandler(async (req, res) => {
  const { avatar, display_name } = req.body || {};
  const updates = {};
  if (avatar !== undefined) updates.avatar = avatar;
  if (display_name !== undefined) updates.display_name = display_name;
  const user = await updateUserByUsername(req.user.username, updates);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: sanitizeUser(user) });
}));

app.post('/api/users/e2ee-key', verifyToken, asyncHandler(async (req, res) => {
  const { public_key } = req.body || {};
  if (!public_key) {
    return res.status(400).json({ error: 'public_key is required' });
  }
  const user = await updateUserByUsername(req.user.username, { e2ee_public_key: public_key });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
}));

app.post('/api/users/status', verifyToken, asyncHandler(async (req, res) => {
  const { is_online, last_seen } = req.body || {};
  const updates = {};
  if (is_online !== undefined) updates.is_online = Boolean(is_online);
  if (last_seen !== undefined) updates.last_seen = last_seen;
  const user = await updateUserByUsername(req.user.username, updates);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
}));

app.get('/api/messages', verifyToken, asyncHandler(async (req, res) => {
  const { user1, user2, groupId } = req.query;
  if (!groupId && (!user1 || !user2)) {
    return res.status(400).json({ error: 'user1 and user2 are required unless groupId is provided' });
  }
  const messages = await getMessagesBetween(user1, user2, groupId);
  res.json({ messages: sortedMessages(messages) });
}));

app.post('/api/messages', verifyToken, asyncHandler(async (req, res) => {
  const msg = req.body || {};
  if (!msg.sender || (!msg.receiver && !msg.groupId)) {
    return res.status(400).json({ error: 'sender and receiver/groupId are required' });
  }
  const entry = {
    ...msg,
    id: msg.id || `msg_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    created_at: msg.created_at || new Date().toISOString(),
    read: msg.read || false,
    chat_id: msg.chat_id || `chat_${Date.now()}`
  };
  const stored = await insertMessage(entry);
  res.status(201).json({ message: stored });
}));

app.post('/api/messages/delete', verifyToken, asyncHandler(async (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Message id is required' });
  await deleteMessageById(id);
  res.json({ ok: true });
}));

app.post('/api/messages/read', verifyToken, asyncHandler(async (req, res) => {
  const { sender, receiver, groupId, username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username is required' });
  await markMessagesRead({ sender, receiver, groupId, username });
  res.json({ ok: true });
}));

app.post('/api/admin/messages', verifyToken, asyncHandler(async (req, res) => {
  const { text, sender, sender_name, email } = req.body || {};
  if (!text || !sender) {
    return res.status(400).json({ error: 'Message text and sender username are required' });
  }
  const user = await getUserByUsername(String(sender).trim().toLowerCase());
  if (!user) {
    return res.status(404).json({ error: 'User not found. Please use a registered username.' });
  }
  const entry = {
    id: `admin_msg_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    type: 'admin_contact',
    text: String(text).trim(),
    sender: String(sender).trim().toLowerCase(),
    sender_name: String(sender_name || user.display_name || sender),
    email: String(email || user.email || ''),
    created_at: new Date().toISOString(),
    read: false
  };
  const stored = await insertMessage(entry);
  res.status(201).json({ message: stored });
}));

app.post('/api/admin/create', asyncHandler(async (req, res) => {
  const requestedUsername = String(req.body?.username || config.adminUsername).trim().toLowerCase();
  const existing = await getUserByUsername(requestedUsername);
  if (existing) {
    return res.json({ user: sanitizeUser(existing) });
  }
  if (!config.adminPassword) {
    return res.status(500).json({ error: 'Admin bootstrap is disabled because ADMIN_PASSWORD was not configured.' });
  }
  const users = await getAllUsers();
  const passwordHash = await bcrypt.hash(config.adminPassword, 12);
  const user = {
    id: `user_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    username: requestedUsername,
    email: req.body?.email || `${requestedUsername}@bchat.local`,
    display_name: 'Admin',
    avatar: null,
    role: 'admin',
    code: generateCode(users),
    createdAt: new Date().toISOString(),
    passwordHash,
    security_questions: [],
    device_ids: []
  };
  const saved = await insertUser(user);
  res.status(201).json({ user: sanitizeUser(saved) });
}));

app.get('/api/conversations', verifyToken, asyncHandler(async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'username is required' });
  const messages = await getConversations(username);
  res.json({ messages: sortedMessages(messages) });
}));

app.get('/api/statuses', verifyToken, asyncHandler(async (req, res) => {
  const statuses = await getStatuses();
  res.json({ statuses });
}));

app.post('/api/statuses', verifyToken, asyncHandler(async (req, res) => {
  const status = req.body || {};
  const saved = await insertStatus({ ...status, time: status.time || new Date().toISOString() });
  res.json({ status: saved });
}));

app.get('/api/ads', verifyToken, asyncHandler(async (req, res) => {
  const ads = await getAds();
  res.json({ ads });
}));

app.post('/api/ads', verifyToken, asyncHandler(async (req, res) => {
  const ad = req.body || {};
  const saved = await insertAd({ ...ad, time: ad.time || new Date().toISOString() });
  res.json({ ad: saved });
}));

app.get('/api/groups', verifyToken, asyncHandler(async (req, res) => {
  const groups = await getGroups();
  res.json({ groups });
}));

app.post('/api/groups', verifyToken, asyncHandler(async (req, res) => {
  const group = req.body || {};
  const saved = await insertGroup({
    id: group.id || `group_${Date.now()}`,
    title: group.title || 'New Group',
    members: group.members || [],
    createdBy: group.createdBy || req.user.username,
    createdAt: new Date().toISOString()
  });
  res.status(201).json({ group: saved });
}));

app.get('/api/notifications', verifyToken, asyncHandler(async (req, res) => {
  const notifications = await getNotifications();
  res.json({ notifications });
}));

app.post('/api/notifications', verifyToken, asyncHandler(async (req, res) => {
  const notification = req.body || {};
  const saved = await insertNotification({ ...notification, created_at: notification.createdAt || new Date().toISOString() });
  res.status(201).json({ notification: saved });
}));

app.post('/api/ai/chat', verifyToken, asyncHandler(async (req, res) => {
  const { messages = [] } = req.body || {};
  const last = Array.isArray(messages) ? messages[messages.length - 1]?.content || '' : '';
  if (!last) return res.status(400).json({ error: 'A message is required' });
  const lower = String(last).toLowerCase();
  if (lower.includes('image') || lower.includes('picture') || lower.includes('photo')) {
    return res.json({ reply: '🎨 I can help generate image prompts, but the actual image rendering is handled by the public image route. I can still help you craft the perfect prompt.' });
  }
  if (lower.includes('hello') || lower.includes('hi')) {
    return res.json({ reply: 'Hello! Your request reached the protected backend safely. I can help with short answers, summaries, or follow-up prompts.' });
  }
  if (lower.includes('weather')) {
    return res.json({ reply: 'I can help with general advice, but I do not have live weather access from this backend.' });
  }
  return res.json({ reply: `Secure backend response: ${String(last).slice(0, 180)}` });
}));

app.use((err, _req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  console.error('Request error:', err);
  const status = err && typeof err.status === 'number' ? err.status : 500;
  const message = err && err.message ? err.message : 'Internal server error';
  res.status(status).json({ error: message });
});

const frontendDir = path.join(rootDir, 'frontend');
app.use(express.static(frontendDir));
app.get('*', (_req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

async function seedAdminAccount() {
  if (!config.adminPassword) {
    console.log('Admin bootstrap skipped because ADMIN_PASSWORD is not configured.');
    return;
  }

  try {
    const existing = await getUserByUsername(config.adminUsername);
    if (existing) return;
    const users = await getAllUsers();
    const passwordHash = await bcrypt.hash(config.adminPassword, 12);
    const user = {
      id: `user_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      username: config.adminUsername,
      email: `${config.adminUsername}@bchat.local`,
      display_name: 'Admin',
      avatar: null,
      role: 'admin',
      code: generateCode(users),
      createdAt: new Date().toISOString(),
      passwordHash,
      security_questions: [],
      device_ids: []
    };
    await insertUser(user);
    console.log(`Admin account seeded for ${config.adminUsername}`);
  } catch (error) {
    console.warn('Admin bootstrap skipped due to startup error:', error.message);
  }
}

async function startServer() {
  await seedAdminAccount();
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`B CHAT backend listening on http://0.0.0.0:${PORT}`);
  });

  server.on('error', (error) => {
    console.error('Failed to start server', error);
    process.exit(1);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server', err);
  process.exit(1);
});
