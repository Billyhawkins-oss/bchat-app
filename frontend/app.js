// ═══════════════════════════════════════════
// B CHAT — Local-first app with End-to-End Encryption
// ═══════════════════════════════════════════

const $ = (id) => document.getElementById(id);

// ═══════════════════════════════════════════
// E2EE — End-to-End Encryption
// ═══════════════════════════════════════════
// Messages are encrypted client-side before leaving the device.
// Even the server, database, and admin CANNOT read them.
// Only the sender and the intended receiver can decrypt.
// ═══════════════════════════════════════════

const E2EE_KEY_STORAGE_PREFIX = 'bchat_e2ee_';

function getE2EEKey(username) {
  const raw = localStorage.getItem(E2EE_KEY_STORAGE_PREFIX + username);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function saveE2EEKey(username, keyData) {
  localStorage.setItem(E2EE_KEY_STORAGE_PREFIX + username, JSON.stringify(keyData));
}

function clearE2EEKeys() {
  Object.keys(localStorage)
    .filter(k => k.startsWith(E2EE_KEY_STORAGE_PREFIX))
    .forEach(k => localStorage.removeItem(k));
}

// Generate an RSA-OAEP key pair for the user
async function generateE2EEKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
  return keyPair;
}

// Export public key to base64 string for storage/sharing
async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey('spki', publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Export private key encrypted with a password-derived key
async function exportEncryptedPrivateKey(privateKey, password) {
  // Derive a 256-bit AES key from the password using PBKDF2
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;
  const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    pwKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // Export private key as PKCS8
  const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', privateKey);

  // Encrypt with AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, privateKeyRaw);

  // Package: salt + iv + encrypted data
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  return btoa(String.fromCharCode(...combined));
}

// Import private key from encrypted storage using password
async function importEncryptedPrivateKey(encryptedB64, password) {
  try {
    const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const encryptedData = combined.slice(28);

    // Re-derive AES key from password
    const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );

    // Decrypt
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encryptedData);

    // Import as private key
    return await crypto.subtle.importKey('pkcs8', decrypted, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
  } catch (e) {
    console.error('Failed to decrypt private key:', e);
    return null;
  }
}

// Import a public key from base64 SPKI format
async function importPublicKey(publicKeyB64) {
  try {
    const raw = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey('spki', raw, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  } catch (e) {
    console.error('Failed to import public key:', e);
    return null;
  }
}

// Encrypt a message for a specific receiver
async function e2eeEncrypt(plaintext, receiverPublicKeyB64) {
  if (!receiverPublicKeyB64) return null; // cannot encrypt

  // Generate a one-time AES-GCM symmetric key
  const symKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the plaintext with the symmetric key
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, symKey, encoded);

  // Export and encrypt the symmetric key with the receiver's RSA public key
  const symKeyRaw = await crypto.subtle.exportKey('raw', symKey);
  const pubKey = await importPublicKey(receiverPublicKeyB64);
  if (!pubKey) return null;
  const encryptedSymKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, symKeyRaw);

  return {
    ct: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
    ek: btoa(String.fromCharCode(...new Uint8Array(encryptedSymKey))),
  };
}

// Decrypt a message using the user's private key
async function e2eeDecrypt(packet, privateKey) {
  if (!packet || !packet.ct || !packet.iv || !packet.ek) return null;
  try {
    const ciphertext = Uint8Array.from(atob(packet.ct), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(packet.iv), c => c.charCodeAt(0));
    const encryptedSymKey = Uint8Array.from(atob(packet.ek), c => c.charCodeAt(0));

    // Decrypt the symmetric key with the private key
    const symKeyRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedSymKey);
    const symKey = await crypto.subtle.importKey('raw', symKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);

    // Decrypt the message
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, symKey, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error('E2EE decrypt failed:', e);
    return null;
  }
}

// Encrypt a binary/photo as base64 using a one-time AES-GCM key
async function e2eeEncryptBinary(dataB64, receiverPublicKeyB64) {
  if (!receiverPublicKeyB64) return null;
  const raw = Uint8Array.from(atob(dataB64), c => c.charCodeAt(0));
  const symKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, symKey, raw);
  const symKeyRaw = await crypto.subtle.exportKey('raw', symKey);
  const pubKey = await importPublicKey(receiverPublicKeyB64);
  if (!pubKey) return null;
  const encryptedSymKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, symKeyRaw);
  return {
    ct: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
    ek: btoa(String.fromCharCode(...new Uint8Array(encryptedSymKey))),
  };
}

async function e2eeDecryptBinary(packet, privateKey) {
  if (!packet || !packet.ct || !packet.iv || !packet.ek) return null;
  try {
    const ciphertext = Uint8Array.from(atob(packet.ct), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(packet.iv), c => c.charCodeAt(0));
    const encryptedSymKey = Uint8Array.from(atob(packet.ek), c => c.charCodeAt(0));
    const symKeyRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedSymKey);
    const symKey = await crypto.subtle.importKey('raw', symKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, symKey, ciphertext);
    return btoa(String.fromCharCode(...new Uint8Array(decrypted)));
  } catch (e) {
    console.error('E2EE binary decrypt failed:', e);
    return null;
  }
}

// Get or create E2EE keys for the current user
let _e2eePrivateKey = null;

async function ensureE2EEKeys(username, password) {
  const stored = getE2EEKey(username);
  if (stored && stored.encryptedPrivateKey && stored.publicKey) {
    // Try to decrypt the private key
    _e2eePrivateKey = await importEncryptedPrivateKey(stored.encryptedPrivateKey, password);
    if (_e2eePrivateKey) {
      return { publicKey: stored.publicKey, privateKey: _e2eePrivateKey };
    }
    // If decryption fails, password might have changed — regenerate
    console.warn('E2EE: Failed to decrypt private key, generating new pair');
  }

  // Generate new key pair
  const keyPair = await generateE2EEKeyPair();
  const publicKeyB64 = await exportPublicKey(keyPair.publicKey);
  const encryptedPrivateKey = await exportEncryptedPrivateKey(keyPair.privateKey, password);

  saveE2EEKey(username, {
    publicKey: publicKeyB64,
    encryptedPrivateKey: encryptedPrivateKey,
  });

  _e2eePrivateKey = keyPair.privateKey;

  // Upload public key to backend
  try {
    await apiJson('/api/users/e2ee-key', {
      method: 'POST',
      body: JSON.stringify({ public_key: publicKeyB64 })
    });
  } catch (e) {
    console.warn('Failed to upload E2EE public key:', e);
  }

  return { publicKey: publicKeyB64, privateKey: keyPair.privateKey };
}

async function fetchUserPublicKey(username) {
  try {
    const data = await apiJson(`/api/users?username=${encodeURIComponent(username)}`);
    if (data?.user?.e2ee_public_key) return data.user.e2ee_public_key;
    // Try fetching all users and finding the one
    const allData = await apiJson('/api/users');
    const user = (allData?.users || []).find(u => u.username === username);
    return user?.e2ee_public_key || null;
  } catch {
    return null;
  }
}

// ── Supabase Client ──
// Uses the runtime configuration supplied by the frontend build or deployment.
const SUPABASE_URL = window.__BCHAT_CONFIG__?.SUPABASE_URL || '';
const SUPABASE_ANON_KEY = window.__BCHAT_CONFIG__?.SUPABASE_ANON_KEY || '';
let sb = null;
try {
    if (window.supabase && window.supabase.createClient && SUPABASE_URL && SUPABASE_ANON_KEY) {
        sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
            auth: {
                autoRefreshToken: true,
                persistSession: true,
                detectSessionInUrl: true
            }
        });
    }
} catch (err) {
    sb = null;
    console.warn('Supabase init failed:', err);
}

// Express backend base URL (defaults to the configured production API endpoint)
const API_BASE_URL = window.__BCHAT_CONFIG__?.API_BASE_URL || '';

async function apiJson(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    // Try Supabase session token first, fallback to stored custom token
    let token = getStoredToken();
    if (sb) {
        try {
            const { data: { session } } = await sb.auth.getSession();
            if (session?.access_token) token = session.access_token;
        } catch (e) {}
    }
    if (token) headers.Authorization = `Bearer ${token}`;
    // If no base URL (deployed on Netlify), the path must be a full URL or relative
    const url = `${API_BASE_URL}${path}`;
    try {
        const res = await fetch(url, { ...options, headers });
        const data = await res.json().catch(() => null);
        if (!res.ok) throw new Error(data?.error || 'Request failed');
        return data;
    } catch (err) {
        // If backend is not reachable (deployed without it), throw clearly
        throw err;
    }
}

function getStoredToken() { return localStorage.getItem('bchat_backend_token') || ''; }
function setStoredToken(token) {
    if (token) localStorage.setItem('bchat_backend_token', token);
    else localStorage.removeItem('bchat_backend_token');
}
function clearStoredToken() { localStorage.removeItem('bchat_backend_token'); }

function getPendingMessages() {
    const key = 'bchat_pending_messages_' + (currentUser?.username || 'guest');
    return JSON.parse(localStorage.getItem(key) || '[]');
}

function savePendingMessages(messages) {
    const key = 'bchat_pending_messages_' + (currentUser?.username || 'guest');
    localStorage.setItem(key, JSON.stringify(messages));
}

function getConversationKey(user1, user2) {
    return 'bchat_msgs_cache_' + [user1, user2].sort().join('_');
}

function mergeConversationMessages(baseMessages, extraMessages) {
    const merged = [...baseMessages];
    extraMessages.forEach((msg) => {
        const exists = merged.some((entry) => {
            if (entry.id && msg.id && entry.id === msg.id) return true;
            return entry.created_at === msg.created_at && entry.sender === msg.sender && entry.receiver === msg.receiver && entry.text === msg.text;
        });
        if (!exists) merged.push(msg);
    });
    return merged.sort((a, b) => new Date(a.created_at || a.time || 0) - new Date(b.created_at || b.time || 0));
}

function persistMessageToLocalCaches(message) {
    const entry = {
        ...message,
        id: message.id || `local_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        created_at: message.created_at || message.time || new Date().toISOString(),
        pending: message.pending !== false
    };

    const convoKey = getConversationKey(entry.sender, entry.receiver);
    const localConvoMessages = JSON.parse(localStorage.getItem(convoKey) || '[]');
    if (!localConvoMessages.some((item) => item.id === entry.id)) {
        localConvoMessages.push(entry);
        localStorage.setItem(convoKey, JSON.stringify(localConvoMessages));
    }

    const allMessages = JSON.parse(localStorage.getItem('bchat_all_msgs_cache') || '[]');
    if (!allMessages.some((item) => item.id === entry.id)) {
        allMessages.push(entry);
        localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(allMessages));
    }

    return entry;
}

function addPendingMessage(message) {
    const pending = getPendingMessages();
    if (!pending.some((entry) => entry.id === message.id)) {
        pending.push(message);
        savePendingMessages(pending);
    }
}

function removePendingMessage(messageId) {
    const pending = getPendingMessages().filter((entry) => entry.id !== messageId);
    savePendingMessages(pending);
}

async function syncPendingMessages() {
    if (!navigator.onLine || !currentUser) return;
    const pending = getPendingMessages();
    if (!pending.length) return;

    const stillPending = [];
    for (const message of pending) {
        try {
            const { decryptedText, ...networkMessage } = message;
            const data = await apiJson('/api/messages', { method: 'POST', body: JSON.stringify(networkMessage) });
            const synced = data?.message || message;
            persistMessageToLocalCaches({ ...synced, pending: false });
            removePendingMessage(message.id);
        } catch (err) {
            stillPending.push(message);
        }
    }

    if (stillPending.length !== pending.length) {
        savePendingMessages(stillPending);
    }
}

function makeSessionId() {
    return (crypto.randomUUID?.() || ('sess_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2)));
}
const ANALYTICS_SESSION_ID = localStorage.getItem('bchat_analytics_session') || makeSessionId();
localStorage.setItem('bchat_analytics_session', ANALYTICS_SESSION_ID);
let analyticsHeartbeatTimer = null;
let notificationPollTimer = null;

function appSurface() {
    return isStandalone() ? 'installed_app' : 'web_app';
}

async function recordAnalyticsEvent(eventType, meta = {}) {
    if (!navigator.onLine) return;
    try {
        const entry = {
            event_type: eventType,
            username: currentUser?.username || null,
            platform: appSurface(),
            session_id: ANALYTICS_SESSION_ID,
            meta: meta,
            created_at: new Date().toISOString()
        };
        const key = 'bchat_analytics_' + ANALYTICS_SESSION_ID;
        const history = JSON.parse(localStorage.getItem(key) || '[]');
        history.push(entry);
        localStorage.setItem(key, JSON.stringify(history.slice(-30)));
    } catch (err) {
        // Analytics is optional and should never block the app.
    }
}

function startUsageAnalytics() {
    recordAnalyticsEvent('usage_heartbeat');
    clearInterval(analyticsHeartbeatTimer);
    analyticsHeartbeatTimer = setInterval(() => recordAnalyticsEvent('usage_heartbeat'), 180000);
}

async function pollAdminNotifications() {
    if (!navigator.onLine || !currentUser) return;
    try {
        const data = await apiJson('/api/notifications');
        const items = (data?.notifications || []).filter(n => String(n.title || '').toLowerCase().startsWith('notification:'));
        const seen = JSON.parse(localStorage.getItem('bchat_seen_notifications') || '[]');
        items.slice().reverse().forEach(n => {
            const key = String(n.id || n.createdAt || n.title);
            if (seen.includes(key)) return;
            seen.push(key);
            showToast((n.title || 'Notification').replace(/^Notification:\s*/i, '') + (n.text ? ' — ' + n.text : ''), 'info', 9000);
        });
        localStorage.setItem('bchat_seen_notifications', JSON.stringify(seen.slice(-80)));
    } catch (err) {
        // Broadcast polling is optional and should never block chat usage.
    }
}

function startNotificationPolling() {
    pollAdminNotifications();
    clearInterval(notificationPollTimer);
    notificationPollTimer = setInterval(pollAdminNotifications, 180000);
}

// ── Toast notifications + global offline banner ──
function showToast(message, type = 'info', duration = 3000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

function updateOfflineBanner() {
    let banner = document.getElementById('global-offline-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'global-offline-banner';
        banner.className = 'global-offline-banner';
        banner.innerHTML = "📴 You're offline — messages and AI need an internet connection.";
        document.body.appendChild(banner);
    }
    banner.classList.toggle('hidden', navigator.onLine);
}

// Returns true if online; otherwise warns the user and returns false.
function requireOnline(action = 'do this') {
    if (navigator.onLine) return true;
    showToast("📴 You're offline — connect to the internet to " + action + '.', 'error');
    return false;
}

window.addEventListener('online', () => { updateOfflineBanner(); showToast('✅ Back online', 'success'); syncPendingMessages(); });
window.addEventListener('offline', () => { updateOfflineBanner(); showToast("📴 You went offline", 'error', 4000); });
updateOfflineBanner();

// ── Install app ("Add to Home Screen") ──
let deferredInstallPrompt = null;
let installAvailable = false;
function isStandalone() {
    return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}
function showInstallButton() {
    if (isStandalone()) return;
    let btn = document.getElementById('install-btn');
    if (!btn) {
        btn = document.createElement('button');
        btn.id = 'install-btn';
        btn.className = 'install-btn';
        btn.addEventListener('click', doInstall);
        document.body.appendChild(btn);
    }
    btn.textContent = deferredInstallPrompt ? '📲 Install B CHAT' : '📲 Add B CHAT to Home Screen';
    const onAuth = loginScreen.classList.contains('active') || signupScreen.classList.contains('active');
    btn.classList.toggle('on-auth', onAuth);
    btn.classList.add('show');
}
function hideInstallButton() {
    document.getElementById('install-btn')?.classList.remove('show');
}
async function doInstall() {
    if (deferredInstallPrompt) {
        const btn = document.getElementById('install-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Opening installer…';
        }
        deferredInstallPrompt.prompt();
        const { outcome } = await deferredInstallPrompt.userChoice;
        deferredInstallPrompt = null;
        installAvailable = false;
        if (outcome === 'accepted') {
            hideInstallButton();
            showToast('B CHAT is installing now.', 'success', 5000);
        } else {
            if (btn) {
                btn.disabled = false;
                btn.textContent = '📲 Install B CHAT';
            }
            showToast('Install was cancelled. Tap Install when you are ready.', 'info', 5000);
        }
    } else if (/iphone|ipad|ipod/i.test(navigator.userAgent)) {
        showToast('📲 Tap the Share icon (□↑) then "Add to Home Screen".', 'info', 8000);
    } else if (/android/i.test(navigator.userAgent)) {
        showToast('📲 Tap the ⋮ menu, then "Install app" / "Add to Home screen".', 'info', 8000);
    } else {
        showToast('📲 In Chrome: click the ⋮ menu → "Cast, save, and share" → "Install page as app…". Or click the install icon at the right end of the address bar.', 'info', 11000);
    }
}

const _isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    installAvailable = true;
    showInstallButton();
});
window.addEventListener('appinstalled', () => {
    hideInstallButton();
    deferredInstallPrompt = null;
    installAvailable = false;
    recordAnalyticsEvent('app_installed');
});
// iOS never fires beforeinstallprompt — show the button so users get the Add-to-Home-Screen hint.
if (_isIOS && !isStandalone()) setTimeout(() => { showInstallButton(); }, 500);

// ── Password/show-hide toggles ──
document.addEventListener('click', (event) => {
    const btn = event.target.closest('.pw-toggle');
    if (!btn) return;
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    btn.textContent = reveal ? '🙈' : '👁';
    btn.setAttribute('aria-label', reveal ? 'Hide answer' : 'Show answer');
});

// ── Password strength meter (signup) ──
function scorePassword(pw) {
    let score = 0;
    if (pw.length >= 4) score++;
    if (pw.length >= 8) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(score, 4);
}
function isValidEmail(email) {
    if (!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$/.test(email)) return false;
    const [local, domain] = email.split('@');
    if (!local || !domain || local.length > 64 || domain.length > 253) return false;
    if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
    if (domain.includes('..')) return false;
    return domain.split('.').every(part => /^[A-Za-z0-9-]+$/.test(part) && !part.startsWith('-') && !part.endsWith('-'));
}
function validateSignupPassword(password) {
    if (!password) return 'Enter a password.';
    if (/\s/.test(password)) return 'Password cannot contain spaces.';
    if (password.length < 6) return 'Password must be at least 6 characters.';
    if (password.length > 128) return 'Password must be 128 characters or fewer.';
    return '';
}
function validateDisplayName(display) {
    if (display.length < 2) return 'Display name must be at least 2 characters.';
    if (display.length > 40) return 'Display name must be 40 characters or fewer.';
    return '';
}
function validateUsername(username) {
    if (username.length < 3) return 'Username must be at least 3 characters.';
    if (username.length > 20) return 'Username must be 20 characters or fewer.';
    if (/[^a-z0-9_]/.test(username)) return 'Username: letters, numbers, underscores only.';
    if (/^_+$/.test(username)) return 'Username cannot be only underscores.';
    return '';
}
const _signupPwInput = document.getElementById('signup-start-password');
if (_signupPwInput) {
    _signupPwInput.addEventListener('input', () => {
        const meter = document.getElementById('pw-strength');
        if (!meter) return;
        const bar = meter.querySelector('.pw-strength-bar');
        const label = meter.querySelector('.pw-strength-label');
        if (!_signupPwInput.value) { meter.classList.add('hidden'); return; }
        meter.classList.remove('hidden');
        const levels = [
            { w: '25%', c: '#ef4444', t: 'Weak' },
            { w: '50%', c: '#f59e0b', t: 'Fair' },
            { w: '75%', c: '#eab308', t: 'Good' },
            { w: '100%', c: '#22c55e', t: 'Strong' }
        ];
        const lvl = levels[Math.max(0, scorePassword(_signupPwInput.value) - 1)];
        bar.style.width = lvl.w;
        bar.style.background = lvl.c;
        label.textContent = lvl.t;
        label.style.color = lvl.c;
    });
}

// ── Local Storage (offline cache + local-only data) ──
function getCurrentUser() { return JSON.parse(localStorage.getItem('bchat_current') || 'null'); }
function setCurrentUser(user) { localStorage.setItem('bchat_current', JSON.stringify(user)); }
function getGallery(username) { return JSON.parse(localStorage.getItem('bchat_gallery_' + username) || '[]'); }
function saveGallery(username, photos) { localStorage.setItem('bchat_gallery_' + username, JSON.stringify(photos)); }
function getStarred() { return JSON.parse(localStorage.getItem('bchat_starred_' + (currentUser?.username || '')) || '[]'); }
function saveStarred(s) { localStorage.setItem('bchat_starred_' + currentUser.username, JSON.stringify(s)); }

async function restoreBackendSession() {
    const saved = getCurrentUser();
    const token = getStoredToken();
    if (!saved || !saved.username || !token) return null;
    if (!navigator.onLine) return saved;
    try {
        const data = await apiJson('/api/me');
        const user = { ...saved, ...data.user };
        setCurrentUser(user);
        currentUser = user;
        return user;
    } catch (err) {
        clearStoredToken();
        setCurrentUser(null);
        return null;
    }
}

// ── Cloud wrappers with offline fallback ──
async function getUsers() {
    if (!navigator.onLine) return JSON.parse(localStorage.getItem('bchat_users_cache') || '[]');
    try {
        const data = await apiJson('/api/users');
        const users = data?.users || [];
        localStorage.setItem('bchat_users_cache', JSON.stringify(users));
        return users;
    } catch (err) {
        return JSON.parse(localStorage.getItem('bchat_users_cache') || '[]');
    }
}

function preserveLocalDisplayText(serverMessages, cachedMessages) {
    const localTextById = new Map(
        cachedMessages
            .filter((message) => message.id && message.decryptedText)
            .map((message) => [message.id, message.decryptedText])
    );
    return serverMessages.map((message) => localTextById.has(message.id)
        ? { ...message, decryptedText: localTextById.get(message.id) }
        : message
    );
}

async function getMessages(user1, user2) {
    const cacheKey = getConversationKey(user1, user2);
    const cached = JSON.parse(localStorage.getItem(cacheKey) || '[]');
    const pending = getPendingMessages().filter((msg) => (msg.sender === user1 && msg.receiver === user2) || (msg.sender === user2 && msg.receiver === user1));
    const mergedCached = mergeConversationMessages(cached, pending);

    if (!navigator.onLine) {
        localStorage.setItem(cacheKey, JSON.stringify(mergedCached));
        return mergedCached;
    }

    try {
        const data = await apiJson(`/api/messages?user1=${encodeURIComponent(user1)}&user2=${encodeURIComponent(user2)}`);
        const serverMessages = preserveLocalDisplayText(data?.messages || [], cached);
        const msgs = mergeConversationMessages(serverMessages, pending);
        localStorage.setItem(cacheKey, JSON.stringify(msgs));
        return msgs;
    } catch (err) {
        localStorage.setItem(cacheKey, JSON.stringify(mergedCached));
        return mergedCached;
    }
}

async function getConversationMessages(username) {
    const cached = JSON.parse(localStorage.getItem('bchat_all_msgs_cache') || '[]');
    const pending = getPendingMessages().filter((msg) => msg.sender === username || msg.receiver === username);
    const mergedCached = mergeConversationMessages(cached, pending);

    if (!navigator.onLine) {
        localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(mergedCached));
        return mergedCached;
    }

    try {
        const data = await apiJson(`/api/conversations?username=${encodeURIComponent(username)}`);
        const serverMessages = preserveLocalDisplayText(data?.messages || [], cached);
        const msgs = mergeConversationMessages(serverMessages, pending);
        localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(msgs));
        return msgs;
    } catch (err) {
        localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(mergedCached));
        return mergedCached;
    }
}

async function getStatuses() {
    if (!navigator.onLine) return JSON.parse(localStorage.getItem('bchat_statuses_cache') || '[]');
    try {
        const data = await apiJson('/api/statuses');
        const statuses = data?.statuses || [];
        localStorage.setItem('bchat_statuses_cache', JSON.stringify(statuses));
        return statuses;
    } catch (err) {
        return JSON.parse(localStorage.getItem('bchat_statuses_cache') || '[]');
    }
}

async function getAds() {
    if (!navigator.onLine) return JSON.parse(localStorage.getItem('bchat_ads_cache') || '[]');
    try {
        const data = await apiJson('/api/ads');
        const ads = data?.ads || [];
        localStorage.setItem('bchat_ads_cache', JSON.stringify(ads));
        return ads;
    } catch (err) {
        return JSON.parse(localStorage.getItem('bchat_ads_cache') || '[]');
    }
}

// ── State ──
let currentUser = null;
let activeChatWith = null;
let signupAvatarData = null;
let signupContact = { email: '', password: '' };
let galleryMode = 'profile';
let showArchivedChats = false;
let unlockedChats = new Set();
let galleryPreviewIdx = -1;
let replyToMsg = null;
let contextMsgIdx = -1;
let prevMsgCount = 0;
let mediaRecorder = null;
let recordChunks = [];
let recordTimer = null;
let recordSeconds = 0;
let typingTimeout = null;
function getPinnedChats() { return JSON.parse(localStorage.getItem('bchat_pinned_' + (currentUser?.username || '')) || '[]'); }
function savePinnedChats(pins) { localStorage.setItem('bchat_pinned_' + currentUser.username, JSON.stringify(pins)); }
function getReadCounts() { return JSON.parse(localStorage.getItem('bchat_read_' + (currentUser?.username || '')) || '{}'); }
function saveReadCounts(rc) { localStorage.setItem('bchat_read_' + currentUser.username, JSON.stringify(rc)); }
function getArchivedChats() { return JSON.parse(localStorage.getItem('bchat_archived_' + (currentUser?.username || 'guest')) || '[]'); }
function saveArchivedChats(list) { localStorage.setItem('bchat_archived_' + (currentUser?.username || 'guest'), JSON.stringify(list)); }
function getLockedChats() { return JSON.parse(localStorage.getItem('bchat_locked_' + (currentUser?.username || 'guest')) || '[]'); }
function saveLockedChats(list) { localStorage.setItem('bchat_locked_' + (currentUser?.username || 'guest'), JSON.stringify(list)); }
function getLockPassword() { return localStorage.getItem('bchat_lock_password') || ''; }
function setLockPassword(password) { if (password) localStorage.setItem('bchat_lock_password', password); else localStorage.removeItem('bchat_lock_password'); }
function isChatArchived(username) { return getArchivedChats().includes(username); }
function isChatLocked(username) { return getLockedChats().includes(username); }
function toggleArchiveChat(username) {
    const archived = getArchivedChats();
    const next = archived.includes(username) ? archived.filter(u => u !== username) : [...archived, username];
    saveArchivedChats(next);
    showToast(archived.includes(username) ? 'Chat restored from archive' : 'Chat archived', 'info', 2200);
    renderChatList();
}
function toggleLockChat(username) {
    const locked = getLockedChats();
    const isLocked = locked.includes(username);
    if (!isLocked) {
        const existing = getLockPassword();
        const password = existing || window.prompt('Set a password to lock this chat', '');
        if (!password) {
            showToast('A password is required to lock chats', 'error', 2500);
            return false;
        }
        setLockPassword(password);
        saveLockedChats([...locked, username]);
        unlockedChats.add(username);
        showToast('Chat locked 🔒', 'success', 2200);
    } else {
        saveLockedChats(locked.filter(u => u !== username));
        unlockedChats.delete(username);
        showToast('Chat unlocked', 'info', 2200);
    }
    renderChatList();
    return true;
}
function requireChatAccess(username) {
    if (!isChatLocked(username)) return true;
    if (unlockedChats.has(username)) return true;
    const password = getLockPassword();
    if (!password) {
        showToast('Set a lock password first from the chat menu', 'info', 2500);
        return false;
    }
    const entered = window.prompt('Enter your lock password to open this chat');
    if (entered === null) return false;
    if (entered !== password) {
        showToast('Incorrect password', 'error', 2500);
        return false;
    }
    unlockedChats.add(username);
    return true;
}
function updateArchiveToggleButton() {
    const btn = $('btn-toggle-archive');
    if (!btn) return;
    btn.textContent = showArchivedChats ? 'Show active chats' : 'Show archived';
    btn.classList.toggle('active', showArchivedChats);
}
function renderChatActionsMenu() {
    const menu = $('chat-actions-menu');
    if (!menu || !activeChatWith) return;
    const lockBtn = menu.querySelector('[data-action="lock"]');
    if (lockBtn) lockBtn.textContent = isChatLocked(activeChatWith) ? 'Unlock chat' : 'Lock chat';
}
function showChatActionsMenu(x, y) {
    const menu = $('chat-actions-menu');
    if (!menu) return;
    renderChatActionsMenu();
    menu.classList.remove('hidden');
    menu.style.left = Math.min(x, window.innerWidth - 200) + 'px';
    menu.style.top = Math.min(y, window.innerHeight - 140) + 'px';
}
function hideChatActionsMenu() {
    $('chat-actions-menu')?.classList.add('hidden');
}

// ── DOM ──
const loginScreen = $('login-screen');
const signupScreen = $('signup-screen');
const appScreen = $('app-screen');
const sidebar = $('sidebar');
const chatArea = $('chat-area');
const chatList = $('chat-list');
const chatWelcome = $('chat-welcome');
const chatView = $('chat-view');
const messagesDiv = $('messages');
const msgInput = $('msg-input');
const emojiPicker = $('emoji-picker');
const emojiGrid = $('emoji-grid');

function showScreen(screen) {
    loginScreen?.classList.remove('active');
    signupScreen?.classList.remove('active');
    appScreen?.classList.remove('active');
    screen?.classList.add('active');
    // Show the install button on every screen (repositioned on auth screens).
    if (installAvailable) showInstallButton();
    else hideInstallButton();
}

function setSignupStep(step) {
    const step1 = $('signup-step-1');
    const step2 = $('signup-step-2');
    const step3 = $('signup-step-3');
    if (!step1 || !step2 || !step3) return;
    const step1Active = step === 1;
    const step2Active = step === 2;
    const step3Active = step === 3;
    step1.classList.toggle('active', step1Active);
    step2.classList.toggle('active', step2Active);
    step3.classList.toggle('active', step3Active);
    step1.querySelectorAll('input,button').forEach(el => { el.disabled = step2Active || step3Active; });
    step2.querySelectorAll('input,button').forEach(el => { el.disabled = !step2Active; });
    step3.querySelectorAll('input,button').forEach(el => { el.disabled = !step3Active; });
    $('signup-subtitle').textContent = step1Active ? 'Start with your email' : (step2Active ? 'Create your public profile' : 'Choose security answers');
    $('signup-error').textContent = '';
    setTimeout(() => {
        if (step1Active) $('signup-email')?.focus();
        else if (step2Active) $('signup-display')?.focus();
        else $('signup-sq-answer-1')?.focus();
    }, 30);
}

function resetSignupFlow() {
    $('signup-error').textContent = '';
    $('signup-form').reset();
    $('signup-avatar-img').classList.add('hidden');
    $('signup-avatar-img').src = '';
    $('signup-avatar-letter').classList.remove('hidden');
    const meter = $('pw-strength');
    if (meter) meter.classList.add('hidden');
    signupAvatarData = null;
    signupContact = { email: '', password: '' };
    setSignupStep(1);
}

function getSecurityQuestionAnswers() {
    const answers = [];
    for (let i = 1; i <= 6; i++) {
        const input = $(`signup-sq-answer-${i}`);
        if (!input) continue;
        const value = input.value.trim();
        if (value || i <= 4) {
            answers.push({ id: i, answer: value });
        }
    }
    return answers.filter((q) => q.answer || q.id <= 4);
}

function showSecurityChallenge(questions) {
    const panel = $('security-challenge-panel');
    const list = $('security-questions-list');
    const loginForm = $('login-form');
    const error = $('security-challenge-error');
    if (!panel || !list || !loginForm) return;

    loginForm.classList.add('hidden');
    panel.classList.remove('hidden');
    error.textContent = '';
    list.innerHTML = questions.map((q, idx) => `
        <div class="form-group security-question pw-field">
            <label for="security-answer-${idx}">${q.question}</label>
            <input type="password" id="security-answer-${idx}" placeholder="Your answer" autocomplete="off" required>
            <button type="button" class="pw-toggle" data-target="security-answer-${idx}" aria-label="Show answer">👁</button>
        </div>
    `).join('');
}

function hideSecurityChallenge() {
    const panel = $('security-challenge-panel');
    const loginForm = $('login-form');
    if (!panel || !loginForm) return;
    panel.classList.add('hidden');
    loginForm.classList.remove('hidden');
    $('security-challenge-error').textContent = '';
}

function collectSecurityChallengeAnswers() {
    const answers = [];
    const list = document.querySelectorAll('#security-questions-list .security-question');
    list.forEach((question, idx) => {
        const input = question.querySelector('input');
        if (input) {
            answers.push({ id: idx + 1, answer: input.value.trim() });
        }
    });
    return answers;
}

function getCurrentDeviceId() {
    let id = localStorage.getItem('bchat_device_id');
    if (!id) {
        id = `dev_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
        localStorage.setItem('bchat_device_id', id);
    }
    return id;
}

$('security-challenge-submit').addEventListener('click', async () => {
    const username = $('login-username').value.trim().toLowerCase();
    const password = $('login-password').value;
    const error = $('security-challenge-error');
    const answers = collectSecurityChallengeAnswers();

    if (!username || !password) {
        error.textContent = 'Please enter username and password first.';
        hideSecurityChallenge();
        return;
    }
    if (answers.some((q) => q.answer.length === 0)) {
        error.textContent = 'Please answer all security questions.';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, device_id: getCurrentDeviceId(), security_answers: answers })
        });
        const data = await response.json();
        if (!response.ok) {
            error.textContent = data?.error || 'Verification failed. Please try again.';
            return;
        }

        hideSecurityChallenge();
        $('login-form').reset();
        currentUser = data.user;
        setCurrentUser(currentUser);
        setStoredToken(data.token);
        try { await ensureE2EEKeys(username, password); } catch(e) { console.warn('E2EE init on login:', e); }
        if (currentUser.role === 'admin') {
            await handleAdminRedirect($('login-error'));
            return;
        }
        enterApp();
    } catch (err) {
        console.error('Security challenge error:', err);
        error.textContent = 'Verification failed. Please try again.';
    }
});

$('security-challenge-cancel').addEventListener('click', () => {
    hideSecurityChallenge();
});

// ═══════════════════════════════════════════
// REALTIME SUBSCRIPTION
// ═══════════════════════════════════════════

let realtimeChannel = null;
let realtimePollTimer = null;

function setupRealtime() {
    if (realtimePollTimer) clearInterval(realtimePollTimer);
    if (realtimeChannel) {
        try { sb.removeChannel(realtimeChannel); } catch (e) {}
    }
    realtimeChannel = null;

    const refresh = () => {
        if (!currentUser || !document.body.classList.contains('active')) return;
        if (activeChatWith) renderMessages().catch(() => {});
        renderChatList().catch(() => {});
    };

    refresh();
    realtimePollTimer = setInterval(refresh, 3500);
}

// ═══════════════════════════════════════════
// NOTIFICATION SOUND
// ═══════════════════════════════════════════

function soundsMuted() { return localStorage.getItem(_userKey('bchat_muted')) === '1'; }

function playNotifSound() {
    if (soundsMuted()) return;
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.setValueAtTime(1100, ctx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.25);
    } catch (e) {}
}

function playSentSound() {
    if (soundsMuted()) return;
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.type = 'sine';
        osc.frequency.setValueAtTime(600, ctx.currentTime);
        osc.frequency.setValueAtTime(900, ctx.currentTime + 0.06);
        gain.gain.setValueAtTime(0.1, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.15);
    } catch (e) {}
}

// ═══════════════════════════════════════════
// IMAGE RESIZE UTILITY
// ═══════════════════════════════════════════

function resizeImage(file, maxSize, callback) {
    const reader = new FileReader();
    reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            let w = img.width;
            let h = img.height;
            if (w > maxSize || h > maxSize) {
                if (w > h) { h = Math.round(h * maxSize / w); w = maxSize; }
                else { w = Math.round(w * maxSize / h); h = maxSize; }
            }
            canvas.width = w;
            canvas.height = h;
            canvas.getContext('2d').drawImage(img, 0, 0, w, h);
            callback(canvas.toDataURL('image/jpeg', 0.7));
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// ═══════════════════════════════════════════
// LOGIN
// ═══════════════════════════════════════════

async function handleAdminRedirect(errorElement) {
    const adminUrl = 'admin.html';
    showToast('Redirecting you to the admin dashboard…', 'info', 2200);
    try {
        const response = await fetch(adminUrl, { method: 'HEAD', cache: 'no-store' });
        if (response.ok) {
            window.location.href = adminUrl;
            return true;
        }
    } catch (err) {
        console.warn('Admin dashboard check failed:', err);
    }
    if (errorElement) {
        errorElement.textContent = 'Admin dashboard is unavailable right now. Please try again later.';
    }
    showToast('Admin dashboard is unavailable. Please try again later.', 'error', 4200);
    return false;
}

$('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('login-username').value.trim().toLowerCase();
    const password = $('login-password').value;
    const error = $('login-error');

    if (!navigator.onLine) {
        const cached = getCurrentUser();
        const token = getStoredToken();
        if (cached && cached.username === username && token) {
            currentUser = cached;
            $('login-form').reset();
            enterApp();
            return;
        }
        error.textContent = 'You are offline. Connect to the internet to log in.';
        return;
    }

    try {
        // Prefer the username/password backend login so admin access does not depend on an email.
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, device_id: getCurrentDeviceId() })
            });
            const data = await response.json();
            if (!response.ok) {
                if (data?.require_security && Array.isArray(data.questions)) {
                    showSecurityChallenge(data.questions);
                    return;
                }
                throw new Error(data?.error || 'Login failed');
            }

            error.textContent = '';
            currentUser = data.user;
            setCurrentUser(currentUser);
            setStoredToken(data.token);
            $('login-form').reset();
            try { await ensureE2EEKeys(username, password); } catch(e) { console.warn('E2EE init on login:', e); }
            if (currentUser.role === 'admin') {
                await handleAdminRedirect(error);
                return;
            }
            enterApp();
            return;
        } catch (backendErr) {
            console.warn('Backend login failed, trying Supabase fallback:', backendErr);
        }

        // Supabase is kept as a fallback for users who already have a stored email/profile mapping.
        if (sb) {
            let profile = null;
            let emailCandidate = '';

            const { data: profileByUsername } = await sb
                .from('profiles')
                .select('*')
                .eq('username', username)
                .maybeSingle();

            if (profileByUsername?.id) {
                profile = profileByUsername;
                emailCandidate = profileByUsername.email || '';
            }

            if (!profile) {
                const storedEmail = localStorage.getItem('bchat_email_' + username);
                if (storedEmail) {
                    emailCandidate = storedEmail;
                }
            }

            if (profile?.id || emailCandidate) {
                const { data: signInData, error: signInError } = await sb.auth.signInWithPassword({
                    email: profile?.email || emailCandidate,
                    password: password
                });

                if (!signInError && signInData?.user) {
                    const resolvedProfile = profile || (await sb
                        .from('profiles')
                        .select('*')
                        .eq('id', signInData.user.id)
                        .maybeSingle()).data;

                    const user = {
                        id: signInData.user.id,
                        username: resolvedProfile?.username || username,
                        email: signInData.user.email || resolvedProfile?.email || emailCandidate,
                        display_name: resolvedProfile?.full_name || resolvedProfile?.username || username,
                        displayName: resolvedProfile?.full_name || resolvedProfile?.username || username,
                        avatar: resolvedProfile?.avatar_url || null,
                        avatar_url: resolvedProfile?.avatar_url || null,
                        code: resolvedProfile?.four_digit_code || '',
                        role: resolvedProfile?.is_admin ? 'admin' : 'user',
                        is_online: true,
                        isOnline: true,
                        last_seen: new Date().toISOString(),
                        lastSeen: new Date().toISOString(),
                        bio: resolvedProfile?.bio || '',
                        createdAt: resolvedProfile?.created_at || new Date().toISOString(),
                        e2ee_public_key: resolvedProfile?.e2ee_public_key || null
                    };

                    error.textContent = '';
                    currentUser = user;
                    setCurrentUser(currentUser);
                    setStoredToken(signInData.session?.access_token || '');
                    $('login-form').reset();
                    try { await ensureE2EEKeys(username, password); } catch(e) { console.warn('E2EE init on login:', e); }
                    if (currentUser.role === 'admin') {
                        await handleAdminRedirect(error);
                        return;
                    }
                    enterApp();
                    return;
                }

                if (signInError) {
                    console.warn('Supabase sign-in failed:', signInError.message);
                }
            }
        }
    } catch (err) {
        console.error('Login error:', err);
        error.textContent = 'Incorrect username or password.';
    }
});

// ── Welcome overlay (shown after signup / login) ──
function showWelcome(user, isNew) {
    const overlay = $('welcome-overlay');
    if (!overlay || !user) return;
    const name = uName(user);
    $('welcome-title').textContent = isNew ? 'Welcome to B CHAT! 🎉' : 'Welcome back! 👋';
    $('welcome-sub').textContent = isNew
        ? "You're all set, " + name + " — your account is ready."
        : 'Good to see you again, ' + name + '.';
    const codeBox = $('welcome-code-box');
    if (isNew && user.code) {
        codeBox.style.display = '';
        $('welcome-code').textContent = user.code;
    } else {
        codeBox.style.display = 'none';
    }
    overlay.classList.remove('hidden');
    requestAnimationFrame(() => overlay.classList.add('show'));
}
function hideWelcome() {
    const overlay = $('welcome-overlay');
    if (!overlay) return;
    overlay.classList.remove('show');
    setTimeout(() => overlay.classList.add('hidden'), 320);
}
$('welcome-start')?.addEventListener('click', hideWelcome);
$('welcome-overlay')?.addEventListener('click', (e) => { if (e.target === $('welcome-overlay')) hideWelcome(); });
$('welcome-copy')?.addEventListener('click', () => {
    const code = $('welcome-code').textContent;
    if (navigator.clipboard) navigator.clipboard.writeText(code).then(() => showToast('Code copied! 📋', 'success', 2000), () => {});
});

$('go-signup').addEventListener('click', (e) => {
    e.preventDefault();
    $('login-error').textContent = '';
    $('login-form').reset();
    resetSignupFlow();
    showScreen(signupScreen);
});

$('forgot-password').addEventListener('click', () => {
    $('signup-error').textContent = 'Password reset is not connected yet. Ask the app owner to reset your account password.';
});

// ═══════════════════════════════════════════
// SIGNUP + PROFILE PHOTO
// ═══════════════════════════════════════════

$('signup-avatar-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    resizeImage(file, 200, (data) => {
        signupAvatarData = data;
        $('signup-avatar-img').src = data;
        $('signup-avatar-img').classList.remove('hidden');
        $('signup-avatar-letter').classList.add('hidden');
    });
});

$('signup-avatar-preview').addEventListener('click', () => {
    $('signup-avatar-input').click();
});

$('signup-avatar-btn').addEventListener('click', () => {
    $('signup-avatar-input').click();
});

$('signup-next').addEventListener('click', () => {
    const email = $('signup-email');
    const error = $('signup-error');
    const cleanEmail = email.value.trim().toLowerCase();
    error.textContent = '';

    if (!navigator.onLine) { error.textContent = 'You need internet to sign up.'; return; }
    email.value = cleanEmail;
    if (!isValidEmail(cleanEmail)) { error.textContent = 'Enter a valid email address.'; email.focus(); return; }
    if (!email.checkValidity()) { email.reportValidity(); return; }

    signupContact.email = cleanEmail;
    setSignupStep(2);
});

$('signup-back').addEventListener('click', () => {
    signupContact.email = $('signup-email').value.trim().toLowerCase();
    signupContact.password = $('signup-start-password').value;
    setSignupStep(1);
});

$('signup-security-back').addEventListener('click', () => {
    setSignupStep(2);
});

document.querySelectorAll('.social-btn[data-provider]').forEach(btn => {
    btn.addEventListener('click', () => {
        $('signup-error').textContent = btn.dataset.provider + ' signup is not connected yet. Continue with email for now.';
    });
});

$('signup-next').addEventListener('click', () => {
    const email = $('signup-email').value.trim().toLowerCase();
    const error = $('signup-error');
    const cleanEmail = email;
    error.textContent = '';

    if (!navigator.onLine) { error.textContent = 'You need internet to sign up.'; return; }
    if (!isValidEmail(cleanEmail)) { error.textContent = 'Enter a valid email address.'; $('signup-email').focus(); return; }

    signupContact.email = cleanEmail;
    setSignupStep(2);
});

$('signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if ($('signup-step-1').classList.contains('active')) {
        $('signup-next').click();
        return;
    }
    if ($('signup-step-2').classList.contains('active')) {
        const display = $('signup-display').value.trim();
        const username = $('signup-username').value.trim().toLowerCase();
        const startPassword = $('signup-start-password').value;
        const startConfirm = $('signup-start-confirm').value;
        const error = $('signup-error');
        const displayIssue = validateDisplayName(display);
        const usernameIssue = validateUsername(username);
        const passwordIssue = validateSignupPassword(startPassword);

        if (!navigator.onLine) { error.textContent = 'You need internet to sign up.'; return; }
        if (displayIssue) { error.textContent = displayIssue; $('signup-display').focus(); return; }
        if (usernameIssue) { error.textContent = usernameIssue; $('signup-username').focus(); return; }
        if (passwordIssue) { error.textContent = passwordIssue; $('signup-start-password').focus(); return; }
        if (startPassword !== startConfirm) { error.textContent = 'Passwords do not match.'; $('signup-start-confirm').focus(); return; }

        signupContact.display = display;
        signupContact.username = username;
        signupContact.password = startPassword;
        signupContact.avatar = signupAvatarData;
        setSignupStep(3);
        return;
    }

    const email = $('signup-email').value.trim().toLowerCase();
    const display = $('signup-display').value.trim();
    const username = $('signup-username').value.trim().toLowerCase();
    const startPassword = $('signup-start-password').value;
    const error = $('signup-error');
    const securityAnswers = getSecurityQuestionAnswers();

    if (securityAnswers.length < 4) {
        error.textContent = 'Please answer at least 4 security questions.';
        return;
    }

    try {
        const data = await apiJson('/api/auth/signup', {
            method: 'POST',
            body: JSON.stringify({
                username,
                password: startPassword,
                email,
                display_name: display,
                avatar: signupAvatarData || null,
                security_questions: [
                    { id: 1, question: 'What was the name of your first school?', answer: $('signup-sq-answer-1').value.trim() },
                    { id: 2, question: 'What is the name of your first pet?', answer: $('signup-sq-answer-2').value.trim() },
                    { id: 3, question: 'Which city were you born in?', answer: $('signup-sq-answer-3').value.trim() },
                    { id: 4, question: 'What is your favorite childhood toy?', answer: $('signup-sq-answer-4').value.trim() },
                    { id: 5, question: 'What is your favorite movie?', answer: $('signup-sq-answer-5').value.trim() },
                    { id: 6, question: 'What is the name of the street where you grew up?', answer: $('signup-sq-answer-6').value.trim() }
                ].filter((q) => q.answer || q.id <= 4),
                device_id: getCurrentDeviceId()
            })
        });

        if (signupAvatarData) {
            const gallery = getGallery(username);
            gallery.push({ data: signupAvatarData, addedAt: new Date().toISOString(), isProfile: true });
            saveGallery(username, gallery);
        }

        error.textContent = '';
        resetSignupFlow();
        currentUser = data.user;
        setCurrentUser(currentUser);
        setStoredToken(data.token);
        try { await ensureE2EEKeys(username, startPassword); } catch(e) { console.warn('E2EE init on signup:', e); }
        localStorage.setItem('bchat_show_welcome', '1');
        enterApp();
    } catch (err) {
        console.error('Signup error:', err);
        error.textContent = 'Error: ' + err.message;
    }
});

// Generate a unique 4-digit code for the local-first backend.
async function generateUniqueCode() {
    for (let attempt = 0; attempt < 40; attempt++) {
        const code = String(Math.floor(1000 + Math.random() * 9000));
        try {
            const data = await apiJson(`/api/users?code=${encodeURIComponent(code)}`);
            if (!data?.user) return code;
        } catch (err) {}
    }
    return null;
}

$('go-login').addEventListener('click', (e) => {
    e.preventDefault();
    resetSignupFlow();
    showScreen(loginScreen);
});

// ═══════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════

function uName(u) { return u.display_name || u.displayName || u.username; }

function enterApp() {
    showScreen(appScreen);
    applyUserSettings();
    startUsageAnalytics();
    startNotificationPolling();
    syncPendingMessages();
    $('my-name').textContent = uName(currentUser);
    const codeEl = $('my-code');
    if (codeEl) codeEl.textContent = currentUser.code ? 'Code: ' + currentUser.code : '';

    // ── Admin Panel shortcut — shown only for users with an admin role ──
    const adminSection = document.getElementById('admin-panel-section');
    if (adminSection) {
        adminSection.classList.toggle('hidden', currentUser?.role !== 'admin');
    }
    $('my-avatar').textContent = uName(currentUser).charAt(0).toUpperCase();

    if (currentUser.avatar) {
        $('my-avatar-img').src = currentUser.avatar;
        $('my-avatar-img').classList.remove('hidden');
    } else {
        $('my-avatar-img').classList.add('hidden');
    }

    activeChatWith = null;
    chatView.classList.add('hidden');
    chatWelcome.classList.remove('hidden');
    sidebar.classList.remove('chat-open');
    chatArea.classList.add('chat-closed');
    emojiPicker.classList.add('hidden');
    renderChatList();
    setupRealtime();
}

// ── Open Gallery to change profile photo ──
$('my-profile-wrap').addEventListener('click', () => {
    openGallery('profile');
});

async function setProfilePhoto(data) {
    currentUser.avatar = data;
    if (navigator.onLine) {
        try {
            await apiJson('/api/users/profile', { method: 'POST', body: JSON.stringify({ avatar: data }) });
        } catch (err) {}
    }
    setCurrentUser(currentUser);
    $('my-avatar-img').src = data;
    $('my-avatar-img').classList.remove('hidden');

    const gallery = getGallery(currentUser.username);
    gallery.forEach(p => p.isProfile = false);
    const match = gallery.find(p => p.data === data);
    if (match) match.isProfile = true;
    saveGallery(currentUser.username, gallery);

    renderChatList();
}

// ── Theme Toggle ──
// Per-user settings key helper — keeps one user's personalization from affecting another.
function _userKey(base) { return base + '_' + (currentUser?.username || 'guest'); }

function loadTheme() {
    // In-app: strictly this user's own theme (default dark); login screen: the device default.
    const theme = currentUser
        ? (localStorage.getItem(_userKey('bchat_theme')) || 'dark')
        : (localStorage.getItem('bchat_theme') || 'dark');
    document.body.classList.toggle('light', theme === 'light');
    updateAuthThemeIcon(theme === 'light');
}

function updateAuthThemeIcon(isLight) {
    // Show the icon for what you'll switch TO: sun in dark mode, moon in light mode.
    document.querySelectorAll('.auth-theme-toggle').forEach(b => { b.textContent = isLight ? '🌙' : '☀️'; });
}

function toggleTheme() {
    const isLight = document.body.classList.toggle('light');
    const val = isLight ? 'light' : 'dark';
    // In-app changes affect only this user; login-screen changes set the device default.
    if (currentUser) localStorage.setItem(_userKey('bchat_theme'), val);
    else localStorage.setItem('bchat_theme', val);
    updateAuthThemeIcon(isLight);
}

document.querySelectorAll('.auth-theme-toggle').forEach(b => b.addEventListener('click', toggleTheme));

// Theme/accent are applied inside enterApp() so they never touch the login page.

// ── Logout ──
$('btn-logout').addEventListener('click', async () => {
    clearInterval(analyticsHeartbeatTimer);
    clearInterval(notificationPollTimer);
    if (currentUser && navigator.onLine) {
        try {
            await apiJson('/api/users/status', { method: 'POST', body: JSON.stringify({ is_online: false, last_seen: new Date().toISOString() }) });
        } catch (err) {}
        // Sign out from Supabase if connected
        if (sb) {
            try { await sb.auth.signOut(); } catch (e) {}
        }
    }
    currentUser = null;
    setCurrentUser(null);
    clearStoredToken();
    activeChatWith = null;
    $('login-form').reset();
    applyAuthDefaults();
    showScreen(loginScreen);
});

// ═══════════════════════════════════════════
// GALLERY / FILE MANAGER
// ═══════════════════════════════════════════

function openGallery(mode) {
    galleryMode = mode;
    galleryPreviewIdx = -1;
    $('gallery-preview').classList.add('hidden');
    $('gallery-grid').classList.remove('hidden');

    if (mode === 'profile') {
        $('gallery-title').textContent = 'Choose Profile Photo';
        $('gallery-set-profile').classList.remove('hidden');
    } else {
        $('gallery-title').textContent = 'My Photos';
        $('gallery-set-profile').classList.add('hidden');
    }

    renderGalleryGrid();
    $('gallery-modal').classList.remove('hidden');
}

function renderGalleryGrid() {
    const photos = getGallery(currentUser.username);
    const grid = $('gallery-grid');
    $('gallery-count').textContent = photos.length + ' photo' + (photos.length !== 1 ? 's' : '');

    if (photos.length === 0) {
        grid.innerHTML = `
            <div class="gallery-empty">
                <p>&#128247;</p>
                <p>No photos yet</p>
                <p class="hint">Upload photos from your device to build your gallery</p>
            </div>`;
        return;
    }

    grid.innerHTML = '';
    photos.forEach((photo, idx) => {
        const item = document.createElement('div');
        item.className = 'gallery-item';
        item.innerHTML = `
            <img src="${photo.data}" alt="Photo ${idx + 1}">
            ${photo.isProfile ? '<div class="gallery-item-badge">Profile</div>' : ''}
        `;
        item.addEventListener('click', () => openGalleryPreview(idx));
        grid.appendChild(item);
    });
}

function openGalleryPreview(idx) {
    const photos = getGallery(currentUser.username);
    if (!photos[idx]) return;
    galleryPreviewIdx = idx;
    $('gallery-preview-img').src = photos[idx].data;
    $('gallery-grid').classList.add('hidden');
    $('gallery-preview').classList.remove('hidden');

    $('gallery-set-profile').textContent = photos[idx].isProfile ? 'Current Profile Photo' : 'Set as Profile Photo';
    $('gallery-set-profile').disabled = photos[idx].isProfile;
}

// Upload photos to gallery
$('gallery-file-input').addEventListener('change', (e) => {
    const files = Array.from(e.target.files);
    if (!files.length) return;
    let processed = 0;
    const gallery = getGallery(currentUser.username);

    files.forEach(file => {
        resizeImage(file, 800, (data) => {
            gallery.push({ data: data, addedAt: new Date().toISOString(), isProfile: false });
            processed++;
            if (processed === files.length) {
                saveGallery(currentUser.username, gallery);
                renderGalleryGrid();
            }
        });
    });
    e.target.value = '';
});

// Set as profile photo
$('gallery-set-profile').addEventListener('click', () => {
    const photos = getGallery(currentUser.username);
    if (!photos[galleryPreviewIdx]) return;
    setProfilePhoto(photos[galleryPreviewIdx].data);
    $('gallery-set-profile').textContent = 'Current Profile Photo';
    $('gallery-set-profile').disabled = true;
});

// Delete photo from gallery
$('gallery-delete').addEventListener('click', () => {
    const photos = getGallery(currentUser.username);
    if (!photos[galleryPreviewIdx]) return;

    const wasProfile = photos[galleryPreviewIdx].isProfile;
    photos.splice(galleryPreviewIdx, 1);
    saveGallery(currentUser.username, photos);

    if (wasProfile) {
        currentUser.avatar = null;
        const users = getUsers();
        const idx = users.findIndex(u => u.username === currentUser.username);
        if (idx !== -1) { users[idx].avatar = null; saveUsers(users); }
        setCurrentUser(currentUser);
        $('my-avatar-img').classList.add('hidden');
        renderChatList();
    }

    $('gallery-preview').classList.add('hidden');
    $('gallery-grid').classList.remove('hidden');
    renderGalleryGrid();
});

// Back from preview to grid
$('gallery-preview-close').addEventListener('click', () => {
    $('gallery-preview').classList.add('hidden');
    $('gallery-grid').classList.remove('hidden');
    renderGalleryGrid();
});

// Close gallery
$('btn-close-gallery').addEventListener('click', () => { $('gallery-modal').classList.add('hidden'); });
$('gallery-modal').addEventListener('click', (e) => {
    if (e.target === $('gallery-modal')) $('gallery-modal').classList.add('hidden');
});

// ═══════════════════════════════════════════
// CHAT BACKGROUND PICKER
// ═══════════════════════════════════════════

function getChatBgs() { return JSON.parse(localStorage.getItem('bchat_chatbgs_' + currentUser.username) || '{}'); }
function saveChatBgs(bgs) { localStorage.setItem('bchat_chatbgs_' + currentUser.username, JSON.stringify(bgs)); }

function applyChatBackground() {
    if (!activeChatWith) return;
    const bgs = getChatBgs();
    const bg = bgs[activeChatWith] || null;
    if (bg) {
        messagesDiv.style.backgroundImage = 'url(' + bg + ')';
        messagesDiv.style.background = '';
        messagesDiv.style.backgroundImage = 'url(' + bg + ')';
        messagesDiv.style.backgroundSize = 'cover';
        messagesDiv.style.backgroundPosition = 'center';
        messagesDiv.classList.add('has-bg');
    } else {
        const preset = getWallpaperPreset();
        if (preset !== 'none' && WP_GRADIENTS[preset]) {
            messagesDiv.style.backgroundImage = '';
            messagesDiv.style.background = WP_GRADIENTS[preset];
            messagesDiv.classList.add('has-bg');
        } else {
            messagesDiv.style.backgroundImage = '';
            messagesDiv.style.background = '';
            messagesDiv.classList.remove('has-bg');
        }
    }
}

$('btn-chat-bg').addEventListener('click', () => {
    renderBgPickerGrid();
    $('bg-picker-modal').classList.remove('hidden');
});

function renderBgPickerGrid() {
    const photos = getGallery(currentUser.username);
    const grid = $('bg-picker-grid');

    if (photos.length === 0) {
        grid.innerHTML = '<div class="gallery-empty"><p>No saved photos yet</p><p class="hint">Use "Choose from Device" above or upload to your gallery</p></div>';
    } else {
        grid.innerHTML = '';
        photos.forEach(photo => {
            const item = document.createElement('div');
            item.className = 'gallery-item';
            item.innerHTML = `<img src="${photo.data}" alt="Background option">`;
            item.addEventListener('click', () => {
                const bgs = getChatBgs();
                bgs[activeChatWith] = photo.data;
                saveChatBgs(bgs);
                applyChatBackground();
                $('bg-picker-modal').classList.add('hidden');
            });
            grid.appendChild(item);
        });
    }
}

$('bg-file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file || !activeChatWith) return;
    resizeImage(file, 800, (data) => {
        const bgs = getChatBgs();
        bgs[activeChatWith] = data;
        saveChatBgs(bgs);
        applyChatBackground();
        $('bg-picker-modal').classList.add('hidden');
    });
    e.target.value = '';
});

$('bg-default').addEventListener('click', () => {
    const bgs = getChatBgs();
    delete bgs[activeChatWith];
    saveChatBgs(bgs);
    applyChatBackground();
    $('bg-picker-modal').classList.add('hidden');
});

$('btn-close-bg-picker').addEventListener('click', () => { $('bg-picker-modal').classList.add('hidden'); });
$('bg-picker-modal').addEventListener('click', (e) => {
    if (e.target === $('bg-picker-modal')) $('bg-picker-modal').classList.add('hidden');
});

// ═══════════════════════════════════════════
// CHAT LIST
// ═══════════════════════════════════════════

async function renderChatList() {
    const users = await getUsers();
    const pinned = getPinnedChats();
    const readCounts = getReadCounts();

    const archived = getArchivedChats();
    let conversations = {};
    let msgData = await getConversationMessages(currentUser.username);
    if (msgData.length) localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(msgData));

    msgData.forEach(m => {
        const other = m.sender === currentUser.username ? m.receiver : m.sender;
        if (!conversations[other]) conversations[other] = { other, msgs: [], lastTime: m.created_at };
        conversations[other].msgs.push(m);
    });

    let chatItems = Object.values(conversations).filter(conv => {
        const isArchived = archived.includes(conv.other);
        if (showArchivedChats) return isArchived;
        return !isArchived;
    });
    chatItems.sort((a, b) => {
        const aPin = pinned.includes(a.other) ? 1 : 0;
        const bPin = pinned.includes(b.other) ? 1 : 0;
        if (aPin !== bPin) return bPin - aPin;
        return new Date(b.lastTime) - new Date(a.lastTime);
    });

    if (chatItems.length === 0) {
        const emptyHint = showArchivedChats ? 'No archived chats yet' : 'Tap the + button to start a new chat';
        chatList.innerHTML = '<div class="empty-state"><p>' + (showArchivedChats ? 'No archived chats' : 'No conversations yet') + '</p><p class="hint">' + emptyHint + '</p></div>';
        updateTabBadge(0);
        updateArchiveToggleButton();
        return;
    }

    let totalUnread = 0;
    chatList.innerHTML = '';
    chatItems.forEach(conv => {
        const otherUser = users.find(u => u.username === conv.other);
        const displayName = getContactName(conv.other, otherUser);
        const initial = displayName.charAt(0).toUpperCase();
        const avatarSrc = otherUser?.avatar || null;
        const isOnline = !!otherUser?.is_online;
        const isPinned = pinned.includes(conv.other);
        const isArchived = archived.includes(conv.other);
        const isLocked = isChatLocked(conv.other);
        const lastMsg = conv.msgs[0];
        let preview = lastMsg?.type === 'photo' ? '📷 Photo' : lastMsg?.type === 'voice' ? '🎤 Voice' : (lastMsg?.text || '');
        const time = lastMsg ? formatTime(new Date(lastMsg.created_at)) : '';
        const isActive = activeChatWith === conv.other;

        const readCount = readCounts[conv.other] || 0;
        const unread = Math.max(0, conv.msgs.length - readCount);
        totalUnread += unread;

        const item = document.createElement('div');
        item.className = 'chat-list-item' + (isActive ? ' active' : '') + (isArchived ? ' archived' : '') + (isLocked ? ' locked' : '');
        item.innerHTML = `
            <div class="chat-item-avatar">
                ${initial}
                ${avatarSrc ? `<img src="${avatarSrc}" alt="${escapeHtml(displayName)}">` : ''}
                ${isOnline ? '<span class="online-dot" title="Online"></span>' : ''}
            </div>
            <div class="chat-item-info">
                <div class="chat-item-name">${escapeHtml(displayName)}${isPinned ? '<span class="pin-icon">📌</span>' : ''}</div>
                <div class="chat-preview">${escapeHtml(preview)}</div>
            </div>
            <div class="chat-item-meta">
                <div class="chat-time">${time}</div>
                ${unread > 0 && !isActive ? `<div class="unread-badge">${unread}</div>` : ''}
            </div>
        `;
        item.addEventListener('click', () => openChat(conv.other));
        chatList.appendChild(item);
    });

    updateTabBadge(totalUnread);
    updateArchiveToggleButton();
}

function updateTabBadge(count) {
    const chatTab = document.querySelector('[data-tab="tab-chats"]');
    let badge = chatTab.querySelector('.tab-badge');
    if (count > 0) {
        if (!badge) {
            badge = document.createElement('span');
            badge.className = 'tab-badge';
            chatTab.appendChild(badge);
        }
        badge.textContent = count > 99 ? '99+' : count;
    } else if (badge) {
        badge.remove();
    }
    updatePageTitle(count);
}

$('search-chats').addEventListener('input', () => {
    const query = $('search-chats').value.trim().toLowerCase();
    const items = chatList.querySelectorAll('.chat-list-item');
    items.forEach(item => {
        const name = item.querySelector('.chat-item-name').textContent.toLowerCase();
        item.style.display = name.includes(query) ? '' : 'none';
    });
});

// ═══════════════════════════════════════════
// OPEN CHAT
// ═══════════════════════════════════════════

async function openChat(otherUsername) {
    if (!requireChatAccess(otherUsername)) return;
    activeChatWith = otherUsername;
    const users = await getUsers();
    const otherUser = users.find(u => u.username === otherUsername);
    const displayName = getContactName(otherUsername, otherUser);

    $('chat-name').textContent = displayName;
    $('chat-avatar').textContent = displayName.charAt(0).toUpperCase();

    if (otherUser?.is_online) {
        $('chat-status').textContent = 'online';
        $('chat-status').className = 'chat-status status-online';
    } else if (otherUser?.last_seen) {
        $('chat-status').textContent = 'last seen ' + formatLastSeen(new Date(otherUser.last_seen));
        $('chat-status').className = 'chat-status';
    } else {
        $('chat-status').textContent = 'B CHAT user';
        $('chat-status').className = 'chat-status';
    }

    if (otherUser?.avatar) {
        $('chat-avatar-img').src = otherUser.avatar;
        $('chat-avatar-img').classList.remove('hidden');
    } else {
        $('chat-avatar-img').classList.add('hidden');
    }

    chatWelcome.classList.add('hidden');
    chatView.classList.remove('hidden');
    sidebar.classList.add('chat-open');
    chatArea.classList.remove('chat-closed');
    emojiPicker.classList.add('hidden');
    $('btn-emoji').classList.remove('active');

    replyToMsg = null;
    $('reply-bar').classList.add('hidden');
    markAsRead(otherUsername);
    renderMessages();
    applyChatBackground();
    renderChatList();
    msgInput.focus();
}

function markAsRead(otherUsername) {
    const chat = findChat(currentUser.username, otherUsername);
    if (chat) {
        const rc = getReadCounts();
        rc[otherUsername] = chat.messages.length;
        saveReadCounts(rc);
    }
    if (navigator.onLine) {
        apiJson('/api/messages/read', {
            method: 'POST',
            body: JSON.stringify({ sender: otherUsername, receiver: currentUser.username, username: currentUser.username })
        }).catch(() => {});
    }
}

async function renderMessages() {
    if (!activeChatWith) return;
    const msgs = await getMessages(currentUser.username, activeChatWith);
    messagesDiv.innerHTML = '';

    if (!msgs || msgs.length === 0) {
        messagesDiv.innerHTML = '<div class="msg-date-divider">Start of conversation</div>';
        prevMsgCount = 0;
        return;
    }

    if (msgs.length > prevMsgCount && prevMsgCount > 0) {
        const newest = msgs[msgs.length - 1];
        if (newest.sender !== currentUser.username) playNotifSound();
    }
    prevMsgCount = msgs.length;

    // ═══ E2EE: Attempt to decrypt incoming messages ═══
    const decryptedMsgs = [];
    for (const msg of msgs) {
        let processed = { ...msg };
        // Try to decrypt text messages that come to us
        if (msg.sender !== currentUser.username && msg.type === 'text' && msg.text) {
            try {
                const parsed = JSON.parse(msg.text);
                if (parsed && parsed._e2ee && _e2eePrivateKey) {
                    const decrypted = await e2eeDecrypt(parsed, _e2eePrivateKey);
                    if (decrypted) {
                        processed.decryptedText = decrypted;
                    }
                }
            } catch (e) { /* not encrypted */ }
        }
        // Try to decrypt photo messages
        if (msg.sender !== currentUser.username && msg.type === 'photo' && msg.photo) {
            try {
                const parsed = JSON.parse(msg.photo);
                if (parsed && parsed._e2ee && _e2eePrivateKey) {
                    const decrypted = await e2eeDecryptBinary(parsed, _e2eePrivateKey);
                    if (decrypted) {
                        processed.decryptedPhoto = decrypted;
                    }
                }
            } catch (e) { /* not encrypted */ }
        }
        decryptedMsgs.push(processed);
    }

    // Show E2EE indicator in chat header
    const e2eeBadge = $('e2ee-badge');
    if (e2eeBadge) {
        e2eeBadge.classList.remove('hidden');
    }

    const starred = getStarred();
    const otherReadCounts = getReadCounts();

    let lastDate = '';
    decryptedMsgs.forEach((msg, idx) => {
        const msgDate = formatDate(new Date(msg.created_at || msg.time));
        if (msgDate !== lastDate) {
            lastDate = msgDate;
            const divider = document.createElement('div');
            divider.className = 'msg-date-divider';
            divider.textContent = msgDate;
            messagesDiv.appendChild(divider);
        }

        const isSent = msg.sender === currentUser.username;
        const div = document.createElement('div');
        const isStarred = starred.some(s => s.chatWith === activeChatWith && s.msgIdx === idx);

        let replyHtml = '';
        const replyData = msg.reply_to || msg.replyTo;
        if (replyData) {
            const preview = replyData.type === 'photo' ? '📷 Photo' : escapeHtml(replyData.text || '');
            replyHtml = `<div class="msg-reply-quote">${preview}</div>`;
        }

        let reactionsHtml = '';
        if (msg.reactions && Object.keys(msg.reactions).length > 0) {
            const counts = {};
            Object.values(msg.reactions).forEach(r => { counts[r] = (counts[r] || 0) + 1; });
            reactionsHtml = '<div class="msg-reactions">' +
                Object.entries(counts).map(([r, c]) => `<span class="msg-reaction">${r}${c > 1 ? ' ' + c : ''}</span>`).join('') +
                '</div>';
        }

        const starHtml = isStarred ? '<span class="msg-star">⭐</span>' : '';
        let ticksHtml = '';
        if (isSent) {
            ticksHtml = `<span class="msg-ticks ${msg.read ? 'read' : 'delivered'}">✓✓</span>`;
        }

        const timeHtml = `<div class="msg-time">${formatMessageTime(new Date(msg.created_at || msg.time))}${starHtml}${ticksHtml}</div>`;

        if (msg.type === 'photo') {
            div.className = 'message photo-msg ' + (isSent ? 'sent' : 'received');
            div.innerHTML = `${replyHtml}<img src="${msg.photo}" alt="Photo" class="msg-photo">${timeHtml}${reactionsHtml}`;
            div.querySelector('.msg-photo').addEventListener('click', () => openImageViewer(msg.photo));
        } else if (msg.type === 'voice') {
            div.className = 'message ' + (isSent ? 'sent' : 'received');
            const bars = Array.from({length: 20}, () => {
                const h = Math.floor(Math.random() * 16) + 4;
                return `<span style="height:${h}px"></span>`;
            }).join('');
            div.innerHTML = `${replyHtml}<div class="voice-msg"><button class="voice-play-btn">&#9654;</button><div class="voice-waveform">${bars}</div><span class="voice-duration">${msg.voice_duration || msg.voiceDuration || '0:00'}</span></div>${timeHtml}${reactionsHtml}`;
            const playBtn = div.querySelector('.voice-play-btn');
            const waveform = div.querySelector('.voice-waveform');
            playBtn.addEventListener('click', () => {
                const audio = new Audio(msg.voice_data || msg.voiceData);
                playBtn.innerHTML = '&#9646;&#9646;';
                waveform.classList.add('playing');
                audio.play();
                audio.onended = () => { playBtn.innerHTML = '&#9654;'; waveform.classList.remove('playing'); };
            });
        } else {
            // Use decrypted text if available (E2EE)
            const displayText = msg.decryptedText || msg.text;
            div.className = 'message ' + (isSent ? 'sent' : 'received');
            div.innerHTML = `${replyHtml}<div class="msg-text">${formatMsgText(displayText)}</div>${timeHtml}${reactionsHtml}`;
        }

        let pressTimer;
        div.addEventListener('pointerdown', (e) => {
            pressTimer = setTimeout(() => { e.preventDefault(); showContextMenu(e, idx); }, 500);
        });
        div.addEventListener('pointerup', () => clearTimeout(pressTimer));
        div.addEventListener('pointerleave', () => clearTimeout(pressTimer));
        div.addEventListener('contextmenu', (e) => { e.preventDefault(); showContextMenu(e, idx); });

        let lastTap = 0;
        div.addEventListener('click', (e) => {
            if (e.target.closest('a') || e.target.closest('.voice-play-btn') || e.target.closest('.msg-photo')) return;
            const now = Date.now();
            if (now - lastTap < 300) {
                contextMsgIdx = idx;
                const picker = $('reaction-picker');
                picker.classList.remove('hidden');
                const rect = div.getBoundingClientRect();
                picker.style.left = Math.min(rect.left, window.innerWidth - 260) + 'px';
                picker.style.top = (rect.top - 50) + 'px';
            }
            lastTap = now;
        });

        // Swipe-to-reply (WhatsApp-style)
        let swStartX = 0, swStartY = 0, swiping = false;
        div.addEventListener('touchstart', (e) => {
            if (e.touches.length !== 1) return;
            swStartX = e.touches[0].clientX; swStartY = e.touches[0].clientY; swiping = true;
        }, { passive: true });
        div.addEventListener('touchmove', (e) => {
            if (!swiping) return;
            const dx = e.touches[0].clientX - swStartX;
            const dy = e.touches[0].clientY - swStartY;
            if (Math.abs(dy) > 30) { swiping = false; div.style.transform = ''; return; }
            if (dx > 0) div.style.transform = 'translateX(' + Math.min(dx, 72) + 'px)';
        }, { passive: true });
        div.addEventListener('touchend', (e) => {
            if (!swiping) return;
            const dx = e.changedTouches[0].clientX - swStartX;
            div.style.transition = 'transform 0.2s';
            div.style.transform = '';
            setTimeout(() => { div.style.transition = ''; }, 200);
            if (dx > 55) startReplyTo(msg);
            swiping = false;
        }, { passive: true });

        messagesDiv.appendChild(div);
    });

    markAsRead(activeChatWith);
    scrollToBottom();
}

// ═══════════════════════════════════════════
// SEND TEXT MESSAGE
// ═══════════════════════════════════════════

$('btn-send').addEventListener('click', sendMessage);
msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

function sendMessage() {
    const text = msgInput.value.trim();
    if (!text || !activeChatWith) return;
    msgInput.value = '';
    const msg = { sender: currentUser.username, receiver: activeChatWith, text: text, type: 'text' };
    if (replyToMsg) {
        msg.reply_to = { text: replyToMsg.text || '', type: replyToMsg.type };
        replyToMsg = null;
        $('reply-bar').classList.add('hidden');
    }
    addMessageToChat(msg);
}

async function addMessageToChat(msg) {
    // ═══ E2EE: Encrypt the message text before sending ═══
    let processedMsg = { ...msg };
    
    // For text messages, encrypt with the receiver's public key
    if (msg.type === 'text' && msg.text && msg.receiver) {
        try {
            const receiverPubKey = await fetchUserPublicKey(msg.receiver);
            if (receiverPubKey) {
                const encrypted = await e2eeEncrypt(msg.text, receiverPubKey);
                if (encrypted) {
                    processedMsg.text = JSON.stringify({ ...encrypted, _e2ee: true });
                }
            }
        } catch (e) {
            console.warn('E2EE encryption failed for text, sending plaintext:', e);
        }
    }
    
    // For photo messages, encrypt the binary data
    if (msg.type === 'photo' && msg.photo && msg.receiver) {
        try {
            const receiverPubKey = await fetchUserPublicKey(msg.receiver);
            if (receiverPubKey) {
                const encrypted = await e2eeEncryptBinary(msg.photo, receiverPubKey);
                if (encrypted) {
                    processedMsg.photo = JSON.stringify({ ...encrypted, _e2ee: true });
                }
            }
        } catch (e) {
            console.warn('E2EE encryption failed for photo:', e);
        }
    }
    
    const entry = persistMessageToLocalCaches({
        ...processedMsg,
        decryptedText: msg.type === 'text' ? msg.text : undefined,
        id: msg.id || `local_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        pending: true,
        created_at: msg.created_at || new Date().toISOString()
    });
    addPendingMessage(entry);
    if (!navigator.onLine) {
        showToast('Message saved locally and will sync when you are back online.', 'info', 2600);
        playSentSound();
        await renderMessages();
        renderChatList();
        return;
    }

    try {
        const { decryptedText, ...networkEntry } = entry;
        const data = await apiJson('/api/messages', { method: 'POST', body: JSON.stringify(networkEntry) });
        const synced = data?.message || entry;
        persistMessageToLocalCaches({ ...synced, pending: false });
        removePendingMessage(entry.id);
        playSentSound();
        await renderMessages();
        renderChatList();
    } catch (err) {
        showToast('Message saved locally and will sync when you are back online.', 'info', 2600);
        await renderMessages();
        renderChatList();
    }
}

// ═══════════════════════════════════════════
// SEND PHOTO
// ═══════════════════════════════════════════

$('btn-photo').addEventListener('click', () => { $('photo-input').click(); });

$('photo-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file || !activeChatWith) return;
    resizeImage(file, 600, (data) => {
        addMessageToChat({ sender: currentUser.username, receiver: activeChatWith, type: 'photo', photo: data });
    });
    e.target.value = '';
});

// ═══════════════════════════════════════════
// IMAGE VIEWER
// ═══════════════════════════════════════════

function openImageViewer(src) {
    $('viewer-img').src = src;
    $('image-viewer').classList.remove('hidden');
}

$('close-viewer').addEventListener('click', () => { $('image-viewer').classList.add('hidden'); });
$('image-viewer').addEventListener('click', (e) => {
    if (e.target === $('image-viewer')) $('image-viewer').classList.add('hidden');
});

// ═══════════════════════════════════════════
// CONTEXT MENU, REPLY, REACT, DELETE, PIN
// ═══════════════════════════════════════════

function showContextMenu(e, msgIdx) {
    contextMsgIdx = msgIdx;
    const menu = $('msg-context-menu');
    menu.classList.remove('hidden');
    const chat = findChat(currentUser.username, activeChatWith);
    const msg = chat?.messages[msgIdx];
    const isMine = msg?.sender === currentUser.username;
    menu.querySelector('[data-action="delete-all"]').style.display = isMine ? '' : 'none';
    const x = Math.min(e.clientX, window.innerWidth - 180);
    const y = Math.min(e.clientY, window.innerHeight - 280);
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
}

document.addEventListener('click', (e) => {
    if (!e.target.closest('.msg-context-menu')) {
        $('msg-context-menu').classList.add('hidden');
    }
    if (!e.target.closest('.reaction-picker')) {
        $('reaction-picker').classList.add('hidden');
    }
});

document.querySelectorAll('.ctx-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
        const action = btn.dataset.action;
        $('msg-context-menu').classList.add('hidden');

        if (action === 'reply') {
            const msgs = await getMessages(currentUser.username, activeChatWith);
            startReplyTo(msgs?.[contextMsgIdx]);
        }

        if (action === 'react') {
            const menu = $('msg-context-menu');
            const picker = $('reaction-picker');
            picker.classList.remove('hidden');
            picker.style.left = menu.style.left;
            picker.style.top = (parseInt(menu.style.top) - 50) + 'px';
        }

        if (action === 'delete-me' || action === 'delete-all') {
            const msgs = await getMessages(currentUser.username, activeChatWith);
            const msg = msgs[contextMsgIdx];
            if (!msg) return;
            if (action === 'delete-all' && msg.sender !== currentUser.username) return;
            if (navigator.onLine) await apiJson('/api/messages/delete', { method: 'POST', body: JSON.stringify({ id: msg.id }) });
            await renderMessages();
            renderChatList();
        }

        if (action === 'pin') {
            const pinned = getPinnedChats();
            if (pinned.includes(activeChatWith)) {
                pinned.splice(pinned.indexOf(activeChatWith), 1);
            } else {
                pinned.push(activeChatWith);
            }
            savePinnedChats(pinned);
            renderChatList();
        }

        if (action === 'forward') {
            const msgs = await getMessages(currentUser.username, activeChatWith);
            const msg = msgs?.[contextMsgIdx];
            if (!msg) return;
            const users = getUsers().filter(u => u.username !== currentUser.username);
            const list = $('forward-list');
            if (users.length === 0) {
                list.innerHTML = '<p class="no-users-msg">No other users to forward to.</p>';
            } else {
                list.innerHTML = '';
                users.forEach(user => {
                    const item = document.createElement('div');
                    item.className = 'user-result-item';
                    item.innerHTML = `<div class="user-result-avatar">${user.displayName.charAt(0).toUpperCase()}${user.avatar ? `<img src="${user.avatar}" alt="">` : ''}</div><div class="user-result-info"><strong>${escapeHtml(user.displayName)}</strong><span>@${escapeHtml(user.username)}</span></div>`;
                    item.addEventListener('click', async () => {
                        const fwd = { sender: currentUser.username, receiver: user.username, type: msg.type, forwarded: true };
                        if (msg.type === 'photo') fwd.photo = msg.photo;
                        else if (msg.type === 'voice') { fwd.voice_data = msg.voice_data || msg.voiceData; fwd.voice_duration = msg.voice_duration || msg.voiceDuration; }
                        else fwd.text = msg.text;
                        if (navigator.onLine) await apiJson('/api/messages', { method: 'POST', body: JSON.stringify(fwd) });
                        $('forward-modal').classList.add('hidden');
                        renderChatList();
                    });
                    list.appendChild(item);
                });
            }
            $('forward-modal').classList.remove('hidden');
        }

        if (action === 'star') {
            const starred = getStarred();
            const existing = starred.findIndex(s => s.chatWith === activeChatWith && s.msgIdx === contextMsgIdx);
            if (existing !== -1) {
                starred.splice(existing, 1);
            } else {
                const msgs = await getMessages(currentUser.username, activeChatWith);
                const msg = msgs?.[contextMsgIdx];
                if (msg) {
                    starred.push({ chatWith: activeChatWith, msgIdx: contextMsgIdx, text: msg.text || (msg.type === 'photo' ? '📷 Photo' : msg.type === 'voice' ? '🎤 Voice note' : ''), sender: msg.sender, time: msg.created_at || msg.time });
                }
            }
            saveStarred(starred);
            renderMessages();
        }

        if (action === 'disappear') {
            const settings = getDisappearSettings();
            const current = settings[activeChatWith] || 0;
            document.querySelectorAll('.disappear-opt').forEach(o => o.classList.toggle('active', parseInt(o.dataset.dur) === current));
            $('disappear-modal').classList.remove('hidden');
        }

        if (action === 'cancel') {}
    });
});

$('btn-close-forward').addEventListener('click', () => { $('forward-modal').classList.add('hidden'); });
$('forward-modal').addEventListener('click', (e) => { if (e.target === $('forward-modal')) $('forward-modal').classList.add('hidden'); });

// ═══════════════════════════════════════════
// STARRED MESSAGES VIEWER
// ═══════════════════════════════════════════

// ═══════════════════════════════════════════
// MESSAGE SEARCH
// ═══════════════════════════════════════════

$('btn-search-msgs').addEventListener('click', () => {
    const bar = $('msg-search-bar');
    bar.classList.toggle('hidden');
    if (!bar.classList.contains('hidden')) {
        $('msg-search-input').value = '';
        $('msg-search-input').focus();
    } else {
        document.querySelectorAll('.message.search-highlight').forEach(m => m.classList.remove('search-highlight'));
    }
});

$('btn-close-msg-search').addEventListener('click', () => {
    $('msg-search-bar').classList.add('hidden');
    document.querySelectorAll('.message.search-highlight').forEach(m => m.classList.remove('search-highlight'));
});

$('msg-search-input').addEventListener('input', () => {
    const query = $('msg-search-input').value.trim().toLowerCase();
    document.querySelectorAll('.message.search-highlight').forEach(m => m.classList.remove('search-highlight'));
    if (!query) return;

    const msgs = messagesDiv.querySelectorAll('.message');
    let firstMatch = null;
    msgs.forEach(m => {
        const text = m.textContent.toLowerCase();
        if (text.includes(query)) {
            m.classList.add('search-highlight');
            if (!firstMatch) firstMatch = m;
        }
    });
    if (firstMatch) firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
});

$('btn-contact-admin').addEventListener('click', () => {
    openContactAdminForm();
});

function openContactAdminForm() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'contact-admin-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📨 Contact Admin</h3>
                <button class="icon-btn" id="btn-close-admin-contact">&times;</button>
            </div>
            <div style="padding:16px;">
                <p style="color:var(--text-muted);font-size:13px;margin-bottom:14px;">Enter your details and message. The admin will reply to you directly.</p>
                <div class="field">
                    <input type="text" id="admin-username-input" placeholder="Your B CHAT Username *" required autocomplete="username" style="width:100%;padding:10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;color:var(--text);font:inherit;outline:none;margin-bottom:10px;">
                </div>
                <div class="field">
                    <input type="email" id="admin-email-input" placeholder="Your Email (optional)" autocomplete="email" style="width:100%;padding:10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;color:var(--text);font:inherit;outline:none;margin-bottom:10px;">
                </div>
                <div class="field">
                    <textarea id="admin-message-input" placeholder="Type your message, question, or feedback..." rows="4" required style="width:100%;resize:vertical;min-height:90px;padding:10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;color:var(--text);font:inherit;outline:none;"></textarea>
                </div>
                <button class="btn auth" id="btn-send-to-admin" style="width:100%;justify-content:center;padding:11px;margin-top:12px;">Send to Admin</button>
                <p id="admin-contact-status" style="margin-top:10px;font-size:13px;text-align:center;"></p>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    requestAnimationFrame(() => modal.classList.add('show'));

    const send = async () => {
        const usernameInput = document.getElementById('admin-username-input');
        const emailInput = document.getElementById('admin-email-input');
        const messageInput = document.getElementById('admin-message-input');
        const status = document.getElementById('admin-contact-status');
        const username = usernameInput.value.trim();
        const email = emailInput.value.trim();
        const text = messageInput.value.trim();

        if (!username || !text) {
            status.textContent = 'Please enter your username and message.';
            status.style.color = 'var(--amber)';
            return;
        }

        status.textContent = 'Sending...';
        status.style.color = 'var(--text-muted)';
        try {
            const data = await apiJson('/api/admin/messages', {
                method: 'POST',
                body: JSON.stringify({ text, sender: username, sender_name: username, email })
            });
            status.textContent = '✓ Message sent to admin! They will reply soon.';
            status.style.color = 'var(--green)';
            messageInput.value = '';
            setTimeout(() => { modal.classList.remove('show'); setTimeout(() => modal.remove(), 300); }, 1800);
        } catch (e) {
            status.textContent = 'Failed to send. Please try again later.';
            status.style.color = 'var(--red)';
        }
    };

    document.getElementById('btn-send-to-admin').addEventListener('click', send);
    document.getElementById('btn-close-admin-contact').addEventListener('click', () => { modal.classList.remove('show'); setTimeout(() => modal.remove(), 300); });
    modal.addEventListener('click', (e) => { if (e.target === modal) { modal.classList.remove('show'); setTimeout(() => modal.remove(), 300); } });
    document.getElementById('admin-message-input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
}

$('btn-starred').addEventListener('click', () => {
    const starred = getStarred();
    const list = $('starred-list');
    const users = getUsers();

    if (starred.length === 0) {
        list.innerHTML = '<div class="starred-empty"><p>⭐</p><p>No starred messages</p><p class="hint" style="font-size:0.8rem;color:var(--text-muted);margin-top:6px;">Long-press a message and tap Star to save it here</p></div>';
    } else {
        list.innerHTML = '';
        starred.slice().reverse().forEach(s => {
            const sender = users.find(u => u.username === s.sender);
            const chatWith = users.find(u => u.username === s.chatWith);
            const item = document.createElement('div');
            item.className = 'starred-item';
            item.innerHTML = `
                <div class="starred-item-header">
                    <span class="starred-item-sender">${escapeHtml(sender?.displayName || s.sender)}</span>
                    <span class="starred-item-time">${formatTime(new Date(s.time))}</span>
                </div>
                <div class="starred-item-text">${escapeHtml(s.text)}</div>
                <div class="starred-item-chat">In chat with ${escapeHtml(chatWith?.displayName || s.chatWith)}</div>
            `;
            item.style.cursor = 'pointer';
            item.addEventListener('click', () => {
                $('starred-modal').classList.add('hidden');
                openChat(s.chatWith);
            });
            list.appendChild(item);
        });
    }
    $('starred-modal').classList.remove('hidden');
});

$('btn-close-starred').addEventListener('click', () => { $('starred-modal').classList.add('hidden'); });
$('starred-modal').addEventListener('click', (e) => { if (e.target === $('starred-modal')) $('starred-modal').classList.add('hidden'); });

$('reply-bar-close').addEventListener('click', () => {
    replyToMsg = null;
    $('reply-bar').classList.add('hidden');
});

document.querySelectorAll('.react-emoji').forEach(btn => {
    btn.addEventListener('click', () => {
        quickReact(contextMsgIdx, btn.dataset.r);
        $('reaction-picker').classList.add('hidden');
    });
});

function quickReact(msgIdx, emoji) {
    const chats = getChats();
    const chat = chats.find(c => c.participants.includes(currentUser.username) && c.participants.includes(activeChatWith));
    if (!chat || !chat.messages[msgIdx]) return;
    if (!chat.messages[msgIdx].reactions) chat.messages[msgIdx].reactions = {};
    const existing = chat.messages[msgIdx].reactions[currentUser.username];
    if (existing === emoji) {
        delete chat.messages[msgIdx].reactions[currentUser.username];
    } else {
        chat.messages[msgIdx].reactions[currentUser.username] = emoji;
    }
    saveChats(chats);
    renderMessages();
}

// ═══════════════════════════════════════════
// PROFILE CARD
// ═══════════════════════════════════════════

$('chat-header-info').addEventListener('click', () => {
    if (!activeChatWith) return;
    const users = getUsers();
    const user = users.find(u => u.username === activeChatWith);
    if (!user) return;

    $('pc-name').textContent = user.displayName;
    $('pc-username').textContent = '@' + user.username;
    $('pc-avatar').textContent = user.displayName.charAt(0).toUpperCase();

    if (user.avatar) {
        $('pc-avatar-img').src = user.avatar;
        $('pc-avatar-img').classList.remove('hidden');
    } else {
        $('pc-avatar-img').classList.add('hidden');
    }

    if (user.isOnline) {
        $('pc-status-text').textContent = '🟢 Online';
    } else if (user.lastSeen) {
        $('pc-status-text').textContent = 'Last seen ' + formatLastSeen(new Date(user.lastSeen));
    } else {
        $('pc-status-text').textContent = 'B CHAT user';
    }

    $('pc-joined').textContent = 'Joined ' + new Date(user.createdAt).toLocaleDateString([], { month: 'long', year: 'numeric' });
    const bioEl = document.getElementById('pc-bio');
    if (bioEl) bioEl.textContent = user.bio || '';
    else {
        const b = document.createElement('p');
        b.id = 'pc-bio';
        b.className = 'pc-status-text';
        b.style.fontStyle = 'italic';
        b.textContent = user.bio || '';
        $('pc-joined').before(b);
    }
    $('profile-card-modal').classList.remove('hidden');
});

$('pc-close').addEventListener('click', () => { $('profile-card-modal').classList.add('hidden'); });
$('profile-card-modal').addEventListener('click', (e) => {
    if (e.target === $('profile-card-modal')) $('profile-card-modal').classList.add('hidden');
});

// ═══════════════════════════════════════════
// SPLASH SCREEN
// ═══════════════════════════════════════════

setTimeout(() => {
    const splash = $('splash-screen');
    if (splash) splash.remove();
}, 2400);

// ═══════════════════════════════════════════
// VOICE NOTES (Real Recording)
// ═══════════════════════════════════════════

$('btn-voice').addEventListener('pointerdown', async (e) => {
    if (!activeChatWith) return;
    e.preventDefault();
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        recordChunks = [];
        recordSeconds = 0;

        mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) recordChunks.push(e.data); };
        mediaRecorder.onstop = () => {
            stream.getTracks().forEach(t => t.stop());
            if (recordChunks.length === 0) return;
            const blob = new Blob(recordChunks, { type: 'audio/webm' });
            const reader = new FileReader();
            reader.onload = () => {
                const dur = Math.floor(recordSeconds / 60) + ':' + (recordSeconds % 60).toString().padStart(2, '0');
                addMessageToChat({ sender: currentUser.username, receiver: activeChatWith, type: 'voice', voice_data: reader.result, voice_duration: dur });
            };
            reader.readAsDataURL(blob);
        };

        mediaRecorder.start();
        $('voice-record-bar').classList.remove('hidden');
        $('record-timer').textContent = '0:00';
        recordTimer = setInterval(() => {
            recordSeconds++;
            const m = Math.floor(recordSeconds / 60);
            const s = (recordSeconds % 60).toString().padStart(2, '0');
            $('record-timer').textContent = m + ':' + s;
        }, 1000);
    } catch (err) {
        alert('Microphone access denied or unavailable.');
    }
});

$('btn-voice').addEventListener('pointerup', () => {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
        clearInterval(recordTimer);
        mediaRecorder.stop();
        mediaRecorder = null;
        $('voice-record-bar').classList.add('hidden');
    }
});

$('btn-cancel-record').addEventListener('click', () => {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
        clearInterval(recordTimer);
        recordChunks = [];
        mediaRecorder.stop();
        mediaRecorder = null;
        $('voice-record-bar').classList.add('hidden');
    }
});

// ═══════════════════════════════════════════
// TYPING INDICATOR
// ═══════════════════════════════════════════

let typingBroadcastTimer = null;
let typingPollTimer = null;

msgInput.addEventListener('input', () => {
    if (!activeChatWith || !currentUser) return;
    $('typing-indicator').classList.remove('hidden');
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
        $('typing-indicator').classList.add('hidden');
    }, 1500);

    if (!typingBroadcastTimer) {
        typingBroadcastTimer = setTimeout(() => { typingBroadcastTimer = null; }, 2000);
        const typingKey = 'bchat_typing_' + activeChatWith;
        localStorage.setItem(typingKey, JSON.stringify({
            username: currentUser.username,
            timestamp: Date.now()
        }));
        setTimeout(() => {
            const current = JSON.parse(localStorage.getItem(typingKey) || '{}');
            if (current.username === currentUser.username) {
                localStorage.removeItem(typingKey);
            }
        }, 3000);
    }
});

function pollTypingIndicators() {
    if (!activeChatWith || !currentUser) return;
    const indicator = $('typing-indicator');
    if (!indicator) return;
    const typingKey = 'bchat_typing_' + currentUser.username;
    const typingData = JSON.parse(localStorage.getItem(typingKey) || '{}');
    const isOtherTyping = typingData.username && typingData.username !== currentUser.username && (Date.now() - typingData.timestamp < 3000);
    indicator.classList.toggle('hidden', !isOtherTyping);
    if (isOtherTyping) {
        const typingText = $('typing-text');
        if (typingText) typingText.textContent = typingData.username + ' is typing...';
    }
}

const originalOpenChat = openChat;
openChat = async function(otherUsername) {
    if (!requireChatAccess(otherUsername)) return;
    activeChatWith = otherUsername;
    
    // Start typing poll
    if (typingPollTimer) clearInterval(typingPollTimer);
    typingPollTimer = setInterval(pollTypingIndicators, 500);
    
    // Clear any stale typing data
    const typingKey = 'bchat_typing_' + otherUsername;
    const typingData = JSON.parse(localStorage.getItem(typingKey) || '{}');
    if (typingData.username === currentUser?.username) {
        localStorage.removeItem(typingKey);
    }
    
    // Hide typing indicator initially
    $('typing-indicator').classList.add('hidden');
    
    // Call original openChat logic
    await originalOpenChat(otherUsername);
};

$('btn-back').addEventListener('click', () => {
    if (typingPollTimer) { clearInterval(typingPollTimer); typingPollTimer = null; }
    if (activeChatWith && currentUser) {
        const typingKey = 'bchat_typing_' + activeChatWith;
        const typingData = JSON.parse(localStorage.getItem(typingKey) || '{}');
        if (typingData.username === currentUser.username) localStorage.removeItem(typingKey);
    }
    activeChatWith = null;
    chatView.classList.add('hidden');
    chatWelcome.classList.remove('hidden');
    sidebar.classList.remove('chat-open');
    chatArea.classList.add('chat-closed');
    emojiPicker.classList.add('hidden');
    $('btn-emoji').classList.remove('active');
    $('typing-indicator').classList.add('hidden');
    renderChatList();
});

// ═══════════════════════════════════════════
// VOICE & VIDEO CALL (Real Media)
// ═══════════════════════════════════════════

let callTimer = null;
let callSeconds = 0;
let callStream = null;
let callType = 'voice';
let facingMode = 'user';

async function startCall(type) {
    if (!activeChatWith) return;

    if (!navigator.onLine) {
        $('call-screen').classList.remove('hidden');
        $('call-offline-banner').classList.remove('hidden');
        $('call-error').classList.add('hidden');
        $('call-type-label').textContent = 'Cannot connect';
        $('call-type-label').style.animation = 'none';
        $('call-timer').textContent = '';
        $('call-video').classList.add('hidden');
        $('call-self-video').classList.add('hidden');
        $('btn-flip-cam').classList.add('hidden');
        $('call-avatar-wrap').classList.remove('hidden');
        setupCallHeader();
        return;
    }

    callType = type;
    callSeconds = 0;
    $('call-offline-banner').classList.add('hidden');
    $('call-error').classList.add('hidden');
    $('call-timer').textContent = '';
    $('call-video').classList.add('hidden');
    $('call-self-video').classList.add('hidden');
    $('btn-flip-cam').classList.add('hidden');
    $('call-avatar-wrap').classList.remove('hidden');
    $('btn-mute-call').classList.remove('active');
    $('btn-speaker-call').classList.remove('active');
    $('call-type-label').style.animation = '';

    setupCallHeader();
    $('call-type-label').textContent = type === 'video' ? '📹 Video Calling...' : '📞 Voice Calling...';
    $('call-screen').classList.remove('hidden');

    playRingSound();

    const constraints = type === 'video'
        ? { audio: true, video: { facingMode: facingMode } }
        : { audio: true, video: false };

    try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            throw new Error('This browser does not support microphone or camera access.');
        }

        callStream = await navigator.mediaDevices.getUserMedia(constraints);
        const callAudio = $('call-audio');
        if (callAudio) {
            callAudio.srcObject = callStream;
            callAudio.muted = false;
            callAudio.play().catch(() => {});
        }

        if (type === 'video') {
            $('call-self-video').srcObject = callStream;
            $('call-self-video').classList.remove('hidden');
            $('btn-flip-cam').classList.remove('hidden');
        }

        $('call-type-label').textContent = type === 'video' ? '📹 Video Call Connected' : '📞 Voice Call Connected';
        $('call-type-label').style.animation = 'none';

        callTimer = setInterval(() => {
            callSeconds++;
            const m = Math.floor(callSeconds / 60).toString().padStart(2, '0');
            const s = (callSeconds % 60).toString().padStart(2, '0');
            $('call-timer').textContent = m + ':' + s;

            if (!navigator.onLine) {
                $('call-offline-banner').classList.remove('hidden');
            } else {
                $('call-offline-banner').classList.add('hidden');
            }
        }, 1000);

    } catch (err) {
        $('call-type-label').textContent = 'Could not connect';
        $('call-type-label').style.animation = 'none';
        $('call-error').classList.remove('hidden');
        if (err.name === 'NotAllowedError') {
            $('call-error').textContent = 'Permission denied. Please allow microphone' + (type === 'video' ? ' and camera' : '') + ' access in your browser settings.';
        } else if (err.name === 'NotFoundError') {
            $('call-error').textContent = 'No ' + (type === 'video' ? 'camera or microphone' : 'microphone') + ' found on this device.';
        } else {
            $('call-error').textContent = 'Error: ' + err.message;
        }
    }
}

function setupCallHeader() {
    const users = getUsers();
    const user = users.find(u => u.username === activeChatWith);
    const name = user ? user.displayName : activeChatWith;
    $('call-name').textContent = name;
    $('call-avatar').textContent = name.charAt(0).toUpperCase();
    if (user?.avatar) {
        $('call-avatar-img').src = user.avatar;
        $('call-avatar-img').classList.remove('hidden');
    } else {
        $('call-avatar-img').classList.add('hidden');
    }
}

function endCall() {
    if (callStream) {
        callStream.getTracks().forEach(t => t.stop());
        callStream = null;
    }
    $('call-video').srcObject = null;
    $('call-self-video').srcObject = null;
    const callAudio = $('call-audio');
    if (callAudio) {
        callAudio.pause();
        callAudio.srcObject = null;
    }
    clearInterval(callTimer);
    callTimer = null;
    $('call-screen').classList.add('hidden');
    $('call-type-label').style.animation = '';
    $('call-video').classList.add('hidden');
    $('call-self-video').classList.add('hidden');

    if (callSeconds > 0 && activeChatWith) {
        const duration = Math.floor(callSeconds / 60) + ':' + (callSeconds % 60).toString().padStart(2, '0');
        const label = callType === 'video' ? '📹 Video call' : '📞 Voice call';
        addMessageToChat({
            sender: currentUser.username,
            text: label + ' · ' + duration,
            type: 'text',
            time: new Date().toISOString()
        });
    }
}

// Mute toggle
$('btn-mute-call').addEventListener('click', () => {
    const isMuted = $('btn-mute-call').classList.toggle('active');
    if (callStream) {
        const audioTracks = callStream.getAudioTracks();
        audioTracks.forEach(t => { t.enabled = !isMuted; });
    }
    const callAudio = $('call-audio');
    if (callAudio) {
        callAudio.muted = isMuted;
    }
});

// Speaker toggle
$('btn-speaker-call').addEventListener('click', () => {
    const isSpeakerOn = $('btn-speaker-call').classList.toggle('active');
    const callAudio = $('call-audio');
    if (callAudio) {
        callAudio.muted = !isSpeakerOn;
    }
});

// Flip camera
$('btn-flip-cam').addEventListener('click', async () => {
    if (!callStream || callType !== 'video') return;
    facingMode = facingMode === 'user' ? 'environment' : 'user';
    callStream.getVideoTracks().forEach(t => t.stop());
    try {
        const newStream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: facingMode } });
        const newVideoTrack = newStream.getVideoTracks()[0];
        const oldAudioTrack = callStream.getAudioTracks()[0];
        callStream = new MediaStream([oldAudioTrack, newVideoTrack]);
        $('call-self-video').srcObject = callStream;
    } catch (e) {}
});

// Internet status listener during calls
window.addEventListener('offline', () => {
    if (!$('call-screen').classList.contains('hidden')) {
        $('call-offline-banner').classList.remove('hidden');
    }
});

window.addEventListener('online', () => {
    $('call-offline-banner').classList.add('hidden');
});

function playRingSound() {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        for (let i = 0; i < 3; i++) {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.frequency.setValueAtTime(440, ctx.currentTime + i * 0.6);
            osc.frequency.setValueAtTime(520, ctx.currentTime + i * 0.6 + 0.15);
            gain.gain.setValueAtTime(0.08, ctx.currentTime + i * 0.6);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.6 + 0.4);
            osc.start(ctx.currentTime + i * 0.6);
            osc.stop(ctx.currentTime + i * 0.6 + 0.4);
        }
    } catch (e) {}
}

$('btn-voice-call').addEventListener('click', () => startCall('voice'));
$('btn-video-call').addEventListener('click', () => startCall('video'));
$('btn-end-call').addEventListener('click', endCall);

// ═══════════════════════════════════════════
// EMOJI PICKER
// ═══════════════════════════════════════════

const EMOJIS = {
    smileys: ['😀','😃','😄','😁','😆','😅','🤣','😂','🙂','😊','😇','🥰','😍','🤩','😘','😗','😚','😙','🥲','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🫢','🤫','🤔','🫡','🤐','🤨','😐','😑','😶','🫥','😏','😒','🙄','😬','🤥','😌','😔','😪','🤤','😴','😷','🤒','🤕','🤢','🤮','🥴','😵','🤯','🥳','🥸','😎','🤓','🧐','😕','🫤','😟','🙁','😮','😯','😲','😳','🥺','🥹','😦','😧','😨','😰','😥','😢','😭','😱','😖','😣','😞','😓','😩','😫','🥱','😤','😡','😠','🤬','😈','👿','💀','☠️','💩','🤡','👹','👺','👻','👽','👾','🤖'],
    gestures: ['👋','🤚','🖐️','✋','🖖','🫱','🫲','🫳','🫴','👌','🤌','🤏','✌️','🤞','🫰','🤟','🤘','🤙','👈','👉','👆','🖕','👇','☝️','🫵','👍','👎','✊','👊','🤛','🤜','👏','🙌','🫶','👐','🤲','🤝','🙏','✍️','💅','🤳','💪','🦾','🦿','🦵','🦶','👂','🦻','👃','🧠','🫀','🫁','🦷','🦴','👀','👁️','👅','👄'],
    hearts: ['❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❤️‍🔥','❤️‍🩹','❣️','💕','💞','💓','💗','💖','💘','💝','💟','♥️','💋','💯','💢','💥','💫','💦','💨','🕊️','✨','⭐','🌟','💤','🎵','🎶','🔥','💐','🌹','🌸','🌺','🌻','🌼','🌷'],
    animals: ['🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🙈','🙉','🙊','🐒','🐔','🐧','🐦','🐤','🐣','🐥','🦆','🦅','🦉','🦇','🐺','🐗','🐴','🦄','🐝','🪱','🐛','🦋','🐌','🐞','🐜','🦟','🦗','🕷️','🐢','🐍','🦎','🦂','🐠','🐟','🐡','🐬','🐳','🐋','🦈','🐊','🐅','🐆','🦓','🦍','🦧','🐘','🦛','🦏','🐪','🐫','🦒','🦘','🐃','🐂','🐄','🐎'],
    food: ['🍏','🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓','🫐','🍈','🍒','🍑','🥭','🍍','🥥','🥝','🍅','🍆','🥑','🥦','🥬','🥒','🌶️','🫑','🌽','🥕','🫒','🧄','🧅','🥔','🍠','🫘','🥐','🥯','🍞','🧀','🥚','🍳','🥞','🧇','🥓','🥩','🍗','🍖','🌭','🍔','🍟','🍕','🫓','🥪','🌮','🌯','🫔','🥙','🧆','🥚','🍝','🍜','🍲','🍛','🍣','🍱','🥟','🍤','🍙','🍚','🍘','🍥','🥠','🍢','🍡','🍧','🍨','🍦','🥧','🧁','🍰','🎂','🍮','🍭','🍬','🍫','🍿','🧈','🍩','🍪','☕','🫖','🍵','🧃','🥤','🧋','🍶','🍺','🍻','🥂','🍷','🍸','🍹','🧉','🍾'],
    activities: ['⚽','🏀','🏈','⚾','🥎','🎾','🏐','🏉','🥏','🎱','🪀','🏓','🏸','🏒','🥅','⛳','🏹','🎣','🤿','🥊','🥋','🎽','🛹','🛼','🛷','⛸️','🥌','🎿','⛷️','🏂','🏋️','🤸','🤺','⛹️','🤾','🏇','🧘','🏄','🏊','🤽','🚣','🧗','🚴','🏆','🥇','🥈','🥉','🏅','🎖️','🎗️','🎪','🎭','🎨','🎬','🎤','🎧','🎼','🎹','🥁','🪘','🎷','🎺','🪗','🎸','🪕','🎻','🎲','♟️','🎯','🎳','🎮','🕹️'],
    objects: ['💡','🔦','🕯️','📱','💻','⌨️','🖥️','🖨️','🖱️','💽','💾','💿','📷','📹','🎥','📞','☎️','📟','📠','📺','📻','🎙️','⏱️','⏰','🔔','📣','📢','🔍','🔎','💰','💵','💴','💶','💷','💳','💎','⚖️','🔧','🔨','⚒️','🛠️','⛏️','🔩','⚙️','🧱','🔗','📎','🖇️','📌','📍','🏷️','🎁','🎀','🎊','🎉','🎈','🎏','🎐','🪭','🎑','📫','📪','📬','📭','📮','📦','📜','📃','📄','📑','🧾','📊','📈','📉','📆','📅','🗓️','📇','🗃️','🗳️','🗄️','📋','📁','📂','📰','🗞️','📓','📔','📒','📕','📗','📘','📙','📚','📖','🔖','🔗','📐','📏','🧮']
};

let currentEmojiCat = 'smileys';

function renderEmojis(category) {
    currentEmojiCat = category;
    emojiGrid.innerHTML = '';
    document.querySelectorAll('.emoji-tab').forEach(t => t.classList.toggle('active', t.dataset.cat === category));
    EMOJIS[category].forEach(emoji => {
        const btn = document.createElement('button');
        btn.className = 'emoji-item';
        btn.textContent = emoji;
        btn.addEventListener('click', () => {
            msgInput.value += emoji;
            msgInput.focus();
        });
        emojiGrid.appendChild(btn);
    });
}

$('btn-emoji').addEventListener('click', () => {
    const isHidden = emojiPicker.classList.contains('hidden');
    emojiPicker.classList.toggle('hidden');
    $('btn-emoji').classList.toggle('active', isHidden);
    if (isHidden) renderEmojis(currentEmojiCat);
});

document.querySelectorAll('.emoji-tab').forEach(tab => {
    tab.addEventListener('click', () => renderEmojis(tab.dataset.cat));
});

msgInput.addEventListener('focus', () => {
    emojiPicker.classList.add('hidden');
    $('btn-emoji').classList.remove('active');
});

// ═══════════════════════════════════════════
// BACK BUTTON (mobile)
// ═══════════════════════════════════════════

$('btn-back').addEventListener('click', () => {
    activeChatWith = null;
    chatView.classList.add('hidden');
    chatWelcome.classList.remove('hidden');
    sidebar.classList.remove('chat-open');
    chatArea.classList.add('chat-closed');
    emojiPicker.classList.add('hidden');
    $('btn-emoji').classList.remove('active');
    renderChatList();
});

// ═══════════════════════════════════════════
// NEW CHAT MODAL
// ═══════════════════════════════════════════

$('btn-new-chat').addEventListener('click', () => {
    $('new-chat-modal').classList.remove('hidden');
    $('add-code-input').value = '';
    $('add-nickname-input').value = '';
    $('add-code-error').textContent = '';
    $('user-results').innerHTML = '';
    setTimeout(() => $('add-code-input').focus(), 60);
});

$('btn-toggle-archive').addEventListener('click', () => {
    showArchivedChats = !showArchivedChats;
    updateArchiveToggleButton();
    renderChatList();
});

$('btn-chat-more').addEventListener('click', (e) => {
    e.stopPropagation();
    const rect = $('btn-chat-more').getBoundingClientRect();
    showChatActionsMenu(rect.left, rect.bottom + 8);
});

$('chat-actions-menu')?.querySelectorAll('.chat-action-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        hideChatActionsMenu();
        if (!activeChatWith) return;
        if (action === 'archive') {
            toggleArchiveChat(activeChatWith);
        } else if (action === 'lock') {
            toggleLockChat(activeChatWith);
        } else if (action === 'password') {
            const password = window.prompt('Set a master password for locked chats', getLockPassword());
            if (password !== null) {
                setLockPassword(password.trim());
                showToast(password.trim() ? 'Lock password saved' : 'Lock password cleared', 'success', 2200);
            }
        }
    });
});

document.addEventListener('click', (e) => {
    if (!e.target.closest('#chat-actions-menu') && !e.target.closest('#btn-chat-more')) hideChatActionsMenu();
});

$('btn-close-modal').addEventListener('click', () => { $('new-chat-modal').classList.add('hidden'); });
$('new-chat-modal').addEventListener('click', (e) => {
    if (e.target === $('new-chat-modal')) $('new-chat-modal').classList.add('hidden');
});

// Start a chat by looking up another user's 4-digit code.
// ── Custom contact names (private per-user, like naming a contact in WhatsApp) ──
function getNicknames() { return JSON.parse(localStorage.getItem('bchat_nicknames_' + (currentUser?.username || '')) || '{}'); }
function saveNicknames(n) { localStorage.setItem('bchat_nicknames_' + currentUser.username, JSON.stringify(n)); }
function setNickname(username, name) {
    const n = getNicknames();
    if (name && name.trim()) n[username] = name.trim(); else delete n[username];
    saveNicknames(n);
}
// The name to show for a contact: your custom name if set, else their display name.
function getContactName(username, userObj) {
    const nn = getNicknames()[username];
    if (nn) return nn;
    if (userObj) return uName(userObj);
    return username;
}

async function startChatByCode() {
    const input = $('add-code-input');
    const nickInput = $('add-nickname-input');
    const error = $('add-code-error');
    const results = $('user-results');
    const code = input.value.trim();
    error.textContent = '';
    results.innerHTML = '';

    if (!/^\d{4}$/.test(code)) { error.textContent = 'Enter a 4-digit code.'; return; }
    if (currentUser.code && code === String(currentUser.code)) { error.textContent = "That's your own code!"; return; }
    if (!navigator.onLine) { error.textContent = 'You need internet to add someone.'; return; }

    try {
        const data = await apiJson(`/api/users?code=${encodeURIComponent(code)}`);
        const user = data?.user || null;
        if (!user) { error.textContent = 'No one found with code ' + code + '. Double-check it.'; return; }
        if (nickInput && nickInput.value.trim()) setNickname(user.username, nickInput.value);
        $('new-chat-modal').classList.add('hidden');
        openChat(user.username);
    } catch (err) {
        error.textContent = 'Unable to look up that code right now.';
    }

}

$('add-code-input').addEventListener('input', () => {
    // digits only
    $('add-code-input').value = $('add-code-input').value.replace(/\D/g, '').slice(0, 4);
});
$('add-code-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); startChatByCode(); } });

// Rename the current contact (custom private name)
$('btn-rename-contact')?.addEventListener('click', () => {
    if (!activeChatWith) return;
    const name = prompt('Name this contact (leave blank to use their real name):', $('chat-name').textContent);
    if (name === null) return;
    setNickname(activeChatWith, name);
    openChat(activeChatWith);
    renderChatList();
    showToast(name.trim() ? '✏️ Contact renamed' : 'Custom name removed', 'success', 2000);
});
$('btn-add-by-code').addEventListener('click', startChatByCode);


// ═══════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════

function formatLastSeen(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return diffMin + ' min ago';
    const diffHrs = Math.floor(diffMin / 60);
    if (diffHrs < 24 && now.getDate() === date.getDate()) return 'today at ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diffHrs < 48) return 'yesterday at ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' at ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatTime(date) {
    const now = new Date();
    const diff = now - date;
    if (diff < 86400000 && now.getDate() === date.getDate()) return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diff < 172800000) return 'Yesterday';
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function formatDate(date) {
    const now = new Date();
    const diff = now - date;
    if (diff < 86400000 && now.getDate() === date.getDate()) return 'Today';
    if (diff < 172800000) return 'Yesterday';
    return date.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
}

function formatMessageTime(date) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatMsgText(text) {
    let s = escapeHtml(text);
    s = s.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline;">$1</a>');
    s = s.replace(/\*([^*]+)\*/g, '<strong>$1</strong>');
    s = s.replace(/\_([^_]+)\_/g, '<em>$1</em>');
    s = s.replace(/\~([^~]+)\~/g, '<del>$1</del>');
    return s;
}

function scrollToBottom() {
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function startReplyTo(msg) {
    if (!msg) return;
    replyToMsg = msg;
    $('reply-bar-text').textContent = msg.type === 'photo' ? '📷 Photo' : (msg.type === 'voice' ? '🎤 Voice note' : (msg.text || ''));
    $('reply-bar').classList.remove('hidden');
    msgInput.focus();
}

// Scroll-to-bottom floating button (WhatsApp-style)
const scrollBottomBtn = $('scroll-bottom-btn');
if (scrollBottomBtn) {
    messagesDiv.addEventListener('scroll', () => {
        const nearBottom = messagesDiv.scrollHeight - messagesDiv.scrollTop - messagesDiv.clientHeight < 140;
        scrollBottomBtn.classList.toggle('show', !nearBottom);
    });
    scrollBottomBtn.addEventListener('click', () => { scrollToBottom(); scrollBottomBtn.classList.remove('show'); });
}

// ═══════════════════════════════════════════
// BOTTOM TAB BAR
// ═══════════════════════════════════════════

function activateTab(tabId) {
    document.querySelectorAll('.bottom-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === tabId));

    if (tabId === 'tab-status') refreshStatusTab();
    if (tabId === 'tab-ads') renderAds();
    if (tabId === 'tab-ai') loadAiTab();
}

document.querySelectorAll('.bottom-tab').forEach(tab => {
    tab.addEventListener('click', () => activateTab(tab.dataset.tab));
});

const guideButton = $('btn-guide');
if (guideButton) {
    guideButton.addEventListener('click', () => {
        activateTab('tab-tutorial');
        showGuideStep(0);
    });
}

// ═══════════════════════════════════════════
// STATUS
// ═══════════════════════════════════════════

let statusPhotoData = null;

async function refreshStatusTab() {
    if (!currentUser) return;
    $('status-my-avatar').textContent = uName(currentUser).charAt(0).toUpperCase();
    if (currentUser.avatar) {
        $('status-my-avatar-img').src = currentUser.avatar;
        $('status-my-avatar-img').classList.remove('hidden');
    } else {
        $('status-my-avatar-img').classList.add('hidden');
    }

    const statuses = getStatuses();
    const now = Date.now();
    const valid = statuses.filter(s => now - new Date(s.time).getTime() < 86400000);
    if (valid.length !== statuses.length) saveStatuses(valid);

    const myStatus = valid.filter(s => s.username === currentUser.username);
    $('my-status-hint').textContent = myStatus.length > 0
        ? myStatus.length + ' update' + (myStatus.length > 1 ? 's' : '') + ' · ' + formatTime(new Date(myStatus[myStatus.length - 1].time))
        : 'Tap to add status update';

    const others = {};
    valid.filter(s => s.username !== currentUser.username).forEach(s => {
        if (!others[s.username]) others[s.username] = [];
        others[s.username].push(s);
    });

    const list = $('status-list');
    const usernames = Object.keys(others);
    if (usernames.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No status updates yet</p></div>';
        return;
    }

    const users = getUsers();
    list.innerHTML = '';
    usernames.forEach(uname => {
        const user = users.find(u => u.username === uname);
        const displayName = user ? user.displayName : uname;
        const latest = others[uname][others[uname].length - 1];
        const item = document.createElement('div');
        item.className = 'status-item';
        item.innerHTML = `
            <div class="status-ring">
                <div class="status-ring-inner">
                    <div class="user-avatar">${displayName.charAt(0).toUpperCase()}</div>
                    ${user?.avatar ? `<img src="${user.avatar}" alt="${escapeHtml(displayName)}">` : ''}
                </div>
            </div>
            <div class="status-info">
                <strong>${escapeHtml(displayName)}</strong>
                <span>${formatTime(new Date(latest.time))}</span>
            </div>
        `;
        item.addEventListener('click', () => viewStatus(uname, others[uname]));
        list.appendChild(item);
    });
}

$('my-status-bar').addEventListener('click', () => {
    statusPhotoData = null;
    $('status-text-input').value = '';
    $('status-photo-preview').classList.add('hidden');
    $('status-post-panel').classList.remove('hidden');
});

$('btn-close-status-post').addEventListener('click', () => {
    $('status-post-panel').classList.add('hidden');
});

$('status-photo-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    resizeImage(file, 600, (data) => {
        statusPhotoData = data;
        $('status-photo-preview').src = data;
        $('status-photo-preview').classList.remove('hidden');
    });
    e.target.value = '';
});

$('btn-post-status').addEventListener('click', () => {
    const text = $('status-text-input').value.trim();
    if (!text && !statusPhotoData) return;

    const statuses = getStatuses();
    statuses.push({
        username: currentUser.username,
        text: text,
        photo: statusPhotoData || null,
        time: new Date().toISOString()
    });
    saveStatuses(statuses);
    statusPhotoData = null;
    $('status-post-panel').classList.add('hidden');
    refreshStatusTab();
});

function viewStatus(username, items) {
    let idx = 0;
    const users = getUsers();
    const user = users.find(u => u.username === username);
    const displayName = user ? user.displayName : username;

    function showItem() {
        const s = items[idx];
        const viewer = document.createElement('div');
        viewer.className = 'status-viewer';
        viewer.innerHTML = `
            <div class="status-progress"><div class="status-progress-fill"></div></div>
            <div class="status-viewer-header">
                <div class="user-avatar">${displayName.charAt(0).toUpperCase()}</div>
                <div class="status-viewer-info">
                    <strong>${escapeHtml(displayName)}</strong>
                    <span>${formatTime(new Date(s.time))}</span>
                </div>
                <button class="viewer-close" style="margin-left:auto">&times;</button>
            </div>
            <div class="status-viewer-body">
                ${s.photo ? `<img src="${s.photo}" alt="Status photo">` : ''}
                ${s.text ? `<p>${escapeHtml(s.text)}</p>` : ''}
            </div>
        `;

        document.body.appendChild(viewer);

        const close = () => { viewer.remove(); };
        viewer.querySelector('.viewer-close').addEventListener('click', close);

        const timer = setTimeout(() => {
            viewer.remove();
            idx++;
            if (idx < items.length) showItem();
        }, 5000);

        viewer.addEventListener('click', (e) => {
            if (e.target === viewer || e.target.closest('.status-viewer-body')) {
                clearTimeout(timer);
                viewer.remove();
                idx++;
                if (idx < items.length) showItem();
            }
        });
    }

    showItem();
}

// ═══════════════════════════════════════════
// ADS & ANNOUNCEMENTS
// ═══════════════════════════════════════════

let adPhotoData = null;

function renderAds() {
    const ads = getAds();
    const list = $('ads-list');

    if (ads.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No ads or announcements yet</p><p class="hint">Post something for everyone to see</p></div>';
        return;
    }

    const users = getUsers();
    list.innerHTML = '';

    ads.slice().reverse().forEach((ad, reverseIdx) => {
        const realIdx = ads.length - 1 - reverseIdx;
        const user = users.find(u => u.username === ad.username);
        const displayName = user ? user.displayName : ad.username;
        const isOwner = currentUser && ad.username === currentUser.username;

        const card = document.createElement('div');
        card.className = 'ad-card';
        card.innerHTML = `
            ${ad.photo ? `<img src="${ad.photo}" alt="${escapeHtml(ad.title)}" class="ad-card-img">` : ''}
            <div class="ad-card-body">
                <div class="ad-card-title">${escapeHtml(ad.title)}</div>
                <div class="ad-card-text">${escapeHtml(ad.text)}</div>
                <div class="ad-card-meta">
                    <span class="ad-card-author">${escapeHtml(displayName)}</span>
                    <span>${formatTime(new Date(ad.time))}</span>
                    <span class="ad-pin-badge">&#128204; Pinned</span>
                    ${isOwner ? `<button class="ad-delete-btn" data-idx="${realIdx}">Delete</button>` : ''}
                </div>
            </div>
        `;

        const img = card.querySelector('.ad-card-img');
        if (img) img.addEventListener('click', () => openImageViewer(ad.photo));

        const delBtn = card.querySelector('.ad-delete-btn');
        if (delBtn) delBtn.addEventListener('click', () => {
            const allAds = getAds();
            allAds.splice(parseInt(delBtn.dataset.idx), 1);
            saveAds(allAds);
            renderAds();
        });

        list.appendChild(card);
    });
}

$('btn-post-ad').addEventListener('click', () => {
    adPhotoData = null;
    $('ad-title-input').value = '';
    $('ad-text-input').value = '';
    $('ad-photo-preview').classList.add('hidden');
    $('ad-post-panel').classList.remove('hidden');
});

$('btn-close-ad-post').addEventListener('click', () => {
    $('ad-post-panel').classList.add('hidden');
});

$('ad-photo-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    resizeImage(file, 600, (data) => {
        adPhotoData = data;
        $('ad-photo-preview').src = data;
        $('ad-photo-preview').classList.remove('hidden');
    });
    e.target.value = '';
});

$('btn-submit-ad').addEventListener('click', () => {
    const title = $('ad-title-input').value.trim();
    const text = $('ad-text-input').value.trim();
    if (!title) return;

    const ads = getAds();
    ads.push({
        username: currentUser.username,
        title: title,
        text: text,
        photo: adPhotoData || null,
        time: new Date().toISOString()
    });
    saveAds(ads);
    adPhotoData = null;
    $('ad-post-panel').classList.add('hidden');
    renderAds();
});

// ═══════════════════════════════════════════
// AI ASSISTANT (Hybrid: Gemini API online + built-in offline)
// ═══════════════════════════════════════════

// Paste your Gemini API key here — leave empty to use built-in AI only
function getAiHistory() { return JSON.parse(localStorage.getItem('bchat_ai_history_' + (currentUser?.username || '')) || '[]'); }
function saveAiHistory(h) { localStorage.setItem('bchat_ai_history_' + currentUser.username, JSON.stringify(h)); }

function loadAiTab() { renderAiMessages(); }

$('btn-clear-ai').addEventListener('click', () => {
    if (!currentUser) return;
    saveAiHistory([]);
    renderAiMessages();
});

function renderAiMessages() {
    const history = getAiHistory();
    const container = $('ai-messages');
    container.innerHTML = '<div class="message received" style="animation:none;"><div class="msg-text">Hi! I\'m <strong>B AI</strong> — your built-in assistant. I work offline, no internet needed! Try asking me:<br><br>• Math: <em>"what is 245 * 38"</em><br>• Time: <em>"what time is it"</em><br>• <strong>Images: <em>"create an image of a sunset"</em></strong><br>• Facts, jokes, quotes, tips<br>• Translations<br>• Or just chat with me!</div></div>';
    history.forEach(m => {
        const div = document.createElement('div');
        div.className = 'message ' + (m.role === 'user' ? 'sent' : 'received');
        if (m.image) {
            div.innerHTML = `<div class="msg-text">${formatMsgText(m.text)}</div><img src="${m.image}" alt="AI Generated" class="msg-photo" style="max-width:280px;margin-top:8px;">`;
            div.querySelector('.msg-photo').addEventListener('click', () => openImageViewer(m.image));
        } else {
            div.innerHTML = `<div class="msg-text">${formatMsgText(m.text)}</div>`;
        }
        container.appendChild(div);
    });
    container.scrollTop = container.scrollHeight;
}

$('btn-ai-send').addEventListener('click', sendAiMessage);
$('ai-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); sendAiMessage(); }
});

async function sendAiMessage() {
    const text = $('ai-input').value.trim();
    if (!text) return;
    $('ai-input').value = '';

    const history = getAiHistory();
    history.push({ role: 'user', text: text });
    saveAiHistory(history);
    renderAiMessages();

    const typing = document.createElement('div');
    typing.className = 'ai-typing';
    typing.innerHTML = '<span></span><span></span><span></span>';
    $('ai-messages').appendChild(typing);
    $('ai-messages').scrollTop = $('ai-messages').scrollHeight;

    const builtInReply = generateAiReply(text);

    if (builtInReply.startsWith('__IMAGE_GEN__')) {
        const prompt = builtInReply.replace('__IMAGE_GEN__', '').trim();
        if (!navigator.onLine) {
            typing.remove();
            history.push({ role: 'model', text: '🎨 Image generation requires an internet connection. Please connect and try again.' });
            saveAiHistory(history);
            renderAiMessages();
            return;
        }
        const imageUrl = 'https://image.pollinations.ai/prompt/' + encodeURIComponent(prompt) + '?width=512&height=512&nologo=true&seed=' + Math.floor(Math.random() * 100000);
        const img = new Image();
        img.onload = () => {
            typing.remove();
            history.push({ role: 'model', text: '🎨 Here\'s your image for: *"' + prompt + '"*', image: imageUrl });
            saveAiHistory(history);
            renderAiMessages();
        };
        img.onerror = () => {
            typing.remove();
            history.push({ role: 'model', text: '⚠️ Failed to generate image. Check your internet connection and try again.' });
            saveAiHistory(history);
            renderAiMessages();
        };
        img.src = imageUrl;
        return;
    }

    if (navigator.onLine) {
        try {
            const messages = [
                { role: 'system', content: 'You are B AI, a warm, friendly assistant built into the B CHAT messaging app by Billy Hawkins. Keep replies helpful, natural, and concise.' },
                ...history.map(m => ({ role: m.role === 'user' ? 'user' : 'assistant', content: m.text }))
            ];
            const data = await apiJson('/api/ai/chat', {
                method: 'POST',
                body: JSON.stringify({ messages })
            });
            typing.remove();
            history.push({ role: 'model', text: data?.reply || builtInReply });
        } catch (e) {
            typing.remove();
            history.push({ role: 'model', text: builtInReply });
        }
        saveAiHistory(history);
        renderAiMessages();
    } else {
        showToast("📴 You're offline — B AI is using offline mode.", 'error');
        setTimeout(() => {
            typing.remove();
            history.push({ role: 'model', text: '📴 _You\'re offline, so I\'m in offline mode._\n\n' + builtInReply });
            saveAiHistory(history);
            renderAiMessages();
        }, 600 + Math.random() * 800);
    }
}

function generateAiReply(input) {
    const q = input.toLowerCase().trim();

    const mathMatch = q.match(/(?:what(?:'s| is)|calculate|solve|compute)\s+([\d\s\+\-\*\/\.\(\)\^%]+)/);
    if (mathMatch) {
        try {
            const expr = mathMatch[1].replace(/\^/g, '**').replace(/x/g, '*');
            const result = Function('"use strict"; return (' + expr + ')')();
            return '🔢 ' + mathMatch[1].trim() + ' = *' + result + '*';
        } catch (e) { return "Hmm, I couldn't calculate that. Try: *what is 25 * 4*"; }
    }
    const directMath = q.match(/^[\d\s\+\-\*\/\.\(\)\^%]+$/);
    if (directMath) {
        try { return '🔢 = *' + Function('"use strict"; return (' + q.replace(/\^/g,'**') + ')')() + '*'; } catch(e) {}
    }

    if (q.includes('time')) return '🕐 It\'s currently *' + new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}) + '*';
    if (q.includes('date') || q.includes('today') || q.includes('what day')) return '📅 Today is *' + new Date().toLocaleDateString([], {weekday:'long',year:'numeric',month:'long',day:'numeric'}) + '*';

    if (/^(hi|hello|hey|yo|sup|howdy|hola|good\s?(morning|afternoon|evening|night))/.test(q)) {
        return ['Hey there! 😊 How can I help you?','Hello! 👋 What\'s on your mind?','Hi! Nice to chat! What can I do for you?','Hey! 😄 Ask me anything!'][Math.floor(Math.random()*4)];
    }
    if (q.includes('how are you') || q.includes('how r u')) {
        return ['I\'m great, thanks! 😊 How about you?','Running at full speed! ⚡ What can I help with?','Wonderful! Ready to assist!'][Math.floor(Math.random()*3)];
    }
    if (q.includes('who are you') || q.includes('what are you') || q.includes('your name')) {
        return '🤖 I\'m *B AI*, your built-in assistant! I help with math, facts, jokes, tips, translations, and conversation. I work 100% offline!';
    }
    if (q.includes('who built you') || q.includes('who made you') || q.includes('who created you') || q.includes('developer')) {
        return '🛠️ I was built into *B CHAT* by the app developer, *Billy Hawkins*. I\'m your personal AI assistant that lives right inside the app!';
    }
    if (q.includes('what is b chat') || q.includes('about this app') || q.includes('about b chat')) {
        return '💬 *B CHAT* is a messaging app for family and friends! It has chats, voice/video calls, status updates, an AI assistant (me!), ads board, emojis, voice notes, and more!';
    }
    if (q.includes('meaning of') || q.includes('define ') || q.includes('what does') || q.includes('what is a ') || q.includes('what is an ')) {
        return '📖 I\'m a simple offline AI so I can\'t look up definitions right now. For detailed answers, try asking me when online mode is available, or check a dictionary app!';
    }
    if (/\b(create|generate|make|draw|paint|design)\b/.test(q) && /\b(image|picture|photo|art|illustration|icon|logo|wallpaper|poster|pic)\b/.test(q)) {
        return '__IMAGE_GEN__' + input;
    }
    if (/^(create|generate|make|draw|paint|design)\s/.test(q) || /\b(image|picture|pic|photo)\s*(of|about|with|showing|for)\b/.test(q)) {
        return '__IMAGE_GEN__' + input;
    }

    if (q.includes('joke') || q.includes('funny') || q.includes('laugh')) {
        const j = ['😄 Why don\'t scientists trust atoms? They make up everything!','😂 What do you call a fake noodle? An *impasta*!','🤣 Why did the scarecrow win an award? He was *outstanding* in his field!','😆 I told my wife she was drawing her eyebrows too high. She looked surprised.','😄 What do you call a bear with no teeth? A *gummy bear*!','🤣 Why don\'t eggs tell jokes? They\'d *crack* each other up!','😂 I\'m reading a book on anti-gravity. Impossible to put down!','😄 What did the ocean say to the beach? Nothing, it just *waved*.','🤣 Why did the bicycle fall over? It was *two-tired*!','😂 What do you call a dog that does magic? A *Labracadabrador*!'];
        return j[Math.floor(Math.random()*j.length)];
    }

    if (q.includes('quote') || q.includes('motivat') || q.includes('inspir')) {
        const qs = ['💫 _"The only way to do great work is to love what you do."_ — Steve Jobs','🌟 _"Believe you can and you\'re halfway there."_ — Theodore Roosevelt','✨ _"In the middle of difficulty lies opportunity."_ — Albert Einstein','💪 _"It does not matter how slowly you go as long as you do not stop."_ — Confucius','🔥 _"Success is not final, failure is not fatal: courage to continue counts."_ — Churchill','🌈 _"The future belongs to those who believe in the beauty of their dreams."_ — Eleanor Roosevelt','⭐ _"You are never too old to set another goal or dream a new dream."_ — C.S. Lewis','🚀 _"Don\'t watch the clock; do what it does. Keep going."_ — Sam Levenson'];
        return qs[Math.floor(Math.random()*qs.length)];
    }

    if (q.includes('fact') || q.includes('did you know') || q.includes('tell me something')) {
        const f = ['🧠 Honey never spoils. 3,000-year-old honey from Egyptian tombs was still edible!','🐙 An octopus has three hearts, nine brains, and blue blood!','🌍 A day on Venus is longer than a year on Venus!','🍌 Bananas are naturally radioactive!','💎 Diamonds can be made from peanut butter under extreme pressure!','🦈 Sharks have existed longer than trees — about 400 million years!','🧴 Hot water freezes faster than cold water (Mpemba effect)!','🐝 A single bee produces only 1/12th of a teaspoon of honey in its lifetime!','📱 The first text message ever sent was "Merry Christmas" in 1992!','🌊 The ocean produces over 50% of the world\'s oxygen!'];
        return f[Math.floor(Math.random()*f.length)];
    }

    if (q.includes('weather') || q.includes('temperature')) return '🌤️ I work offline so I can\'t check live weather. Try your phone\'s weather app!';

    if (q.includes('tip') || q.includes('advice') || q.includes('suggest')) {
        const t = ['💡 *Productivity:* If it takes less than 2 minutes, do it now!','💡 *Health:* Drink water first thing in the morning!','💡 *Tech:* Ctrl+Shift+T reopens your last closed browser tab!','💡 *Anxiety:* Name 5 things you see, 4 feel, 3 hear, 2 smell, 1 taste.','💡 *Money:* 50/30/20 rule — 50% needs, 30% wants, 20% savings!','💡 *Sleep:* Avoid screens 30 min before bed for better rest!'];
        return t[Math.floor(Math.random()*t.length)];
    }

    if (q.includes('translate') || q.includes('how do you say')) {
        const dict = {
            'hello':{ es:'Hola',fr:'Bonjour',sw:'Habari',zh:'你好',ar:'مرحبا' },
            'thank you':{ es:'Gracias',fr:'Merci',sw:'Asante',zh:'谢谢',ar:'شكرا' },
            'i love you':{ es:'Te amo',fr:'Je t\'aime',sw:'Nakupenda',zh:'我爱你',ar:'أحبك' },
            'goodbye':{ es:'Adiós',fr:'Au revoir',sw:'Kwaheri',zh:'再见',ar:'مع السلامة' },
            'good morning':{ es:'Buenos días',fr:'Bonjour',sw:'Habari za asubuhi',zh:'早上好',ar:'صباح الخير' },
            'please':{ es:'Por favor',fr:'S\'il vous plaît',sw:'Tafadhali',zh:'请',ar:'من فضلك' },
            'yes':{ es:'Sí',fr:'Oui',sw:'Ndiyo',zh:'是',ar:'نعم' },
            'no':{ es:'No',fr:'Non',sw:'Hapana',zh:'不',ar:'لا' }
        };
        for (const [word, langs] of Object.entries(dict)) {
            if (q.includes(word)) {
                return '🌍 *"' + word.charAt(0).toUpperCase()+word.slice(1) + '"*:\n🇪🇸 ' + langs.es + '\n🇫🇷 ' + langs.fr + '\n🇰🇪 ' + langs.sw + '\n🇨🇳 ' + langs.zh + '\n🇸🇦 ' + langs.ar;
            }
        }
        return '🌍 Try: *"translate hello"*, *"translate thank you"*, *"translate i love you"*, *"translate goodbye"*';
    }

    if (q.includes('roll') || q.includes('dice')) return '🎲 You rolled a *' + (Math.floor(Math.random()*6)+1) + '*!';
    if (q.includes('coin') || q.includes('flip')) return '🪙 ' + (Math.random()>0.5 ? '*Heads!*' : '*Tails!*');
    if (q.includes('random number')) return '🔢 Your random number: *' + (Math.floor(Math.random()*100)+1) + '*';

    // Magic 8-ball / decisions
    if (q.includes('8 ball') || q.includes('8ball') || /^(should|will|is|are|can|do|does|did|would) /.test(q) && q.includes('?')) {
        const ball = ['🎱 It is certain.','🎱 Without a doubt.','🎱 Yes, definitely!','🎱 Signs point to yes.','🎱 Ask again later. 🤔','🎱 Better not tell you now.','🎱 Don\'t count on it.','🎱 My reply is no.','🎱 Very doubtful.','🎱 Most likely yes! 😊'];
        return ball[Math.floor(Math.random()*ball.length)];
    }

    // Pick one for me: "choose pizza or pasta"
    if ((q.includes('pick') || q.includes('choose') || q.includes('decide')) && q.includes(' or ')) {
        const opts = input.split(/\bor\b/i).map(s => s.replace(/^.*\b(pick|choose|decide)\b/i,'').trim()).filter(Boolean);
        if (opts.length >= 2) return '🤔 I\'d go with... *' + opts[Math.floor(Math.random()*opts.length)] + '*!';
    }

    // Riddles
    if (q.includes('riddle')) {
        const r = ['🧩 What has keys but no locks, space but no room, and you can enter but can\'t go in?\n\n_(A keyboard!)_','🧩 What gets wetter the more it dries?\n\n_(A towel!)_','🧩 The more you take, the more you leave behind. What am I?\n\n_(Footsteps!)_','🧩 What has hands but cannot clap?\n\n_(A clock!)_','🧩 What goes up but never comes down?\n\n_(Your age!)_'];
        return r[Math.floor(Math.random()*r.length)];
    }

    // Would you rather
    if (q.includes('would you rather')) {
        const w = ['🤷 Would you rather be able to *fly* or be *invisible*?','🤷 Would you rather have *unlimited money* or *unlimited time*?','🤷 Would you rather never use *social media* again or never watch *TV* again?','🤷 Would you rather live at the *beach* or in the *mountains*?'];
        return w[Math.floor(Math.random()*w.length)];
    }

    // Compliments & encouragement
    if (q.includes('compliment') || q.includes('cheer me') || q.includes('nice thing')) {
        const c = ['🌟 You\'re doing better than you think — keep going!','💖 You have a great heart, and it shows.','✨ Your effort today matters, even if no one sees it.','🔥 You\'re stronger than any challenge in front of you.','😊 The world is a little brighter with you in it.'];
        return c[Math.floor(Math.random()*c.length)];
    }
    if (q.includes('affirmation') || q.includes('encourage') || q.includes('sad') || q.includes('stressed') || q.includes('anxious') || q.includes('feeling down')) {
        const a = ['🫶 Take a deep breath. This feeling is temporary — you\'ve got this.','💪 One step at a time. You\'ve survived 100% of your hard days so far.','🌈 It\'s okay to rest. You don\'t have to have it all figured out today.','☀️ Be kind to yourself — you\'re trying, and that counts.'];
        return a[Math.floor(Math.random()*a.length)];
    }

    // Short bedtime story
    if (q.includes('story') || q.includes('bedtime')) {
        const s = ['📖 Once upon a time, a tiny star was afraid to shine. But one dark night a lost traveler looked up, saw its faint light, and found the way home. The star learned that even the smallest light can guide someone. ✨','📖 A little turtle wanted to fly. Everyone laughed — until the day a storm swept it up, and for one glorious moment, it soared. It came down smiling: "I flew, and that\'s enough." 🐢','📖 In a quiet village, a boy planted one seed every day. Years later, the whole hillside was a forest. "How?" they asked. He smiled: "One seed, every day." 🌳'];
        return s[Math.floor(Math.random()*s.length)];
    }

    // Reverse text: "reverse hello"
    if (q.startsWith('reverse ')) {
        return '🔁 *' + input.slice(input.toLowerCase().indexOf('reverse ')+8).split('').reverse().join('') + '*';
    }

    // Word/character count
    if ((q.includes('count') && (q.includes('word') || q.includes('character') || q.includes('letter')))) {
        return '🔢 Send me text like *"count words: your sentence here"* and I\'ll count it!';
    }
    if (q.startsWith('count words:') || q.startsWith('count words ')) {
        const t = input.replace(/count words:?/i,'').trim();
        return '🔢 That\'s *' + t.split(/\s+/).filter(Boolean).length + '* words and *' + t.replace(/\s/g,'').length + '* characters.';
    }

    // Song / hum
    if (q.includes('sing') || q.includes('song')) {
        const s = ['🎵 _La la la_ 🎶 I\'m no Beyoncé, but here goes: *"You are my sunshine, my only sunshine..."* ☀️','🎶 🎵 _Twinkle twinkle little star..._ okay that\'s all I\'ve got offline! 😄','🎵 Doo-doo-doo 🎶 I only know the offline remix — hum along with me!'];
        return s[Math.floor(Math.random()*s.length)];
    }

    if (q.includes('help') || q.includes('what can you do') || q.includes('features')) {
        return '🤖 I can do:\n\n🔢 *Math* — "what is 123 * 456"\n🕐 *Time & Date* — "what time is it"\n😄 *Jokes* — "tell me a joke"\n💫 *Quotes* — "give me a quote"\n🧠 *Facts* — "tell me a fact"\n💡 *Tips* — "give me a tip"\n🌍 *Translate* — "translate hello"\n🎲 *Random* — "roll a dice"\n💬 *Chat* — just talk!\n\n100% offline!';
    }

    if (q.includes('thank') || q.includes('thanks')) return ['You\'re welcome! 😊','Anytime! 👍','Happy to help! 🙌'][Math.floor(Math.random()*3)];
    if (/^(bye|goodbye|see you|later|good\s?night|gtg)/.test(q)) return ['Goodbye! 👋 Have a great day!','See you! Take care! 😊','Bye! I\'ll be here whenever you need me! 🤖'][Math.floor(Math.random()*3)];
    if (/^(ok|okay|sure|cool|nice|great|awesome|wow|lol|haha)$/.test(q)) return ['😊','👍','Awesome! Anything else?','😄'][Math.floor(Math.random()*4)];

    return ['That\'s interesting! Tell me more 😊','Hmm, I\'m in offline mode — try a joke, fact, riddle, or math!','Good question! Offline I can do math, jokes, riddles, stories, quotes & more.','I\'d love to help! Try "tell me a riddle" or "what is 50 * 30"','Want a fun fact? Or say "compliment me" 😊','I\'m your offline buddy! Try "would you rather", "roll a dice", or "flip a coin".','Try me with: a riddle, a bedtime story, a joke, or "reverse hello"! 🤖'][Math.floor(Math.random()*7)];
}

// ═══════════════════════════════════════════
// MEDIA GALLERY (shared photos in a chat)
// ═══════════════════════════════════════════

$('btn-media-gallery').addEventListener('click', () => {
    if (!activeChatWith) return;
    const chat = findChat(currentUser.username, activeChatWith);
    const grid = $('media-gallery-grid');
    const photos = chat ? chat.messages.filter(m => m.type === 'photo' && !(m.hiddenFor && m.hiddenFor.includes(currentUser.username))) : [];

    if (photos.length === 0) {
        grid.innerHTML = '<div class="gallery-empty"><p>No shared media yet</p><p class="hint">Photos you send and receive will appear here</p></div>';
    } else {
        grid.innerHTML = '';
        photos.forEach(msg => {
            const item = document.createElement('div');
            item.className = 'gallery-item';
            item.innerHTML = `<img src="${msg.photo}" alt="Shared photo">`;
            item.addEventListener('click', () => {
                $('media-gallery-modal').classList.add('hidden');
                openImageViewer(msg.photo);
            });
            grid.appendChild(item);
        });
    }
    $('media-gallery-modal').classList.remove('hidden');
});

$('btn-close-media-gallery').addEventListener('click', () => $('media-gallery-modal').classList.add('hidden'));
$('media-gallery-modal').addEventListener('click', (e) => { if (e.target === $('media-gallery-modal')) $('media-gallery-modal').classList.add('hidden'); });

// ═══════════════════════════════════════════
// DISAPPEARING MESSAGES
// ═══════════════════════════════════════════

function getDisappearSettings() { return JSON.parse(localStorage.getItem('bchat_disappear_' + currentUser.username) || '{}'); }
function saveDisappearSettings(s) { localStorage.setItem('bchat_disappear_' + currentUser.username, JSON.stringify(s)); }

$('btn-close-disappear').addEventListener('click', () => $('disappear-modal').classList.add('hidden'));
$('disappear-modal').addEventListener('click', (e) => { if (e.target === $('disappear-modal')) $('disappear-modal').classList.add('hidden'); });

document.querySelectorAll('.disappear-opt').forEach(btn => {
    btn.addEventListener('click', () => {
        const dur = parseInt(btn.dataset.dur);
        const settings = getDisappearSettings();
        settings[activeChatWith] = dur;
        saveDisappearSettings(settings);
        $('disappear-modal').classList.add('hidden');
        renderMessages();
    });
});

function cleanDisappearingMessages() {
    if (!currentUser) return;
    const settings = getDisappearSettings();
    const chats = getChats();
    let changed = false;
    const now = Date.now();

    chats.forEach(chat => {
        const other = chat.participants.find(p => p !== currentUser.username);
        const dur = settings[other];
        if (!dur || dur === 0) return;
        const before = chat.messages.length;
        chat.messages = chat.messages.filter(m => (now - new Date(m.time).getTime()) < dur);
        if (chat.messages.length !== before) changed = true;
    });

    if (changed) {
        saveChats(chats);
        if (activeChatWith) renderMessages();
        renderChatList();
    }
}

setInterval(cleanDisappearingMessages, 30000);

// ═══════════════════════════════════════════
// SETTINGS (Bio, Accent Color, Wallpaper Presets)
// ═══════════════════════════════════════════

function refreshSettingsToggles() {
    const isLight = document.body.classList.contains('light');
    $('settings-theme-label').textContent = isLight ? '☀️ Light mode' : '🌙 Dark mode';
    $('settings-sound-label').textContent = soundsMuted() ? '🔇 Sounds off' : '🔊 Sounds on';
}

$('btn-settings').addEventListener('click', () => {
    $('settings-bio').value = currentUser.bio || '';
    $('settings-code').textContent = currentUser.code || '----';
    $('settings-display').value = uName(currentUser);
    refreshSettingsToggles();
    highlightActiveColor();
    highlightActiveWallpaper();
    $('settings-modal').classList.remove('hidden');
});

$('btn-copy-code').addEventListener('click', () => {
    const code = currentUser.code || '';
    if (code && navigator.clipboard) navigator.clipboard.writeText(code).then(() => showToast('Code copied! 📋', 'success', 2000), () => {});
});

$('btn-save-display').addEventListener('click', async () => {
    const name = $('settings-display').value.trim();
    if (name.length < 2) { showToast('Name must be at least 2 characters.', 'error', 3000); return; }
    currentUser.display_name = name;
    setCurrentUser(currentUser);
    $('my-name').textContent = name;
    if (navigator.onLine) {
        try {
            await apiJson('/api/users/profile', { method: 'POST', body: JSON.stringify({ display_name: name }) });
        } catch (err) {}
    }
    renderChatList();
    showToast('Name updated ✅', 'success', 2000);
});

$('btn-settings-theme').addEventListener('click', () => { toggleTheme(); refreshSettingsToggles(); });

$('btn-settings-sound').addEventListener('click', () => {
    const muted = !soundsMuted();
    localStorage.setItem(_userKey('bchat_muted'), muted ? '1' : '0');
    refreshSettingsToggles();
    if (!muted) playNotifSound();
});

$('btn-close-settings').addEventListener('click', () => $('settings-modal').classList.add('hidden'));
$('settings-modal').addEventListener('click', (e) => { if (e.target === $('settings-modal')) $('settings-modal').classList.add('hidden'); });

$('btn-save-bio').addEventListener('click', () => {
    currentUser.bio = $('settings-bio').value.trim();
    const users = getUsers();
    const idx = users.findIndex(u => u.username === currentUser.username);
    if (idx !== -1) { users[idx].bio = currentUser.bio; saveUsers(users); }
    setCurrentUser(currentUser);
    $('settings-modal').classList.add('hidden');
});

// Accent color
function getAccentColor() { return localStorage.getItem('bchat_accent') || '#6C63FF'; }

function applyAccentColor(color) {
    document.documentElement.style.setProperty('--primary', color);
    const hsl = hexToHSL(color);
    document.documentElement.style.setProperty('--primary-dark', `hsl(${hsl.h}, ${hsl.s}%, ${Math.max(hsl.l - 12, 5)}%)`);
    document.documentElement.style.setProperty('--primary-light', `hsl(${hsl.h}, ${hsl.s}%, ${Math.min(hsl.l + 15, 90)}%)`);
    document.documentElement.style.setProperty('--sent', color);
    localStorage.setItem('bchat_accent', color);   // shared/global — color can be shared
    highlightActiveColor();
}

function hexToHSL(hex) {
    let r = parseInt(hex.slice(1,3),16)/255, g = parseInt(hex.slice(3,5),16)/255, b = parseInt(hex.slice(5,7),16)/255;
    const max = Math.max(r,g,b), min = Math.min(r,g,b), l = (max+min)/2;
    let h = 0, s = 0;
    if (max !== min) {
        const d = max - min;
        s = l > 0.5 ? d/(2-max-min) : d/(max+min);
        if (max === r) h = ((g-b)/d + (g<b?6:0))/6;
        else if (max === g) h = ((b-r)/d+2)/6;
        else h = ((r-g)/d+4)/6;
    }
    return { h: Math.round(h*360), s: Math.round(s*100), l: Math.round(l*100) };
}

function highlightActiveColor() {
    const current = getAccentColor();
    document.querySelectorAll('.color-dot').forEach(d => d.classList.toggle('active', d.dataset.color === current));
}

document.querySelectorAll('.color-dot').forEach(dot => {
    dot.addEventListener('click', () => applyAccentColor(dot.dataset.color));
});

// The login/signup screens must ALWAYS use the default brand look, never a
// logged-in user's personal color or theme.
const DEFAULT_ACCENT = '#6C63FF';
function applyAuthDefaults() {
    // Only the personal ACCENT COLOR is reset to brand default on auth screens.
    // Dark/light is a device-wide preference with its own toggle on the login form.
    document.documentElement.style.setProperty('--primary', DEFAULT_ACCENT);
    document.documentElement.style.setProperty('--primary-dark', '#4834DF');
    document.documentElement.style.setProperty('--primary-light', '#8B83FF');
    document.documentElement.style.setProperty('--sent', DEFAULT_ACCENT);
    loadTheme();
}
// Apply the user's saved personalization — only used once inside the app.
function applyUserSettings() {
    applyAccentColor(getAccentColor());
    loadTheme();
}

applyAuthDefaults();

// Wallpaper presets
const WP_GRADIENTS = {
    none: '',
    gradient1: 'linear-gradient(135deg,#1a1a2e,#16213e,#0f3460)',
    gradient2: 'linear-gradient(135deg,#0f0c29,#302b63,#24243e)',
    gradient3: 'linear-gradient(135deg,#1d1d3b,#2b1055,#4a0e4e)',
    gradient4: 'linear-gradient(135deg,#0a1628,#1a3a4a,#0d4a3a)',
    gradient5: 'linear-gradient(135deg,#2d1b00,#4a2600,#1a0a00)',
    gradient6: 'linear-gradient(135deg,#1a1a1a,#2d2d2d,#1a1a1a)',
    pattern1: 'repeating-linear-gradient(45deg,#16161d,#16161d 10px,#1a1a24 10px,#1a1a24 20px)'
};

function getWallpaperPreset() { return localStorage.getItem(_userKey('bchat_wp_preset')) || 'none'; }

function applyWallpaperPreset(key) {
    if (currentUser) localStorage.setItem(_userKey('bchat_wp_preset'), key);
    highlightActiveWallpaper();
}

function highlightActiveWallpaper() {
    const current = getWallpaperPreset();
    document.querySelectorAll('.wp-preset').forEach(p => p.classList.toggle('active', p.dataset.wp === current));
}

document.querySelectorAll('.wp-preset').forEach(p => {
    p.addEventListener('click', () => {
        applyWallpaperPreset(p.dataset.wp);
        if (activeChatWith) applyChatBackground();
    });
});

// Update profile card to show bio
const origOpenProfile = $('chat-header-info').onclick;

// Browser tab unread count
function updatePageTitle(count) {
    document.title = count > 0 ? '(' + count + ') B CHAT' : 'B CHAT';
}

// ═══════════════════════════════════════════
// TUTORIAL / VOICE GUIDE
// ═══════════════════════════════════════════

let tutorialSpeaking = false;
let tutorialUtterance = null;

const tutorialTexts = [
    "Welcome to B CHAT! B CHAT is a messaging app built by Billy Hawkins. It lets you chat with family and friends, share photos, send voice notes, make calls, and much more. Let me walk you through everything.",
    "Sign Up and Log In. To get started, enter your real email and password, then create your display name, username, and optional profile photo. Next time you open the app, just log in with your username and password.",
    "Starting a Chat. Tap the plus button at the top of the sidebar to see all registered users. Tap on someone's name to start a conversation. You can also search your existing chats using the search bar.",
    "Sending Messages. Type your message in the text box and tap send. You can format text: wrap words in asterisks for bold, underscores for italic, and tildes for strikethrough. Any links you type become clickable automatically.",
    "Photos, Emojis, and Voice Notes. Tap the camera icon to send a photo from your device. Tap the smiley face to open the emoji picker with 7 categories. To send a voice note, hold the microphone button, speak, then release to send. Tap the X to cancel.",
    "Message Actions. Long-press any message to see options: reply, forward to another chat, star it, react with an emoji, pin the conversation, or delete it. You can delete for yourself only, or delete for everyone. Double-tap a message to quickly add an emoji reaction.",
    "Voice and Video Calls. Inside a chat, tap the phone icon for a voice call, or the video camera icon for a video call. Your real microphone and camera are used. You can mute yourself, toggle speaker, flip your camera, and end the call. The call duration is automatically logged in the chat.",
    "Profile and Gallery. Tap your profile picture in the sidebar to open your photo gallery. Here you can upload photos from your device, set any photo as your profile picture, or delete photos. Tap another user's avatar in a chat header to see their profile card with their info.",
    "Status Updates. Switch to the Status tab to post a text or photo update. Your status is visible to all users and disappears automatically after 24 hours, just like stories. Tap on someone else's status to view it full-screen with a progress timer.",
    "Ads and Announcements. The Ads tab is a bulletin board for everyone. Post announcements with a title, description, and optional photo. Great for family news, selling items, or sharing events. You can delete your own ads anytime.",
    "AI Assistant. The AI tab gives you a built-in smart assistant. When you are online, it now gives real, conversational artificial intelligence answers to anything you ask, with no setup or key needed. When you are offline, it still helps with math, jokes, interesting facts, riddles, inspirational quotes, useful tips, and translations. You can even ask it to generate images! Just say 'create an image of' followed by what you want.",
    "Settings and Personalization. Tap the gear icon next to your name to open Settings. Here you can add a bio or about section for your profile. Pick a custom accent color to change the look of the entire app. You can also choose from built-in wallpaper presets for your chat backgrounds — beautiful gradients and patterns with no upload needed.",
    "Shared Media and Disappearing Messages. Tap the media icon in a chat header to view all the photos shared in that conversation in a grid. To enable disappearing messages, long-press any message and tap Disappearing Messages. You can set messages to auto-delete after 5 minutes, 1 hour, 24 hours, or 7 days.",
    "Extra Features. Use the sun icon to switch between dark and light mode. Tap the star icon to view all your bookmarked messages. Use the search magnifying glass inside a chat to find specific messages. The browser tab title shows your unread message count. You can change each chat's background using the palette icon.",
    "Password Security and Privacy. Your account is protected. On the sign up and log in screens, tap the eye icon to show or hide your password, and watch the strength meter as you type to create a strong one. Your password is encrypted before it is saved, so no one, not even the app owner, can read it.",
    "Online Status and Last Seen. See who is around. A green dot appears on the avatar of anyone currently online, in your chat list and when you start a new chat. Inside a chat, the header shows whether the person is online, or when they were last seen.",
    "Offline Mode and Alerts. B CHAT always tells you when you are offline. A red banner appears at the top, and you get a pop up if you try to send a message without internet. The AI assistant keeps working offline with jokes, facts, riddles, and more. It just lets you know it is in offline mode.",
    "Choose Your Guide Voice. Prefer a different narrator? Use the microphone voice selector at the top of this guide to switch between two different voices for the spoken tour. Your choice is remembered next time.",
    "Chat Like a Pro. Your sent messages show ticks: grey double ticks mean delivered, and blue double ticks mean the other person has read your message. Swipe any message to the right to reply to it instantly. When you scroll up in a long chat, tap the down arrow button to jump back to the latest message. Messages are grouped by day, with Today and Yesterday labels.",
    "Your 4-Digit Code and Multiple Devices. Each account gets a unique four digit code, shown next to your name. Share it so your family can add you. To start a new chat, tap the plus button and enter their code. You can also use B CHAT on any phone or computer at the same time. Just log in with the same username and password, and all your chats will appear. And that covers everything. Enjoy using B CHAT!"
];

const guideStepData = [];
let guideStepIndex = 0;
let guideAutoTimer = null;
let guideCountdown = 0;
let guideCountdownInterval = null;
const GUIDE_AUTO_SECONDS = 8;

function buildGuideSteps() {
    document.querySelectorAll('.tutorial-card').forEach(card => {
        const idx = parseInt(card.dataset.step, 10);
        const title = card.querySelector('h4')?.textContent || `Step ${idx + 1}`;
        const text = card.querySelector('p')?.textContent || tutorialTexts[idx] || '';
        guideStepData[idx] = { idx, title, text };
    });
}

function updateGuideCountdownLabel() {
    const label = document.getElementById('guide-time-desc');
    if (!label) return;
    if (guideStepIndex >= guideStepData.length - 1) {
        label.textContent = 'End of guide';
    } else if (guideCountdown > 0) {
        label.textContent = `Auto next in ${guideCountdown}s`;
    } else {
        label.textContent = `Read for ${GUIDE_AUTO_SECONDS} seconds`;
    }
}

function clearGuideTimer() {
    if (guideAutoTimer) {
        clearTimeout(guideAutoTimer);
        guideAutoTimer = null;
    }
    if (guideCountdownInterval) {
        clearInterval(guideCountdownInterval);
        guideCountdownInterval = null;
    }
    guideCountdown = 0;
}

function startGuideTimer() {
    clearGuideTimer();
    if (guideStepIndex >= guideStepData.length - 1) return;
    guideCountdown = GUIDE_AUTO_SECONDS;
    updateGuideCountdownLabel();
    guideCountdownInterval = setInterval(() => {
        guideCountdown -= 1;
        if (guideCountdown <= 0) {
            clearGuideTimer();
            if (guideStepIndex < guideStepData.length - 1) {
                showGuideStep(guideStepIndex + 1);
            }
        } else {
            updateGuideCountdownLabel();
        }
    }, 1000);
}

function highlightGuideCard(idx) {
    document.querySelectorAll('.tutorial-card').forEach(card => card.classList.toggle('active-lesson', parseInt(card.dataset.step, 10) === idx));
}

function showGuideStep(index, options = { auto: true }) {
    const total = guideStepData.length;
    const nextIndex = Math.max(0, Math.min(index, total - 1));

    if (tutorialSpeaking) stopSpeaking();
    guideStepIndex = nextIndex;
    const step = guideStepData[guideStepIndex];
    if (!step) return;

    document.getElementById('guide-step-label').textContent = `Step ${guideStepIndex + 1} of ${total}`;
    document.getElementById('guide-step-title').textContent = step.title;
    document.getElementById('guide-step-copy').textContent = step.text;
    document.getElementById('guide-prev').disabled = guideStepIndex === 0;
    document.getElementById('guide-next').textContent = guideStepIndex === total - 1 ? 'Finish' : 'Next ▶';

    highlightGuideCard(guideStepIndex);
    const card = document.querySelector(`.tutorial-card[data-step="${guideStepIndex}"]`);
    if (card) card.scrollIntoView({ behavior: 'smooth', block: 'center' });

    if (options.auto) startGuideTimer();
    else updateGuideCountdownLabel();
}

function nextGuideStep() {
    if (guideStepIndex < guideStepData.length - 1) {
        showGuideStep(guideStepIndex + 1);
    }
}

function prevGuideStep() {
    if (guideStepIndex > 0) {
        showGuideStep(guideStepIndex - 1);
    }
}

function restartGuide() {
    showGuideStep(0);
}

function initializeGuideNavigation() {
    buildGuideSteps();
    showGuideStep(0, { auto: false });
    document.getElementById('guide-next')?.addEventListener('click', () => {
        nextGuideStep();
    });
    document.getElementById('guide-prev')?.addEventListener('click', () => {
        prevGuideStep();
    });
    document.getElementById('guide-restart')?.addEventListener('click', () => {
        restartGuide();
    });
}

initializeGuideNavigation();

// ── Two narrator voices ──
function pickVoices() {
    const voices = ('speechSynthesis' in window) ? window.speechSynthesis.getVoices() : [];
    const en = voices.filter(v => v.lang && v.lang.toLowerCase().startsWith('en'));
    const female = en.find(v => /(female|zira|samantha|susan|karen|moira|tessa|fiona|serena|amelie|google uk english female)/i.test(v.name));
    const male = en.find(v => /(male|david|mark|daniel|alex|fred|rishi|george|google uk english male)/i.test(v.name));
    const a = female || en[0] || voices[0] || null;
    const b = male || en.find(v => v !== a) || en[1] || voices.find(v => v !== a) || a;
    return { a, b };
}
function getSelectedVoice() {
    const pref = localStorage.getItem('bchat_tts_voice') || 'a';
    const v = pickVoices();
    return pref === 'b' ? v.b : v.a;
}
const _voiceSelect = document.getElementById('voice-select');
if (_voiceSelect) {
    _voiceSelect.value = localStorage.getItem('bchat_tts_voice') || 'a';
    _voiceSelect.addEventListener('change', () => {
        localStorage.setItem('bchat_tts_voice', _voiceSelect.value);
        showToast('🎙 Narration voice changed', 'info', 1800);
    });
}

// ── Cartoon explainer narration ──
const explainerLines = [
    { t: "Hi! Welcome to B CHAT — I'm your guide! 👋", who: 'a' },
    { t: "It's a free app to chat with your family and friends. 💬", who: 'b' },
    { t: "Send messages, photos, voice notes, and make calls! 📞", who: 'a' },
    { t: "See who's online and post 24-hour status updates. 🌟", who: 'b' },
    { t: "There's a smart AI assistant, and cloud-saved chats. ☁️", who: 'a' },
    { t: "And look — here's B CHAT right here on my phone! 📱", who: 'a', zoom: true },
    { t: "Chat, status, calls and AI, all in one. Enjoy B CHAT! 🎉", who: 'a', zoom: true }
];
let explainerPlaying = false;
let explainerTimer = null;

function stopExplainer() {
    explainerPlaying = false;
    if (explainerTimer) { clearTimeout(explainerTimer); explainerTimer = null; }
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
    document.getElementById('explainer-stage')?.classList.remove('playing');
    document.getElementById('explainer-stage')?.classList.remove('zoomed');
    const btn = document.getElementById('explainer-play');
    if (btn) btn.textContent = '▶';
    document.getElementById('toon-a')?.classList.remove('speaking');
    document.getElementById('toon-b')?.classList.remove('speaking');
    const bubble = document.getElementById('explainer-bubble');
    if (bubble) bubble.textContent = 'Meet B CHAT! 👋';
}

function playExplainer() {
    if (explainerPlaying) { stopExplainer(); return; }
    if (typeof stopSpeaking === 'function') stopSpeaking();
    explainerPlaying = true;
    const bubble = document.getElementById('explainer-bubble');
    const btn = document.getElementById('explainer-play');
    document.getElementById('explainer-stage')?.classList.add('playing');
    if (btn) btn.textContent = '⏹';
    const voices = pickVoices();
    const supportsTTS = 'speechSynthesis' in window;
    let i = 0;
    function showLine() {
        if (!explainerPlaying) return;
        if (i >= explainerLines.length) { stopExplainer(); return; }
        const line = explainerLines[i];
        bubble.textContent = line.t;
        document.getElementById('toon-a').classList.toggle('speaking', line.who === 'a');
        document.getElementById('toon-b').classList.toggle('speaking', line.who === 'b');
        document.getElementById('explainer-stage')?.classList.toggle('zoomed', !!line.zoom);
        if (supportsTTS) {
            window.speechSynthesis.cancel();
            const u = new SpeechSynthesisUtterance(line.t.replace(/[^\x00-\x7F]/g, '').trim() || line.t);
            const chosen = line.who === 'b' ? voices.b : voices.a;
            if (chosen) u.voice = chosen;
            u.rate = 0.8;
            u.pitch = line.who === 'b' ? 0.85 : 1.15;
            u.onend = () => { i++; if (explainerPlaying) explainerTimer = setTimeout(showLine, 220); };
            u.onerror = () => { i++; if (explainerPlaying) explainerTimer = setTimeout(showLine, 2200); };
            window.speechSynthesis.speak(u);
        } else {
            i++;
            explainerTimer = setTimeout(showLine, 3200);
        }
    }
    showLine();
}
document.getElementById('explainer-play')?.addEventListener('click', playExplainer);

// Tap the phone to zoom into B CHAT (manual, when not narrating)
document.getElementById('explainer-phone')?.addEventListener('click', () => {
    if (explainerPlaying) return;
    document.getElementById('explainer-stage')?.classList.toggle('zoomed');
});

function speakText(text, idx, onEnd) {
    if (explainerPlaying) stopExplainer();
    if (!('speechSynthesis' in window)) {
        alert('Voice is not supported in this browser.');
        return;
    }
    window.speechSynthesis.cancel();
    tutorialUtterance = new SpeechSynthesisUtterance(text);
    tutorialUtterance.rate = 0.8;
    tutorialUtterance.pitch = (localStorage.getItem('bchat_tts_voice') === 'b') ? 0.85 : 1.05;

    const chosen = getSelectedVoice();
    if (chosen) tutorialUtterance.voice = chosen;

    document.querySelectorAll('.tutorial-card').forEach(c => c.classList.remove('active-lesson'));
    document.querySelectorAll('.tutorial-play-btn').forEach(b => b.classList.remove('playing'));

    if (idx !== undefined) {
        const card = document.querySelector(`.tutorial-card[data-step="${idx}"]`);
        if (card) {
            card.classList.add('active-lesson');
            card.querySelector('.tutorial-play-btn').classList.add('playing');
            card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    tutorialSpeaking = true;
    $('btn-stop-voice').classList.remove('hidden');

    tutorialUtterance.onend = () => {
        tutorialSpeaking = false;
        document.querySelectorAll('.tutorial-card').forEach(c => c.classList.remove('active-lesson'));
        document.querySelectorAll('.tutorial-play-btn').forEach(b => b.classList.remove('playing'));
        if (onEnd) onEnd();
        else $('btn-stop-voice').classList.add('hidden');
    };

    window.speechSynthesis.speak(tutorialUtterance);
}

function stopSpeaking() {
    window.speechSynthesis.cancel();
    tutorialSpeaking = false;
    $('btn-stop-voice').classList.add('hidden');
    document.querySelectorAll('.tutorial-card').forEach(c => c.classList.remove('active-lesson'));
    document.querySelectorAll('.tutorial-play-btn').forEach(b => b.classList.remove('playing'));
}

// Individual lesson play buttons
document.querySelectorAll('.tutorial-play-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const card = btn.closest('.tutorial-card');
        const step = parseInt(card.dataset.step);
        if (tutorialSpeaking) {
            stopSpeaking();
            return;
        }
        speakText(tutorialTexts[step], step);
    });
});

// Play full tour
$('btn-play-all').addEventListener('click', () => {
    if (tutorialSpeaking) { stopSpeaking(); return; }
    let current = 0;
    function playNext() {
        if (current >= tutorialTexts.length) {
            $('btn-stop-voice').classList.add('hidden');
            $('btn-play-all').textContent = '▶ Play Full Tour (Voice)';
            return;
        }
        speakText(tutorialTexts[current], current, () => {
            current++;
            playNext();
        });
    }
    $('btn-play-all').textContent = '⏹ Stop Tour';
    playNext();
});

$('btn-stop-voice').addEventListener('click', () => {
    stopSpeaking();
    $('btn-play-all').textContent = '▶ Play Full Tour (Voice)';
});

// Preload voices
if ('speechSynthesis' in window) {
    window.speechSynthesis.getVoices();
    window.speechSynthesis.onvoiceschanged = () => window.speechSynthesis.getVoices();
}

// ═══════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════

// ═══════════════════════════════════════════
// PWA & OFFLINE
// ═══════════════════════════════════════════

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
}

(async function init() {
    const saved = getCurrentUser();
    if (saved && saved.username) {
        currentUser = saved;
        enterApp();

        const token = getStoredToken();
        if (navigator.onLine && token) {
            const refreshed = await restoreBackendSession();
            if (!refreshed) {
                currentUser = null;
                showScreen(loginScreen);
                return;
            }
            $('my-name').textContent = uName(currentUser);
            const codeEl = $('my-code');
            if (codeEl) codeEl.textContent = currentUser.code ? 'Code: ' + currentUser.code : '';
        }
        return;
    }
    showScreen(loginScreen);
})();
