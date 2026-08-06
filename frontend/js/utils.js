export const $ = (id) => document.getElementById(id);

export function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

export function formatTime(date) {
  const now = new Date();
  const diff = now - date;
  if (diff < 86400000 && now.getDate() === date.getDate()) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (diff < 172800000) return 'Yesterday';
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function formatDate(date) {
  const now = new Date();
  const diff = now - date;
  if (diff < 86400000 && now.getDate() === date.getDate()) return 'Today';
  if (diff < 172800000) return 'Yesterday';
  return date.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
}

export function formatLastSeen(date) {
  const now = new Date();
  const diffMs = now - date;
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return diffMin + ' min ago';
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24 && now.getDate() === date.getDate()) {
    return 'today at ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (diffHrs < 48) return 'yesterday at ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' at ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function formatMessageTime(date) {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function formatMsgText(text) {
  if (!text) return '';
  let s = escapeHtml(text);
  s = s.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline;">$1</a>');
  s = s.replace(/\*([^*]+)\*/g, '<strong>$1</strong>');
  s = s.replace(/\_([^_]+)\_/g, '<em>$1</em>');
  s = s.replace(/\~([^~]+)\~/g, '<del>$1</del>');
  return s;
}

export function makeSessionId() {
  return (crypto.randomUUID?.() || ('sess_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2)));
}

export function isStandalone() {
  return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}

export function showToast(message, type = 'info', duration = 3000) {
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

export function updateOfflineBanner() {
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

export function requireOnline(action = 'do this') {
  if (navigator.onLine) return true;
  showToast("📴 You're offline — connect to the internet to " + action + '.', 'error');
  return false;
}
