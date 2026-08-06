import { getStoredToken } from './storage.js';
import { getConversationKey, mergeConversationMessages } from './storage.js';

export const SUPABASE_URL = window.__BCHAT_CONFIG__?.SUPABASE_URL || '';
export const SUPABASE_ANON_KEY = window.__BCHAT_CONFIG__?.SUPABASE_ANON_KEY || '';
export let sb = null;

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

const API_BASE_URL = window.__BCHAT_CONFIG__?.API_BASE_URL || '';

export async function apiJson(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  let token = getStoredToken();
  if (sb) {
    try {
      const result = await sb.auth.getSession();
      if (result?.data?.session?.access_token) token = result.data.session.access_token;
    } catch (e) {
      // ignore
    }
  }
  if (token) headers.Authorization = `Bearer ${token}`;
  const url = `${API_BASE_URL}${path}`;
  try {
    const res = await fetch(url, { ...options, headers });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error(data?.error || 'Request failed');
    return data;
  } catch (err) {
    throw err;
  }
}

export async function getUsers() {
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

export async function getMessages(user1, user2) {
  const cacheKey = getConversationKey(user1, user2);
  const cached = JSON.parse(localStorage.getItem(cacheKey) || '[]');
  const pending = JSON.parse(localStorage.getItem('bchat_pending_messages_' + user1) || '[]').filter((msg) => (msg.sender === user1 && msg.receiver === user2) || (msg.sender === user2 && msg.receiver === user1));
  const mergedCached = mergeConversationMessages(cached, pending);

  if (!navigator.onLine) {
    localStorage.setItem(cacheKey, JSON.stringify(mergedCached));
    return mergedCached;
  }

  try {
    const data = await apiJson(`/api/messages?user1=${encodeURIComponent(user1)}&user2=${encodeURIComponent(user2)}`);
    const msgs = mergeConversationMessages(data?.messages || [], pending);
    localStorage.setItem(cacheKey, JSON.stringify(msgs));
    return msgs;
  } catch (err) {
    localStorage.setItem(cacheKey, JSON.stringify(mergedCached));
    return mergedCached;
  }
}

export async function getConversationMessages(username) {
  const cached = JSON.parse(localStorage.getItem('bchat_all_msgs_cache') || '[]');
  const pending = JSON.parse(localStorage.getItem('bchat_pending_messages_' + username) || '[]').filter((msg) => msg.sender === username || msg.receiver === username);
  const mergedCached = mergeConversationMessages(cached, pending);

  if (!navigator.onLine) {
    localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(mergedCached));
    return mergedCached;
  }

  try {
    const data = await apiJson(`/api/conversations?username=${encodeURIComponent(username)}`);
    const msgs = mergeConversationMessages(data?.messages || [], pending);
    localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(msgs));
    return msgs;
  } catch (err) {
    localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(mergedCached));
    return mergedCached;
  }
}

export async function getStatuses() {
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

export async function getAds() {
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
