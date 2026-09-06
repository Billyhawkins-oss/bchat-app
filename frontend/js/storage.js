let cachedUser = null;

function currentUsername() {
  const user = getCurrentUser();
  return user?.username || 'guest';
}

export function getStoredToken() { return localStorage.getItem('bchat_backend_token') || ''; }
export function setStoredToken(token) {
  if (token) localStorage.setItem('bchat_backend_token', token);
  else localStorage.removeItem('bchat_backend_token');
}
export function clearStoredToken() { localStorage.removeItem('bchat_backend_token'); }

export function getCurrentUser() {
  if (cachedUser === null) {
    cachedUser = JSON.parse(localStorage.getItem('bchat_current') || 'null');
  }
  return cachedUser;
}

export function setCurrentUser(user) {
  cachedUser = user;
  if (user) localStorage.setItem('bchat_current', JSON.stringify(user));
  else localStorage.removeItem('bchat_current');
}

export function getGallery(username) { return JSON.parse(localStorage.getItem('bchat_gallery_' + username) || '[]'); }
export function saveGallery(username, photos) { localStorage.setItem('bchat_gallery_' + username, JSON.stringify(photos)); }

export function getStarred() { return JSON.parse(localStorage.getItem('bchat_starred_' + currentUsername()) || '[]'); }
export function saveStarred(s) { localStorage.setItem('bchat_starred_' + currentUsername(), JSON.stringify(s)); }
export function saveUsers(users) { localStorage.setItem('bchat_users_cache', JSON.stringify(users)); }

export function getPendingMessages() {
  const key = 'bchat_pending_messages_' + currentUsername();
  return JSON.parse(localStorage.getItem(key) || '[]');
}
export function savePendingMessages(messages) {
  const key = 'bchat_pending_messages_' + currentUsername();
  localStorage.setItem(key, JSON.stringify(messages));
}

export function getConversationKey(user1, user2) {
  return 'bchat_msgs_cache_' + [user1, user2].sort().join('_');
}

export function mergeConversationMessages(baseMessages, extraMessages) {
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

export function persistMessageToLocalCaches(message) {
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

export function addPendingMessage(message) {
  const key = 'bchat_pending_messages_' + (message.sender || currentUsername());
  const pending = JSON.parse(localStorage.getItem(key) || '[]');
  if (!pending.some((entry) => entry.id === message.id)) {
    pending.push(message);
    localStorage.setItem(key, JSON.stringify(pending));
  }
}

export function removePendingMessage(messageId) {
  const key = 'bchat_pending_messages_' + currentUsername();
  const pending = JSON.parse(localStorage.getItem(key) || '[]').filter((entry) => entry.id !== messageId);
  localStorage.setItem(key, JSON.stringify(pending));
}

export function getPinnedChats() { return JSON.parse(localStorage.getItem('bchat_pinned_' + currentUsername()) || '[]'); }
export function savePinnedChats(pins) { localStorage.setItem('bchat_pinned_' + currentUsername(), JSON.stringify(pins)); }

export function getReadCounts() { return JSON.parse(localStorage.getItem('bchat_read_' + currentUsername()) || '{}'); }
export function saveReadCounts(rc) { localStorage.setItem('bchat_read_' + currentUsername(), JSON.stringify(rc)); }

export function getArchivedChats() { return JSON.parse(localStorage.getItem('bchat_archived_' + currentUsername()) || '[]'); }
export function saveArchivedChats(list) { localStorage.setItem('bchat_archived_' + currentUsername(), JSON.stringify(list)); }

export function getLockedChats() { return JSON.parse(localStorage.getItem('bchat_locked_' + currentUsername()) || '[]'); }
export function saveLockedChats(list) { localStorage.setItem('bchat_locked_' + currentUsername(), JSON.stringify(list)); }

export function getLockPassword() { return localStorage.getItem('bchat_lock_password') || ''; }
export function setLockPassword(password) { if (password) localStorage.setItem('bchat_lock_password', password); else localStorage.removeItem('bchat_lock_password'); }

export function isChatArchived(username) { return getArchivedChats().includes(username); }
export function isChatLocked(username) { return getLockedChats().includes(username); }

export function getChatBgs() { return JSON.parse(localStorage.getItem('bchat_chatbgs_' + currentUsername()) || '{}'); }
export function saveChatBgs(bgs) { localStorage.setItem('bchat_chatbgs_' + currentUsername(), JSON.stringify(bgs)); }

export function getNicknames() { return JSON.parse(localStorage.getItem('bchat_nicknames_' + currentUsername()) || '{}'); }
export function saveNicknames(n) { localStorage.setItem('bchat_nicknames_' + currentUsername(), JSON.stringify(n)); }
export function setNickname(username, name) {
  const n = getNicknames();
  if (name && name.trim()) n[username] = name.trim(); else delete n[username];
  saveNicknames(n);
}
export function getContactName(username, userObj) {
  const nn = getNicknames()[username];
  if (nn) return nn;
  if (userObj) return userObj.display_name || userObj.displayName || userObj.username;
  return username;
}

export function getAiHistory() { return JSON.parse(localStorage.getItem('bchat_ai_history_' + currentUsername()) || '[]'); }
export function saveAiHistory(h) { localStorage.setItem('bchat_ai_history_' + currentUsername(), JSON.stringify(h)); }

export function getDisappearSettings() { return JSON.parse(localStorage.getItem('bchat_disappear_' + currentUsername()) || '{}'); }
export function saveDisappearSettings(s) { localStorage.setItem('bchat_disappear_' + currentUsername(), JSON.stringify(s)); }

export function saveStatuses(statuses) { localStorage.setItem('bchat_statuses_cache', JSON.stringify(statuses)); }
export function saveAds(ads) { localStorage.setItem('bchat_ads_cache', JSON.stringify(ads)); }

export function getChats() {
  const username = currentUsername();
  const messages = JSON.parse(localStorage.getItem('bchat_all_msgs_cache') || '[]');
  const chats = {};
  messages.forEach(msg => {
    const other = msg.sender === username ? msg.receiver : msg.receiver === username ? msg.sender : null;
    if (!other) return;
    if (!chats[other]) {
      chats[other] = { participants: [username, other], messages: [] };
    }
    chats[other].messages.push(msg);
  });
  return Object.values(chats);
}

export function saveChats(chats) {
  const serialized = [];
  chats.forEach(chat => {
    if (Array.isArray(chat.messages)) {
      serialized.push(...chat.messages);
    }
  });
  localStorage.setItem('bchat_all_msgs_cache', JSON.stringify(serialized));
}

export function findChat(username, otherUsername) {
  const chats = getChats();
  return chats.find(c => c.participants.includes(username) && c.participants.includes(otherUsername));
}

