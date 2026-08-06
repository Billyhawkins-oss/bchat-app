import { getE2EEKey, saveE2EEKey } from './storage.js';
import { apiJson } from './api.js';

export let _e2eePrivateKey = null;

export async function generateE2EEKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey('spki', publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

export async function exportEncryptedPrivateKey(privateKey, password) {
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

  const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, privateKeyRaw);

  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);
  return btoa(String.fromCharCode(...combined));
}

export async function importEncryptedPrivateKey(encryptedB64, password) {
  try {
    const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const encryptedData = combined.slice(28);

    const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encryptedData);
    return await crypto.subtle.importKey('pkcs8', decrypted, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
  } catch (e) {
    console.error('Failed to decrypt private key:', e);
    return null;
  }
}

export async function importPublicKey(publicKeyB64) {
  try {
    const raw = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey('spki', raw, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  } catch (e) {
    console.error('Failed to import public key:', e);
    return null;
  }
}

export async function e2eeEncrypt(plaintext, receiverPublicKeyB64) {
  if (!receiverPublicKeyB64) return null;
  const symKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, symKey, encoded);

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

export async function e2eeDecrypt(packet, privateKey) {
  if (!packet || !packet.ct || !packet.iv || !packet.ek) return null;
  try {
    const ciphertext = Uint8Array.from(atob(packet.ct), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(packet.iv), c => c.charCodeAt(0));
    const encryptedSymKey = Uint8Array.from(atob(packet.ek), c => c.charCodeAt(0));

    const symKeyRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedSymKey);
    const symKey = await crypto.subtle.importKey('raw', symKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, symKey, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error('E2EE decrypt failed:', e);
    return null;
  }
}

export async function e2eeEncryptBinary(dataB64, receiverPublicKeyB64) {
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

export async function e2eeDecryptBinary(packet, privateKey) {
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

export async function ensureE2EEKeys(username, password) {
  const stored = getE2EEKey(username);
  if (stored && stored.encryptedPrivateKey && stored.publicKey) {
    _e2eePrivateKey = await importEncryptedPrivateKey(stored.encryptedPrivateKey, password);
    if (_e2eePrivateKey) {
      return { publicKey: stored.publicKey, privateKey: _e2eePrivateKey };
    }
    console.warn('E2EE: Failed to decrypt private key, generating new pair');
  }

  const keyPair = await generateE2EEKeyPair();
  const publicKeyB64 = await exportPublicKey(keyPair.publicKey);
  const encryptedPrivateKey = await exportEncryptedPrivateKey(keyPair.privateKey, password);

  saveE2EEKey(username, {
    publicKey: publicKeyB64,
    encryptedPrivateKey
  });

  _e2eePrivateKey = keyPair.privateKey;
  try {
    await apiJson('/api/users/e2ee-key', { method: 'POST', body: JSON.stringify({ public_key: publicKeyB64 }) });
  } catch (e) {
    console.warn('Failed to upload E2EE public key:', e);
  }
  return { publicKey: publicKeyB64, privateKey: keyPair.privateKey };
}

export async function fetchUserPublicKey(username) {
  try {
    const data = await apiJson(`/api/users?username=${encodeURIComponent(username)}`);
    if (data?.user?.e2ee_public_key) return data.user.e2ee_public_key;
    const allData = await apiJson('/api/users');
    const user = (allData?.users || []).find(u => u.username === username);
    return user?.e2ee_public_key || null;
  } catch {
    return null;
  }
}
