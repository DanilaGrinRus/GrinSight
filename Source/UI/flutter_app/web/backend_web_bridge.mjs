// Browser-only wallet bridge: keys stay in IndexedDB and in this Wasm module.
// The gateway/service never receives a phrase or password.
import {
  newWalletPhrase, setWalletPhrase, walletAddress, clearWallet, setNetwork, walletScanBundle,
} from './core/grinsight_api.mjs';
import { fetchGatewayBundle } from './gateway_bundle_sync.mjs';

const DB_NAME = 'grinsight-web';
const DB_VERSION = 1;
const STORE = 'profiles';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) {
        req.result.createObjectStore(STORE, { keyPath: 'login' });
      }
    };
    req.onerror = () => reject(req.error || new Error('indexedDB open failed'));
    req.onsuccess = () => resolve(req.result);
  });
}

async function idb(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const store = tx.objectStore(STORE);
      let out;
      try { out = fn(store); } catch (e) { reject(e); return; }
      tx.oncomplete = () => resolve(out && out.__result !== undefined ? out.__result : out);
      tx.onerror = () => reject(tx.error || new Error('indexedDB transaction failed'));
      tx.onabort = () => reject(tx.error || new Error('indexedDB transaction aborted'));
    });
  } finally {
    db.close();
  }
}

function getOne(login) {
  return new Promise(async (resolve, reject) => {
    const db = await openDb();
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(login);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

function putOne(record) {
  return new Promise(async (resolve, reject) => {
    const db = await openDb();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(record);
    tx.oncomplete = () => { db.close(); resolve(record); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

function listAll() {
  return new Promise(async (resolve, reject) => {
    const db = await openDb();
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(bytes) {
  let s = '';
  const a = new Uint8Array(bytes);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s);
}
function unb64(s) {
  const raw = atob(s);
  const a = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) a[i] = raw.charCodeAt(i);
  return a;
}

async function derive(password, salt) {
  if (!globalThis.crypto || !crypto.subtle) {
    throw new Error('WebCrypto недоступен: нужен HTTPS (или localhost)');
  }
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function seal(phrase, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derive(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(phrase));
  return { salt: b64(salt), iv: b64(iv), data: b64(ct) };
}

async function openSealed(rec, password) {
  const key = await derive(password, unb64(rec.salt));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.iv) }, key, unb64(rec.data));
  return dec.decode(pt);
}

function net(mainnet) {
  return setNetwork(mainnet ? 1 : 0);
}

function clean(rec) {
  const out = {
    login: rec.login,
    name: rec.name,
    network: rec.network,
    address: rec.address,
    createdAt: rec.createdAt,
    lastUsed: rec.lastUsed || 0,
  };
  return out;
}

async function validatePhrase(phrase) {
  const r = await setWalletPhrase(String(phrase || ''));
  await clearWallet();
  if (r !== 0) throw new Error('Фраза не прошла проверку');
}

const bridge = {
  async newPhrase(words = 24) {
    return newWalletPhrase(words);
  },

  async checkPhrase(phrase) {
    await validatePhrase(phrase);
    return true;
  },

  async setNetwork(network) {
    await net(network === 'mainnet');
    return true;
  },

  async create({ login, phrase, password, network }) {
    login = String(login || '').trim().toLowerCase();
    if (!login) throw new Error('Укажите имя профиля');
    if (!password || String(password).length < 8) throw new Error('Пароль: минимум 8 символов');
    if (await getOne(login)) throw new Error('Такой профиль уже существует');
    await net(network === 'mainnet');
    await validatePhrase(phrase);
    const rc = await setWalletPhrase(String(phrase));
    if (rc !== 0) throw new Error('Не удалось загрузить ключи');
    const address = await walletAddress();
    if (!address) throw new Error('Не удалось получить адрес');
    const sealed = await seal(String(phrase), String(password));
    const rec = {
      login,
      name: String(login),
      network: network === 'mainnet' ? 'mainnet' : 'floonet',
      address,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      ...sealed,
    };
    await putOne(rec);
    return clean(rec);
  },

  async unlock({ login, password, network }) {
    login = String(login || '').trim().toLowerCase();
    const rec = await getOne(login);
    if (!rec) throw new Error('Профиль не найден');
    const phrase = await openSealed(rec, String(password));
    const useNet = rec.network || (network === 'mainnet' ? 'mainnet' : 'floonet');
    await net(useNet === 'mainnet');
    const rc = await setWalletPhrase(phrase);
    if (rc !== 0) throw new Error('Фраза профиля не прошла проверку');
    const address = await walletAddress();
    if (rec.address && address && rec.address !== address) {
      await clearWallet();
      throw new Error('Адрес профиля не совпал с ключами');
    }
    rec.lastUsed = Date.now();
    await putOne(rec);
    return clean(rec);
  },

  async lock() {
    await clearWallet();
    return true;
  },

  async list() {
    return (await listAll()).map(clean);
  },

  async showPhrase({ login, password }) {
    const rec = await getOne(String(login || '').trim().toLowerCase());
    if (!rec) throw new Error('Профиль не найден');
    return openSealed(rec, String(password));
  },

  async changePassword({ login, oldPassword, newPassword }) {
    if (!newPassword || String(newPassword).length < 8) throw new Error('Пароль: минимум 8 символов');
    const key = String(login || '').trim().toLowerCase();
    const rec = await getOne(key);
    if (!rec) throw new Error('Профиль не найден');
    const phrase = await openSealed(rec, String(oldPassword));
    Object.assign(rec, await seal(phrase, String(newPassword)));
    await putOne(rec);
    return true;
  },

  async rename({ login, name }) {
    const key = String(login || '').trim().toLowerCase();
    const rec = await getOne(key);
    if (!rec) throw new Error('Профиль не найден');
    rec.name = String(name || '').trim() || rec.name;
    await putOne(rec);
    return clean(rec);
  },

  async address() {
    return walletAddress();
  },

  async syncBundle({ url, height = 4102560 }) {
    const bytes = await fetchGatewayBundle(String(url || ''));
    const r = await walletScanBundle(bytes);
    return { amount: r.amount, count: r.count, height, size: bytes.length };
  },

  async scanBundle(bytes) {
    return walletScanBundle(bytes);
  },
};

globalThis.grinsightWeb = bridge;
export default bridge;
