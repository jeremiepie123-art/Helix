const http = require('node:http');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { URL } = require('node:url');
const fs = require('node:fs');
const path = require('node:path');

const scrypt = promisify(crypto.scrypt);

loadEnv(path.join(__dirname, '.env'));

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  ADMIN_SECRET,
  CORS_ORIGIN = '*',
  PORT = '3000'
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !ADMIN_SECRET) {
  console.error('Missing SUPABASE_URL, SUPABASE_SECRET_KEY, or ADMIN_SECRET in .env');
  process.exit(1);
}

const REST_URL = `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1`;
const SAFE_USER_SELECT = 'id,username,banned,created_at,last_login';
const LOGIN_USER_SELECT = 'id,username,password_hash,banned,created_at,last_login';
const KEY_SELECT = 'id,key_code,created_at,created_by,expires_at,assigned_user_id,redeemed_at,revoked';

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (!process.env[key]) process.env[key] = value;
  }
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    ...corsHeaders()
  });
  res.end(body);
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': CORS_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS'
  };
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function cleanUsername(username) {
  return String(username || '').trim();
}

function requireAdmin(req, res) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token || token !== ADMIN_SECRET) {
    json(res, 401, { error: 'Admin access required.' });
    return false;
  }
  return true;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    banned: user.banned,
    created_at: user.created_at,
    last_login: user.last_login
  };
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${hash.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const [kind, salt, hashHex] = String(stored || '').split('$');
  if (kind !== 'scrypt' || !salt || !hashHex) return false;
  const hash = Buffer.from(hashHex, 'hex');
  const check = await scrypt(password, salt, hash.length);
  return crypto.timingSafeEqual(hash, check);
}

async function supabaseFetch(route, options = {}) {
  const headers = {
    apikey: SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
    ...options.headers
  };

  const response = await fetch(`${REST_URL}${route}`, { ...options, headers });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const message = data?.message || data?.error || `Supabase error ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function logEvent(userId, eventType, details = {}) {
  try {
    await supabaseFetch('/user_events', {
      method: 'POST',
      body: JSON.stringify({
        user_id: userId || null,
        event_type: eventType,
        details
      })
    });
  } catch (error) {
    console.warn('Failed to log event:', error.message);
  }
}

async function findUserByUsername(username) {
  const query = `/app_users?select=${LOGIN_USER_SELECT}&username=ilike.${encodeURIComponent(username)}&limit=1`;
  const rows = await supabaseFetch(query);
  return rows[0] || null;
}

async function handleRegister(req, res) {
  const body = await readJson(req);
  const username = cleanUsername(body.username);
  const password = String(body.password || '');
  const keyCode = String(body.key || '').trim().toUpperCase();
  const isAdminUsername = username.toLowerCase() === 'admin';

  if (username.length < 3) return json(res, 400, { error: 'Username must be at least 3 characters.' });
  if (password.length < 4) return json(res, 400, { error: 'Password must be at least 4 characters.' });
  if (!isAdminUsername && !keyCode) return json(res, 400, { error: 'Access key is required.' });

  const existing = await findUserByUsername(username);
  if (existing) return json(res, 409, { error: 'Username already taken.' });

  let accessKey = null;
  if (!isAdminUsername) {
    const keys = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&key_code=eq.${encodeURIComponent(keyCode)}&limit=1`);
    accessKey = keys[0];
    if (!accessKey) return json(res, 404, { error: 'Access key not found.' });
    if (accessKey.revoked) return json(res, 403, { error: 'Access key is revoked.' });
    if (isExpiredKey(accessKey)) return json(res, 403, { error: 'Access key expired.' });
    if (accessKey.assigned_user_id) return json(res, 409, { error: 'Access key already used.' });
  }

  const password_hash = await hashPassword(password);
  const rows = await supabaseFetch(`/app_users?select=${SAFE_USER_SELECT}`, {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ username, password_hash })
  });

  const user = rows[0];

  if (accessKey) {
    const assigned = await supabaseFetch(`/access_keys?id=eq.${encodeURIComponent(accessKey.id)}&assigned_user_id=is.null&select=${KEY_SELECT}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({
        assigned_user_id: user.id,
        redeemed_at: new Date().toISOString()
      })
    });

    if (!assigned[0]) {
      await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(user.id)}`, { method: 'DELETE' });
      return json(res, 409, { error: 'Access key was just used. Try another key.' });
    }
  }

  await logEvent(user.id, 'register', { username, used_key: Boolean(accessKey) });
  json(res, 201, { user });
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  const username = cleanUsername(body.username);
  const password = String(body.password || '');

  const user = await findUserByUsername(username);
  if (!user) return json(res, 404, { error: 'Account not found.' });
  if (user.banned) return json(res, 403, { error: 'You are banned.' });

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json(res, 401, { error: 'Wrong password.' });

  if (user.username.toLowerCase() !== 'admin') {
    const accessKey = await getUserAccessKey(user.id);
    if (isExpiredKey(accessKey)) {
      await logEvent(user.id, 'expired_key_login_blocked', { username: user.username });
      return json(res, 403, { error: 'Your key expired.' });
    }
  }

  const now = new Date().toISOString();
  const rows = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(user.id)}&select=${SAFE_USER_SELECT}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ last_login: now })
  });

  await logEvent(user.id, 'login', { username: user.username });
  json(res, 200, { user: rows[0] || publicUser({ ...user, last_login: now }) });
}

async function handleAdminUsers(req, res) {
  if (!requireAdmin(req, res)) return;
  const users = await supabaseFetch(`/app_users?select=${SAFE_USER_SELECT}&order=created_at.desc`);
  const keys = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&order=created_at.desc&limit=1000`);
  const keyByUserId = new Map();

  for (const key of keys) {
    if (key.assigned_user_id && !keyByUserId.has(key.assigned_user_id)) {
      keyByUserId.set(key.assigned_user_id, key);
    }
  }

  json(res, 200, {
    users: users.map(user => ({
      ...user,
      access_key: keyByUserId.get(user.id) || null
    }))
  });
}

async function handleAdminEvents(req, res) {
  if (!requireAdmin(req, res)) return;
  const events = await supabaseFetch('/user_events?select=id,user_id,event_type,details,created_at&order=created_at.desc&limit=100');
  json(res, 200, { events });
}

function makeAccessKey() {
  const part = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `CRYPT-${part()}-${part()}-${part()}`;
}

function isExpiredKey(key) {
  return Boolean(key?.expires_at && new Date(key.expires_at).getTime() <= Date.now());
}

function makeExpiryDate(expiresIn, customExpiry = {}) {
  if (String(expiresIn || '') === 'custom') {
    const days = Math.max(0, Math.min(Number(customExpiry.days || 0), 365));
    const hours = Math.max(0, Math.min(Number(customExpiry.hours || 0), 23));
    const minutes = Math.max(0, Math.min(Number(customExpiry.minutes || 0), 59));
    const totalMs = ((days * 24 * 60) + (hours * 60) + minutes) * 60 * 1000;
    if (totalMs <= 0) return null;
    return new Date(Date.now() + totalMs).toISOString();
  }

  const daysByValue = {
    '1d': 1,
    '7d': 7,
    '30d': 30,
    '90d': 90
  };
  const days = daysByValue[String(expiresIn || 'never')];
  if (!days) return null;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function makeExtendedExpiryDate(currentExpiresAt, customExpiry = {}) {
  const days = Math.max(0, Math.min(Number(customExpiry.days || 0), 365));
  const hours = Math.max(0, Math.min(Number(customExpiry.hours || 0), 23));
  const minutes = Math.max(0, Math.min(Number(customExpiry.minutes || 0), 59));
  const totalMs = ((days * 24 * 60) + (hours * 60) + minutes) * 60 * 1000;
  if (totalMs <= 0) return null;
  const currentMs = currentExpiresAt ? new Date(currentExpiresAt).getTime() : 0;
  const baseMs = Number.isFinite(currentMs) && currentMs > Date.now() ? currentMs : Date.now();
  return new Date(baseMs + totalMs).toISOString();
}

async function getUserAccessKey(userId) {
  const rows = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&assigned_user_id=eq.${encodeURIComponent(userId)}&limit=1`);
  return rows[0] || null;
}

async function handleAdminKeys(req, res) {
  if (!requireAdmin(req, res)) return;
  const keys = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&order=created_at.desc&limit=100`);
  json(res, 200, { keys });
}

async function handleAdminCreateKey(req, res) {
  if (!requireAdmin(req, res)) return;
  const body = await readJson(req);
  const count = Math.max(1, Math.min(Number(body.count || 1), 25));
  const created_by = String(body.createdBy || 'Admin').slice(0, 80);
  const expires_at = makeExpiryDate(body.expiresIn, body.customExpiry);
  if (String(body.expiresIn || '') === 'custom' && !expires_at) {
    return json(res, 400, { error: 'Custom expiry must be at least 1 minute.' });
  }
  const rows = [];

  for (let i = 0; i < count; i++) {
    rows.push({
      key_code: makeAccessKey(),
      created_by,
      expires_at
    });
  }

  const keys = await supabaseFetch(`/access_keys?select=${KEY_SELECT}`, {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify(rows)
  });
  await logEvent(null, 'generate_keys', { count, expires_at });
  json(res, 201, { keys });
}

async function handleUserKey(req, res, id) {
  const rows = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&assigned_user_id=eq.${encodeURIComponent(id)}&revoked=eq.false&limit=1`);
  json(res, 200, { key: rows[0] || null });
}

async function handleRenewalRequest(req, res, id) {
  const rows = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(id)}&select=${SAFE_USER_SELECT}&limit=1`);
  const user = rows[0];
  if (!user) return json(res, 404, { error: 'User not found.' });
  const accessKey = user.username.toLowerCase() === 'admin' ? null : await getUserAccessKey(user.id);
  await logEvent(user.id, 'key_renewal_request', {
    username: user.username,
    key_code: accessKey?.key_code || null,
    expires_at: accessKey?.expires_at || null,
    expired: isExpiredKey(accessKey)
  });
  json(res, 201, { ok: true });
}

async function handleRedeemKey(req, res) {
  const body = await readJson(req);
  const userId = String(body.userId || '');
  const keyCode = String(body.key || '').trim().toUpperCase();
  if (!userId || !keyCode) return json(res, 400, { error: 'User and key are required.' });

  const users = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(userId)}&select=${SAFE_USER_SELECT}&limit=1`);
  const user = users[0];
  if (!user) return json(res, 404, { error: 'User not found.' });
  if (user.banned) return json(res, 403, { error: 'You are banned.' });

  const existing = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&assigned_user_id=eq.${encodeURIComponent(userId)}&revoked=eq.false&limit=1`);
  if (existing[0]) return json(res, 409, { error: 'You already redeemed a key.' });

  const keys = await supabaseFetch(`/access_keys?select=${KEY_SELECT}&key_code=eq.${encodeURIComponent(keyCode)}&limit=1`);
  const key = keys[0];
  if (!key) return json(res, 404, { error: 'Key not found.' });
  if (key.revoked) return json(res, 403, { error: 'Key is revoked.' });
  if (isExpiredKey(key)) return json(res, 403, { error: 'Key expired.' });
  if (key.assigned_user_id) return json(res, 409, { error: 'Key already used.' });

  const updated = await supabaseFetch(`/access_keys?id=eq.${encodeURIComponent(key.id)}&select=${KEY_SELECT}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({
      assigned_user_id: userId,
      redeemed_at: new Date().toISOString()
    })
  });
  await logEvent(userId, 'redeem_key', { key: keyCode });
  json(res, 200, { key: updated[0] });
}

async function handleUserStatus(req, res, id) {
  const rows = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(id)}&select=${SAFE_USER_SELECT}&limit=1`);
  const user = rows[0];
  if (!user) return json(res, 404, { error: 'User not found.' });
  const accessKey = user.username.toLowerCase() === 'admin' ? null : await getUserAccessKey(user.id);
  json(res, 200, {
    user: {
      ...user,
      access_key: accessKey,
      key_expired: isExpiredKey(accessKey)
    }
  });
}

async function handleAdminBan(req, res, id) {
  if (!requireAdmin(req, res)) return;
  const body = await readJson(req);
  const banned = Boolean(body.banned);
  const rows = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(id)}&select=${SAFE_USER_SELECT}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ banned })
  });
  const user = rows[0];
  if (!user) return json(res, 404, { error: 'User not found.' });
  await logEvent(user.id, banned ? 'ban' : 'unban', { username: user.username });
  json(res, 200, { user });
}

async function handleAdminExtendKey(req, res, id) {
  if (!requireAdmin(req, res)) return;
  const body = await readJson(req);
  const users = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(id)}&select=${SAFE_USER_SELECT}&limit=1`);
  const user = users[0];
  if (!user) return json(res, 404, { error: 'User not found.' });
  if (user.username.toLowerCase() === 'admin') return json(res, 400, { error: 'Admin does not need a key.' });

  const key = await getUserAccessKey(user.id);
  if (!key) return json(res, 404, { error: 'User has no key to extend.' });

  const expires_at = makeExtendedExpiryDate(key.expires_at, body.customExpiry);
  if (!expires_at) return json(res, 400, { error: 'Extension must be at least 1 minute.' });

  const rows = await supabaseFetch(`/access_keys?id=eq.${encodeURIComponent(key.id)}&select=${KEY_SELECT}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ expires_at })
  });
  await logEvent(user.id, 'extend_key', {
    username: user.username,
    key_code: key.key_code,
    expires_at,
    added: body.customExpiry || {}
  });
  json(res, 200, { key: rows[0], user });
}

async function handleAdminResetPassword(req, res, id) {
  if (!requireAdmin(req, res)) return;
  const body = await readJson(req);
  const newPassword = String(body.newPassword || '');
  if (newPassword.length < 4) return json(res, 400, { error: 'New password must be at least 4 characters.' });

  const password_hash = await hashPassword(newPassword);
  const rows = await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(id)}&select=${SAFE_USER_SELECT}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ password_hash })
  });
  const user = rows[0];
  if (!user) return json(res, 404, { error: 'User not found.' });
  await logEvent(user.id, 'reset_password', { username: user.username });
  json(res, 200, { user });
}

async function handleAdminDelete(req, res, id) {
  if (!requireAdmin(req, res)) return;
  await logEvent(id, 'delete_user', {});
  await supabaseFetch(`/app_users?id=eq.${encodeURIComponent(id)}`, { method: 'DELETE' });
  json(res, 200, { ok: true });
}

async function route(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders());
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  try {
    if (req.method === 'GET' && pathname === '/health') return json(res, 200, { ok: true, service: 'crypted-ui-api' });
    if (req.method === 'POST' && pathname === '/api/register') return await handleRegister(req, res);
    if (req.method === 'POST' && pathname === '/api/login') return await handleLogin(req, res);
    if (req.method === 'GET' && pathname === '/api/admin/users') return await handleAdminUsers(req, res);
    if (req.method === 'GET' && pathname === '/api/admin/events') return await handleAdminEvents(req, res);
    if (req.method === 'GET' && pathname === '/api/admin/keys') return await handleAdminKeys(req, res);
    if (req.method === 'POST' && pathname === '/api/admin/keys') return await handleAdminCreateKey(req, res);
    if (req.method === 'POST' && pathname === '/api/keys/redeem') return await handleRedeemKey(req, res);

    const statusMatch = pathname.match(/^\/api\/users\/([^/]+)\/status$/);
    if (req.method === 'GET' && statusMatch) return await handleUserStatus(req, res, statusMatch[1]);

    const userKeyMatch = pathname.match(/^\/api\/users\/([^/]+)\/key$/);
    if (req.method === 'GET' && userKeyMatch) return await handleUserKey(req, res, userKeyMatch[1]);

    const renewalMatch = pathname.match(/^\/api\/users\/([^/]+)\/renewal-request$/);
    if (req.method === 'POST' && renewalMatch) return await handleRenewalRequest(req, res, renewalMatch[1]);

    const banMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/ban$/);
    if (req.method === 'PATCH' && banMatch) return await handleAdminBan(req, res, banMatch[1]);

    const extendMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/extend-key$/);
    if (req.method === 'PATCH' && extendMatch) return await handleAdminExtendKey(req, res, extendMatch[1]);

    const resetMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/reset-password$/);
    if (req.method === 'POST' && resetMatch) return await handleAdminResetPassword(req, res, resetMatch[1]);

    const deleteMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (req.method === 'DELETE' && deleteMatch) return await handleAdminDelete(req, res, deleteMatch[1]);

    json(res, 404, { error: 'Not found.' });
  } catch (error) {
    json(res, error.status || 500, { error: error.message || 'Server error.' });
  }
}

http.createServer(route).listen(Number(PORT), '0.0.0.0', () => {
  console.log(`Crypted UI API running on port ${PORT}`);
});
