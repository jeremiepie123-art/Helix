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

  if (username.length < 3) return json(res, 400, { error: 'Username must be at least 3 characters.' });
  if (password.length < 4) return json(res, 400, { error: 'Password must be at least 4 characters.' });

  const existing = await findUserByUsername(username);
  if (existing) return json(res, 409, { error: 'Username already taken.' });

  const password_hash = await hashPassword(password);
  const rows = await supabaseFetch(`/app_users?select=${SAFE_USER_SELECT}`, {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ username, password_hash })
  });

  const user = rows[0];
  await logEvent(user.id, 'register', { username });
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
  json(res, 200, { users });
}

async function handleAdminEvents(req, res) {
  if (!requireAdmin(req, res)) return;
  const events = await supabaseFetch('/user_events?select=id,user_id,event_type,details,created_at&order=created_at.desc&limit=100');
  json(res, 200, { events });
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

    const banMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/ban$/);
    if (req.method === 'PATCH' && banMatch) return await handleAdminBan(req, res, banMatch[1]);

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
