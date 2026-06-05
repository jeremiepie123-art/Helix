# Crypted UI API

This is the backend that sits between your Tampermonkey script and Supabase.

Flow:

```txt
Tampermonkey script -> this API -> Supabase database
```

Do not put your Supabase secret key in Tampermonkey. It only belongs in this API server.

## Setup

1. Install Node.js if your host does not already provide it.
2. Copy `.env.example` to `.env`.
3. Fill in:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SECRET_KEY=your_sb_secret_key_here
ADMIN_SECRET=make-a-private-admin-secret
CORS_ORIGIN=*
PORT=3000
```

Use your Supabase **Secret key** for `SUPABASE_SECRET_KEY`.

Do not share the secret key.

## Run Locally

No npm packages are needed. This server only uses built-in Node.js features.

```bash
node server.js
```

Open:

```txt
http://localhost:3000/health
```

You should see:

```json
{ "ok": true, "service": "crypted-ui-api" }
```

## Host It

Use a host like Render or Railway.

Render settings:

```txt
Build command: leave empty
Start command: node server.js
```

Add the environment variables from `.env.example` in the host dashboard.

After hosting, your API URL will look like:

```txt
https://your-api-name.onrender.com
```

That is the URL your Tampermonkey script should use.

## Routes

Public:

```txt
POST /api/register
POST /api/login
GET  /health
```

Admin routes require:

```txt
Authorization: Bearer YOUR_ADMIN_SECRET
```

Admin:

```txt
GET    /api/admin/users
GET    /api/admin/events
PATCH  /api/admin/users/:id/ban
POST   /api/admin/users/:id/reset-password
DELETE /api/admin/users/:id
```

Passwords are hashed. Admins can reset passwords, but they cannot view old raw passwords.
