import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// node:sqlite = database bawaan Node.js (tanpa install, tanpa compile) — butuh Node >= 22.5
let DatabaseSync;
try {
  ({ DatabaseSync } = await import('node:sqlite'));
} catch {
  console.error('FATAL: modul node:sqlite tidak tersedia. Gunakan image Node.js 22.5+/23.');
  process.exit(1);
}

const app = express();
const port = Number(process.env.PORT || process.env.SERVER_PORT || 3000);
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) {
  console.warn('[PERINGATAN] JWT_SECRET tidak diset — token akan tidak valid setelah restart.');
}

const dbFile = process.env.DB_FILE || './data/users.db';
fs.mkdirSync(path.dirname(dbFile), { recursive: true });
const db = new DatabaseSync(dbFile);
db.exec('PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// Buat akun admin otomatis dari .env saat pertama jalan
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
  const ada = db.prepare('SELECT id FROM users WHERE username = ?').get(process.env.ADMIN_USERNAME);
  if (!ada) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
      .run(process.env.ADMIN_USERNAME, null, hash);
    console.log(`[info] Akun admin "${process.env.ADMIN_USERNAME}" dibuat otomatis.`);
  }
}

app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: false }));
app.use(express.json({ limit: '32kb' }));

// === REQUEST LOGGER: catat semua yang diminta APK ===
app.use((req, _res, next) => {
  const body = Object.keys(req.body || {}).length ? ' BODY=' + JSON.stringify(req.body).slice(0, 400) : '';
  const line = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}${body} UA=${req.headers['user-agent'] || '-'}`;
  console.log('[REQ]', line);
  try { fs.appendFileSync('./data/requests.log', line + '\n'); } catch {}
  next();
});

function tokenFor(user) {
  return jwt.sign({ sub: user.id, username: user.username }, SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: 'Token tidak ditemukan' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { return res.status(401).json({ success: false, message: 'Token tidak valid atau kedaluwarsa' }); }
}
function publicUser(row) {
  return { id: Number(row.id), username: row.username, email: row.email, is_active: Boolean(row.is_active), created_at: row.created_at };
}

app.get('/health', (_req, res) => res.json({ success: true, service: 'login-api' }));

app.post('/register', async (req, res) => {
  const { username, email = null, password } = req.body || {};
  if (!username || !password || username.length < 3 || password.length < 8)
    return res.status(400).json({ success: false, message: 'Username minimal 3 karakter dan password minimal 8 karakter' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
      .run(username.trim(), email?.trim() || null, hash);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(info.lastInsertRowid));
    res.status(201).json({ success: true, user: publicUser(user), token: tokenFor({ id: Number(user.id), username: user.username }) });
  } catch (e) {
    if (String(e).includes('UNIQUE') || String(e).includes('constraint'))
      return res.status(409).json({ success: false, message: 'Username atau email sudah digunakan' });
    console.error(e);
    res.status(500).json({ success: false, message: 'Gagal membuat akun' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username || '', username || '');
  if (!user || !user.is_active || !(await bcrypt.compare(password || '', user.password_hash)))
    return res.status(401).json({ success: false, message: 'Username atau password salah' });
  res.json({ success: true, token: tokenFor({ id: Number(user.id), username: user.username }), user: publicUser(user) });
});

app.get('/me', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.user.sub));
  if (!user || !user.is_active) return res.status(401).json({ success: false, message: 'Akun tidak aktif' });
  res.json({ success: true, user: publicUser(user) });
});

app.post('/change-password', auth, async (req, res) => {
  const { old_password, new_password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.user.sub));
  if (!user || !(await bcrypt.compare(old_password || '', user.password_hash)))
    return res.status(401).json({ success: false, message: 'Password lama salah' });
  if (!new_password || new_password.length < 8)
    return res.status(400).json({ success: false, message: 'Password baru minimal 8 karakter' });
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(await bcrypt.hash(new_password, 12), Number(user.id));
  res.json({ success: true, message: 'Password berhasil diubah' });
});

// Sementara: endpoint tak dikenal dijawab permisif biar APK jalan terus (mode diagnostik)
app.use((req, res) => {
  console.log('[MISS]', req.method, req.originalUrl);
  res.json({ status: 'success', success: true, code: 200, message: 'ok', data: {}, result: {} });
});

app.listen(port, '0.0.0.0', () => console.log(`Login API berjalan di port ${port}`));
