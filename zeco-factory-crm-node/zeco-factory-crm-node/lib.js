// ============================================================
//  lib.js - database (node:sqlite), passwords, helpers
//  No npm packages needed. Requires Node.js 22.5 or newer.
// ============================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');   // on a host: point DATA_DIR at the persistent disk
const CHEQUE_SOON_DAYS = 30;

const ROLES = ['super_admin', 'admin', 'user'];
const ROLES_ALL = ['user', 'admin', 'super_admin'];
const ROLES_STAFF = ['admin', 'super_admin'];
const ROLES_SUPER = ['super_admin'];

class HttpError extends Error {
  constructor(status, message, code = null) { super(message); this.status = status; this.code = code; }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '',
  phone_key TEXT UNIQUE, city TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS khata_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL REFERENCES customers(id),
  entry_date TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('dilai','wasool','wapsi')),
  detail TEXT NOT NULL DEFAULT '', weight REAL NOT NULL DEFAULT 0, rate REAL NOT NULL DEFAULT 0,
  amount REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS cheques (
  id INTEGER PRIMARY KEY AUTOINCREMENT, party TEXT NOT NULL, amount REAL NOT NULL DEFAULT 0,
  issued_on TEXT NOT NULL, cash_on TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','cleared')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS gate_passes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, pass_date TEXT NOT NULL, party TEXT NOT NULL, product TEXT NOT NULL,
  qty REAL NOT NULL, vehicle TEXT NOT NULL DEFAULT '', total REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS gate_pass_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, pass_id INTEGER NOT NULL REFERENCES gate_passes(id) ON DELETE CASCADE,
  product TEXT NOT NULL, qty REAL NOT NULL, rate REAL NOT NULL DEFAULT 0, price REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('super_admin','admin','user')), password_hash TEXT NOT NULL,
  must_change INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, first_at INTEGER NOT NULL, until_at INTEGER NOT NULL);
`;

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'crm.db'));
db.exec('PRAGMA busy_timeout = 5000');
db.exec('PRAGMA foreign_keys = ON');
try { db.exec('PRAGMA journal_mode = WAL'); } catch (e) { /* default mode is fine */ }
db.exec(SCHEMA);
{
  const cols = db.prepare('PRAGMA table_info(gate_passes)').all();
  const kc = db.prepare('PRAGMA table_info(khata_entries)').all();
  if (!kc.some(c => c.name === 'paid')) db.exec('ALTER TABLE khata_entries ADD COLUMN paid INTEGER NOT NULL DEFAULT 0');
  if (!kc.some(c => c.name === 'pay_method')) db.exec("ALTER TABLE khata_entries ADD COLUMN pay_method TEXT NOT NULL DEFAULT ''");
  if (!cols.some(c => c.name === 'total')) db.exec('ALTER TABLE gate_passes ADD COLUMN total REAL NOT NULL DEFAULT 0');
  if (db.prepare('SELECT COUNT(*) AS n FROM products').get().n === 0) {
    const st = db.prepare('INSERT INTO products (name) VALUES (?)');
    for (const n of ['ڈھلائی', 'پمپ', 'ہانڈی', 'کپ', 'پلے', 'نلکا', 'فلینج']) st.run(n);
  }
}

const clean = a => a.map(v => (v === undefined ? null : typeof v === 'boolean' ? +v : v));
const rows = (sql, p = []) => db.prepare(sql).all(...clean(p)).map(r => ({ ...r }));
const row = (sql, p = []) => { const r = db.prepare(sql).get(...clean(p)); return r ? { ...r } : null; };
const val = (sql, p = []) => { const r = db.prepare(sql).get(...clean(p)); return r ? Object.values(r)[0] : null; };
const run = (sql, p = []) => db.prepare(sql).run(...clean(p));
const insert = (sql, p = []) => Number(db.prepare(sql).run(...clean(p)).lastInsertRowid);
function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; }
}

// ---------------- passwords (scrypt, built into Node) ----------------
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return 'scrypt$' + salt.toString('hex') + '$' + h.toString('hex');
}
function verifyPw(pw, stored) {
  const p = String(stored).split('$');
  if (p[0] !== 'scrypt' || p.length !== 3) return false;      // e.g. a hash made by the PHP version
  const h = crypto.scryptSync(pw, Buffer.from(p[1], 'hex'), 64, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(h, Buffer.from(p[2], 'hex'));
}
function checkPasswordRules(pw, username = null) {
  pw = String(pw ?? '');
  if ([...pw].length < 8) return 'Password must be at least 8 characters.';
  if ([...pw].length > 128) return 'Password is too long.';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Password must contain both letters and numbers.';
  if (username !== null && pw.toLowerCase() === username.toLowerCase()) return 'Password cannot be the same as the username.';
  return null;
}
function randomPassword() {
  const all = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for (;;) {
    let p = '';
    for (let i = 0; i < 12; i++) p += all[crypto.randomInt(0, all.length)];
    if (checkPasswordRules(p) === null) return p;
  }
}

// ---------------- input cleaning ----------------
const isScalar = v => ['string', 'number', 'boolean'].includes(typeof v);
const s = (v, max = 0) => { v = isScalar(v) ? String(v).trim() : ''; return max > 0 ? [...v].slice(0, max).join('') : v; };
const isNumeric = v => (typeof v === 'number' && isFinite(v)) || (typeof v === 'string' && v.trim() !== '' && isFinite(Number(v)));
const num = v => (isNumeric(v) && Number(v) >= 0 ? Number(v) : 0);
const numOrNull = v => (isNumeric(v) && Number(v) >= 0 ? Number(v) : null);
const isDate = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
const todayUtc = () => new Date().toISOString().slice(0, 10);
const ymd = ms => new Date(ms).toISOString().slice(0, 10);
function normPhone(p) {
  let d = String(p ?? '').replace(/\D/g, '');
  if (d.startsWith('92') && d.length === 12) d = '0' + d.slice(2);
  return d;
}
const sum = (a, k) => a.reduce((t, x) => t + x[k], 0);

module.exports = {
  ROOT, DATA_DIR, CHEQUE_SOON_DAYS, ROLES, ROLES_ALL, ROLES_STAFF, ROLES_SUPER, HttpError,
  db, rows, row, val, run, insert, tx, hashPw, verifyPw, checkPasswordRules, randomPassword,
  s, num, numOrNull, isNumeric, isDate, todayUtc, ymd, normPhone, sum,
};
