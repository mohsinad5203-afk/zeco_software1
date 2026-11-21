// ============================================================
//  server.js - ZECO Factory CRM (Node.js, no npm packages)
//  Start:  node server.js     then open  http://localhost:3000
// ============================================================
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const L = require('./lib');
const { HttpError, ROLES, ROLES_ALL, ROLES_STAFF, ROLES_SUPER, rows, row, val, run, insert, tx,
  s, num, numOrNull, isNumeric, isDate, todayUtc, ymd, normPhone, sum, hashPw, verifyPw, checkPasswordRules, randomPassword } = L;

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');   // hosting services set PORT, so listen on all addresses there          // set HOST=0.0.0.0 to open it from other devices
const PUBLIC = path.join(L.ROOT, 'public');
const COOKIE = 'tb_session';
const SESSION_MS = 8 * 3600 * 1000, LOCK_MS = 15 * 60 * 1000, MAX_ACC = 5, MAX_IP = 20;
const now = () => Date.now();
const sha = t => crypto.createHash('sha256').update(t).digest('hex');

// ---------------- sessions / login lock ----------------
function cookieOf(req, name) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}
const tokenHash = req => { const t = cookieOf(req, COOKIE); return t ? sha(t) : null; };
const isHttps = req => process.env.COOKIE_SECURE === '1' || (process.env.TRUST_PROXY === '1' && req.headers['x-forwarded-proto'] === 'https');
function setCookie(res, req, token, maxAge) {
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${isHttps(req) ? '; Secure' : ''}`);
}
function createSession(uid) {
  run('DELETE FROM sessions WHERE expires_at < ?', [now()]);
  const token = crypto.randomBytes(32).toString('hex');
  run('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)', [sha(token), uid, now() + SESSION_MS]);
  return token;
}
function destroyUserSessions(uid, except = '') { run('DELETE FROM sessions WHERE user_id=? AND token_hash != ?', [uid, except || '']); }
function getUser(req) {
  const h = tokenHash(req);
  if (!h) return null;
  const r = row(`SELECT u.id,u.username,u.name,u.role,u.must_change,u.active,s.expires_at
                 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, [h]);
  if (!r) return null;
  if (r.expires_at < now() || !r.active) { run('DELETE FROM sessions WHERE token_hash=?', [h]); return null; }
  run('UPDATE sessions SET expires_at=? WHERE token_hash=?', [now() + SESSION_MS, h]);
  return { id: r.id, username: r.username, name: r.name, role: r.role, must_change: !!r.must_change };
}
function clientIp(req) {
  if (process.env.TRUST_PROXY === '1') { const f = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(); if (f) return f; }
  return req.socket.remoteAddress || 'unknown';
}
function lockedMinutes(key, max) {
  const a = row('SELECT n,until_at FROM login_fails WHERE k=?', [key]);
  return a && a.n >= max && a.until_at > now() ? Math.ceil((a.until_at - now()) / 60000) : 0;
}
function bumpFail(key, max) {
  const t = now();
  let a = row('SELECT n,first_at FROM login_fails WHERE k=?', [key]);
  if (!a || t - a.first_at > LOCK_MS) a = { n: 0, first_at: t };
  const n = a.n + 1;
  run('INSERT OR REPLACE INTO login_fails (k,n,first_at,until_at) VALUES (?,?,?,?)', [key, n, a.first_at, n >= max ? t + LOCK_MS : 0]);
}

// ---------------- first super admin ----------------
function bootstrapAdmin() {
  if (val('SELECT COUNT(*) FROM users') > 0) return;
  const fromEnv = process.env.SUPERADMIN_PASSWORD || null;
  const username = process.env.SUPERADMIN_USER || 'superadmin';
  const pw = fromEnv ?? randomPassword();
  if (fromEnv) { const bad = checkPasswordRules(fromEnv, username); if (bad) throw new HttpError(500, 'SUPERADMIN_PASSWORD: ' + bad); }
  insert('INSERT INTO users (username,name,role,password_hash,must_change) VALUES (?,?,?,?,?)',
    [username, 'Super Admin', 'super_admin', hashPw(pw), fromEnv ? 0 : 1]);
  if (!fromEnv) {
    fs.writeFileSync(path.join(L.DATA_DIR, 'FIRST_PASSWORD.txt'),
      `FIRST-TIME SETUP: Super admin account\r\nUsername : ${username}\r\nPassword : ${pw}\r\n\r\nYou must change this password at first login. This file is then deleted automatically.\r\n`);
    console.log(`Super admin "${username}" created. Password is in data/FIRST_PASSWORD.txt`);
  }
}

// ---------------- routes ----------------
const ROUTES = [];
function route(method, pattern, handler, opts = {}) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  ROUTES.push({ method, re, keys, handler, pub: !!opts.public, roles: opts.roles || ROLES_STAFF, allowMustChange: !!opts.allowMustChange });
}
const ALL = { roles: ROLES_ALL }, STAFF = { roles: ROLES_STAFF }, SUPER = { roles: ROLES_SUPER };

// ----- auth -----
route('POST', '/api/login', (c) => {
  const username = s(c.body.username), password = typeof c.body.password === 'string' || typeof c.body.password === 'number' ? String(c.body.password) : '';
  if (!username || !password) throw new HttpError(400, 'Enter your username and password.');
  const ip = clientIp(c.req), key = ip + '|' + username.toLowerCase();
  const m = Math.max(lockedMinutes(key, MAX_ACC), lockedMinutes('ip:' + ip, MAX_IP));
  if (m) throw new HttpError(429, `Too many failed attempts. Try again in ${m} minute(s).`);
  const u = row('SELECT * FROM users WHERE username=?', [username]);
  const ok = u ? verifyPw(password, u.password_hash) : (hashPw(password), false);
  if (!u || !ok || !u.active) {
    bumpFail(key, MAX_ACC); bumpFail('ip:' + ip, MAX_IP);
    run('DELETE FROM login_fails WHERE first_at < ? AND until_at < ?', [now() - LOCK_MS, now()]);
    throw new HttpError(401, 'Wrong username or password.');
  }
  run('DELETE FROM login_fails WHERE k=?', [key]);
  setCookie(c.res, c.req, createSession(u.id), SESSION_MS / 1000);
  return { id: u.id, username: u.username, name: u.name, role: u.role, must_change: !!u.must_change };
}, { public: true });
route('GET', '/api/me', c => c.user, { roles: ROLES_ALL, allowMustChange: true });
route('POST', '/api/logout', c => {
  const h = tokenHash(c.req); if (h) run('DELETE FROM sessions WHERE token_hash=?', [h]);
  setCookie(c.res, c.req, '', 0); return { ok: true };
}, { roles: ROLES_ALL, allowMustChange: true });
route('POST', '/api/change-password', c => {
  const u = row('SELECT * FROM users WHERE id=?', [c.user.id]);
  const cur = typeof c.body.current === 'string' ? c.body.current : '', next = typeof c.body.next === 'string' ? c.body.next : '';
  if (!verifyPw(cur, u.password_hash)) throw new HttpError(400, 'Current password is wrong.');
  const bad = checkPasswordRules(next, u.username); if (bad) throw new HttpError(400, bad);
  if (next === cur) throw new HttpError(400, 'New password must be different from the current one.');
  run('UPDATE users SET password_hash=?, must_change=0 WHERE id=?', [hashPw(next), u.id]);
  destroyUserSessions(u.id, tokenHash(c.req));
  try { fs.unlinkSync(path.join(L.DATA_DIR, 'FIRST_PASSWORD.txt')); } catch (_) {}
  return { ok: true };
}, { roles: ROLES_ALL, allowMustChange: true });

// ----- users (super admin only) -----
const otherSupers = id => val("SELECT COUNT(*) FROM users WHERE role='super_admin' AND active=1 AND id != ?", [id]);
route('GET', '/api/users', () => rows('SELECT id,username,name,role,active,must_change,created_at FROM users ORDER BY id'), SUPER);
route('POST', '/api/users', c => {
  const b = c.body, username = s(b.username), name = s(b.name), role = b.role;
  if (!/^[A-Za-z0-9._-]{3,30}$/.test(username)) throw new HttpError(400, 'Username must be 3-30 characters (letters, numbers, . _ -).');
  if (!name) throw new HttpError(400, 'Name is required.');
  if (!ROLES.includes(role)) throw new HttpError(400, 'Choose a role.');
  const pw = typeof b.password === 'string' ? b.password : '';
  const bad = checkPasswordRules(pw, username); if (bad) throw new HttpError(400, bad);
  try { return { id: insert('INSERT INTO users (username,name,role,password_hash,must_change) VALUES (?,?,?,?,1)', [username, name, role, hashPw(pw)]) }; }
  catch (e) { if (/UNIQUE/i.test(e.message)) throw new HttpError(409, 'This username already exists.'); throw e; }
}, SUPER);
route('PUT', '/api/users/:id', c => {
  const b = c.body, u = row('SELECT * FROM users WHERE id=?', [c.params.id]);
  if (!u) throw new HttpError(404, 'User not found.');
  const name = b.name !== undefined ? s(b.name) : u.name.trim();
  const role = b.role ?? u.role;
  const active = 'active' in b ? (b.active ? 1 : 0) : u.active;
  if (!name) throw new HttpError(400, 'Name is required.');
  if (!ROLES.includes(role)) throw new HttpError(400, 'Invalid role.');
  if (u.id === c.user.id && (role !== u.role || !active)) throw new HttpError(400, 'You cannot change your own role or status.');
  if (u.role === 'super_admin' && (role !== 'super_admin' || !active) && !otherSupers(u.id)) throw new HttpError(400, 'There must be at least one active super admin.');
  let hash = u.password_hash, must = u.must_change;
  const np = typeof b.password === 'string' ? b.password : '';
  if (np !== '') { const bad = checkPasswordRules(np, u.username); if (bad) throw new HttpError(400, bad); hash = hashPw(np); must = 1; }
  run('UPDATE users SET name=?, role=?, active=?, password_hash=?, must_change=? WHERE id=?', [name, role, active, hash, must, u.id]);
  if (!active || np !== '' || role !== u.role) destroyUserSessions(u.id);
  return { ok: true };
}, SUPER);
route('DELETE', '/api/users/:id', c => {
  const u = row('SELECT * FROM users WHERE id=?', [c.params.id]);
  if (!u) throw new HttpError(404, 'User not found.');
  if (u.id === c.user.id) throw new HttpError(400, 'You cannot delete your own account.');
  if (u.role === 'super_admin' && !otherSupers(u.id)) throw new HttpError(400, 'The last super admin cannot be deleted.');
  run('DELETE FROM users WHERE id=?', [u.id]); return { ok: true };
}, SUPER);

// ----- customers (parties) -----
route('GET', '/api/customers', () => rows(`SELECT c.id,c.name,c.phone,c.city,
  COALESCE((SELECT SUM(CASE WHEN k.kind='dilai' THEN (CASE WHEN k.paid=1 THEN 0 ELSE k.amount END) ELSE -k.amount END) FROM khata_entries k WHERE k.customer_id=c.id),0) AS due
  FROM customers c ORDER BY c.name`), ALL);
const cleanParty = b => {
  const name = s(b.name, 100), phone = s(b.phone, 30);
  if (!name) throw new HttpError(400, 'Name is required.');
  const key = normPhone(phone);
  return { name, phone, key: key || null, city: s(b.city, 60) };
};
const dupPhone = e => { if (/UNIQUE/i.test(e.message)) throw new HttpError(409, 'This phone number already belongs to another party.'); throw e; };
route('POST', '/api/customers', c => {
  const p = cleanParty(c.body);
  try { return { id: insert('INSERT INTO customers (name,phone,phone_key,city) VALUES (?,?,?,?)', [p.name, p.phone, p.key, p.city]) }; } catch (e) { dupPhone(e); }
}, ALL);
route('PUT', '/api/customers/:id', c => {
  if (!row('SELECT 1 FROM customers WHERE id=?', [c.params.id])) throw new HttpError(404, 'Party not found.');
  const p = cleanParty(c.body);
  try { run('UPDATE customers SET name=?,phone=?,phone_key=?,city=? WHERE id=?', [p.name, p.phone, p.key, p.city, c.params.id]); } catch (e) { dupPhone(e); }
  return { ok: true };
}, STAFF);
route('DELETE', '/api/customers/:id', c => {
  if (val('SELECT COUNT(*) FROM khata_entries WHERE customer_id=?', [c.params.id])) throw new HttpError(409, 'This party has khata entries, so it cannot be deleted.');
  run('DELETE FROM customers WHERE id=?', [c.params.id]); return { ok: true };
}, STAFF);

// ----- khata -----
const KINDS = ['dilai', 'wasool', 'wapsi'];
const PAY = { cash: 'کیش', cheque: 'چیک', bank: 'بینک ٹرانزیکشن' };
route('GET', '/api/khata/balances', () => rows(`SELECT customer_id,
  COALESCE(SUM(CASE WHEN kind='dilai' AND paid=0 THEN amount END),0) AS out,
  COALESCE(SUM(CASE WHEN kind!='dilai' THEN amount END),0) AS inn FROM khata_entries GROUP BY customer_id`), ALL);
route('POST', '/api/khata/bill', c => {
  // The party can be sent by id or by name. A NEW name creates the party automatically, so the bill goes straight into its khata.
  const b = c.body, name = s(b.party, 100);
  let cid = Number(b.customer_id) || 0;
  if (cid && !row('SELECT 1 FROM customers WHERE id=?', [cid])) throw new HttpError(404, 'Party not found.');
  if (!cid && !name) throw new HttpError(400, 'Enter the party name.');
  if (!cid) cid = (row('SELECT id FROM customers WHERE LOWER(name)=LOWER(?)', [name]) || {}).id || 0;
  const date = isDate(b.date) ? b.date : todayUtc(), paid = b.mode === 'paid';
  if (!paid && b.mode !== 'khata') throw new HttpError(400, 'Choose khata or paid.');
  if (paid && !(typeof b.pay === 'string' && Object.hasOwn(PAY, b.pay))) throw new HttpError(400, 'Choose cash, cheque or bank transaction.');
  const lines = [];
  for (const r of (Array.isArray(b.rows) ? b.rows.slice(0, 100) : [])) {
    if (!r || typeof r !== 'object') continue;
    const weight = num(r.kg), rate = num(r.rate);
    const amount = (r.amt !== undefined && r.amt !== null && r.amt !== '') ? num(r.amt) : weight * rate;
    if (amount || weight) lines.push({ detail: s(r.t, 150), weight, rate, amount });
  }
  if (!lines.length) throw new HttpError(400, 'Add at least one line with a weight or an amount.');
  const sql = 'INSERT INTO khata_entries (customer_id,entry_date,kind,detail,weight,rate,amount,paid,pay_method) VALUES (?,?,?,?,?,?,?,?,?)';
  let created = false;
  tx(() => {
    if (!cid) { cid = insert("INSERT INTO customers (name,phone,phone_key,city) VALUES (?, '', NULL, '')", [name]); created = true; }
    // a "paid" bill marks the same lines as paid (no separate payment line)
    for (const l of lines) run(sql, [cid, date, 'dilai', l.detail, l.weight, l.rate, l.amount, paid ? 1 : 0, paid ? PAY[b.pay] : '']);
  });
  return { ok: true, lines: lines.length, customer_id: cid, created };
}, ALL);
route('GET', '/api/khata/:cid', c => rows(`SELECT id,entry_date,kind,detail,weight,rate,amount,paid,pay_method FROM khata_entries
  WHERE customer_id=? ORDER BY entry_date,id`, [c.params.cid]), ALL);
route('POST', '/api/khata', c => {
  const b = c.body, cid = Number(b.customer_id) || 0;
  if (!row('SELECT 1 FROM customers WHERE id=?', [cid])) throw new HttpError(404, 'Party not found.');
  if (!KINDS.includes(b.kind)) throw new HttpError(400, 'Kind must be dilai, wasool or wapsi.');
  const date = isDate(b.date) ? b.date : todayUtc(), weight = num(b.weight), rate = num(b.rate);
  const amount = (b.amount !== undefined && b.amount !== null && b.amount !== '') ? num(b.amount) : weight * rate;
  if (!amount && !weight) throw new HttpError(400, 'Enter a weight or an amount.');
  return { id: insert('INSERT INTO khata_entries (customer_id,entry_date,kind,detail,weight,rate,amount) VALUES (?,?,?,?,?,?,?)',
    [cid, date, b.kind, s(b.detail, 200), weight, rate, amount]) };
}, ALL);
route('PATCH', '/api/khata/:id/paid', c => {
  const e = row('SELECT kind FROM khata_entries WHERE id=?', [c.params.id]);
  if (!e) throw new HttpError(404, 'Entry not found.');
  if (e.kind !== 'dilai') throw new HttpError(400, 'Only goods entries can be marked paid.');
  const paid = c.body.paid === true || c.body.paid === 1;
  if (paid && c.body.pay && !Object.hasOwn(PAY, c.body.pay)) throw new HttpError(400, 'Choose cash, cheque or bank transaction.');
  run('UPDATE khata_entries SET paid=?, pay_method=? WHERE id=?', [paid ? 1 : 0, paid && c.body.pay ? PAY[c.body.pay] : '', c.params.id]); return { ok: true };
}, ALL);
route('DELETE', '/api/khata/:id', c => { run('DELETE FROM khata_entries WHERE id=?', [c.params.id]); return { ok: true }; }, STAFF);

// ----- cheques -----
route('GET', '/api/cheques', () => rows('SELECT id,party,amount,issued_on,cash_on,status FROM cheques ORDER BY status DESC, cash_on'), ALL);
route('POST', '/api/cheques', c => {
  const b = c.body, party = s(b.party);
  if (!party) throw new HttpError(400, 'Party name is required.');
  if (!isNumeric(b.amount) || Number(b.amount) <= 0) throw new HttpError(400, 'Enter a valid amount.');
  if (!isDate(b.cash_on)) throw new HttpError(400, 'Cash date is required.');
  const issued = isDate(b.issued_on) ? b.issued_on : todayUtc();
  return { id: insert('INSERT INTO cheques (party,amount,issued_on,cash_on) VALUES (?,?,?,?)', [party, Number(b.amount), issued, b.cash_on]) };
}, ALL);
route('PATCH', '/api/cheques/:id/status', c => {
  if (!['pending', 'cleared'].includes(c.body.status)) throw new HttpError(400, 'Invalid status.');
  run('UPDATE cheques SET status=? WHERE id=?', [c.body.status, c.params.id]); return { ok: true };
}, ALL);
route('DELETE', '/api/cheques/:id', c => { run('DELETE FROM cheques WHERE id=?', [c.params.id]); return { ok: true }; }, STAFF);

// ----- gate pass -----
route('GET', '/api/gatepass', () => {
  const passes = rows('SELECT id,pass_date,party,product,qty,vehicle,total FROM gate_passes ORDER BY id DESC LIMIT 300');
  const items = rows(`SELECT pass_id,product,qty,rate,price FROM gate_pass_items
    WHERE pass_id IN (SELECT id FROM (SELECT id FROM gate_passes ORDER BY id DESC LIMIT 300)) ORDER BY id`);
  const by = {};
  for (const { pass_id, ...i } of items) (by[pass_id] ||= []).push(i);
  for (const p of passes) p.items = by[p.id] || [];
  return passes;
}, ALL);
route('POST', '/api/gatepass', c => {
  const b = c.body, party = s(b.party, 100);
  if (!party) throw new HttpError(400, 'Party name is required.');
  const raw = Array.isArray(b.items) ? b.items : [{ product: b.product, qty: b.qty, rate: b.rate, price: b.price }];
  const items = [];
  for (const i0 of raw.slice(0, 50)) {
    const i = i0 && typeof i0 === 'object' ? i0 : {};
    const product = s(i.product, 60), rate = numOrNull(i.rate) ?? 0;
    if (!product) throw new HttpError(400, 'Product is required.');
    if (!isNumeric(i.qty) || Number(i.qty) <= 0) throw new HttpError(400, 'Enter a valid quantity for ' + product + '.');
    const qty = Number(i.qty);
    const price = (i.price !== undefined && i.price !== null && i.price !== '' && numOrNull(i.price) !== null) ? numOrNull(i.price) : qty * rate;
    items.push({ product, qty, rate, price });
  }
  if (!items.length) throw new HttpError(400, 'Add at least one product.');
  const date = isDate(b.date) ? b.date : todayUtc();
  const id = tx(() => {
    const id = insert('INSERT INTO gate_passes (pass_date,party,product,qty,vehicle,total) VALUES (?,?,?,?,?,?)',
      [date, party, items.map(i => i.product).join('، '), sum(items, 'qty'), s(b.vehicle, 30), sum(items, 'price')]);
    for (const i of items) run('INSERT INTO gate_pass_items (pass_id,product,qty,rate,price) VALUES (?,?,?,?,?)', [id, i.product, i.qty, i.rate, i.price]);
    return id;
  });
  return { id };
}, ALL);
route('DELETE', '/api/gatepass/:id', c => {
  tx(() => { run('DELETE FROM gate_pass_items WHERE pass_id=?', [c.params.id]); run('DELETE FROM gate_passes WHERE id=?', [c.params.id]); });
  return { ok: true };
}, STAFF);

// ----- products -----
route('GET', '/api/products', () => rows('SELECT name FROM products ORDER BY id').map(p => p.name), ALL);
route('POST', '/api/products', c => {
  const name = s(c.body.name, 60);
  if (!name) throw new HttpError(400, 'Product name is required.');
  run('INSERT OR IGNORE INTO products (name) VALUES (?)', [name]); return { ok: true };
}, ALL);

// ----- reports -----
route('GET', '/api/reports', c => {
  const days = Math.max(0, Math.min(3650, parseInt(c.query.get('days'), 10) || 0));
  const since = days ? ymd(now() - (days - 1) * 86400000) : '0000-00-00';
  const today = todayUtc(), soon = ymd(now() + L.CHEQUE_SOON_DAYS * 86400000);
  const t = row(`SELECT COALESCE(SUM(CASE WHEN kind='dilai' THEN amount END),0) AS dilai_amt,
      COALESCE(SUM(CASE WHEN kind='dilai' THEN weight END),0) AS dilai_kg,
      COALESCE(SUM(CASE WHEN kind='wasool' OR (kind='dilai' AND paid=1) THEN amount END),0) AS wasool,
      COALESCE(SUM(CASE WHEN kind='wapsi' THEN amount END),0) AS wapsi
    FROM khata_entries WHERE entry_date >= ?`, [since]);
  const balance = Number(val("SELECT COALESCE(SUM(CASE WHEN kind='dilai' THEN (CASE WHEN paid=1 THEN 0 ELSE amount END) ELSE -amount END),0) FROM khata_entries"));
  const parties = rows(`SELECT c.name, SUM(k.amount) AS total FROM khata_entries k JOIN customers c ON c.id=k.customer_id
    WHERE k.kind='dilai' AND k.entry_date >= ? GROUP BY c.id ORDER BY total DESC LIMIT 6`, [since]);
  const daily = rows(`SELECT entry_date AS d, SUM(weight) AS kg FROM khata_entries
    WHERE kind='dilai' AND entry_date >= ? GROUP BY entry_date ORDER BY entry_date DESC LIMIT 14`, [since]).reverse();
  const ch = row(`SELECT COUNT(*) AS n, COALESCE(SUM(amount),0) AS amt,
      COALESCE(SUM(CASE WHEN cash_on <= ? THEN amount END),0) AS soon,
      COALESCE(SUM(CASE WHEN cash_on < ? THEN 1 END),0) AS overdue FROM cheques WHERE status='pending'`, [soon, today]);
  return { days, ...t, balance, parties, daily, cheques: { n: ch.n, amt: ch.amt, soon: ch.soon, overdue: ch.overdue } };
}, STAFF);

// ---------------- HTTP server ----------------
const HEADERS = {
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};
function sendJson(res, status, data) {
  res.writeHead(status, { ...HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', d => { n += d.length; if (n > 1e6) { reject(new HttpError(413, 'Request body is too large.')); req.destroy(); } else chunks.push(d); });
    req.on('end', () => {
      if (!n) return resolve({});
      try { const d = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(d && typeof d === 'object' && !Array.isArray(d) ? d : (() => { throw 0; })()); }
      catch (_) { reject(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', reject);
  });
}
function checkCsrf(req) {
  if (req.headers['x-requested-with'] !== 'threadbook') throw new HttpError(403, 'Request rejected.');
  const o = req.headers.origin;
  if (o) { let host = ''; try { host = new URL(o).host; } catch (_) {} if (host !== req.headers.host) throw new HttpError(403, 'Request rejected.'); }
}
async function handleApi(req, res, url) {
  try {
    bootstrapAdmin();
    for (const r of ROUTES) {
      if (r.method !== req.method) continue;
      const m = r.re.exec(url.pathname);
      if (!m) continue;
      if (req.method !== 'GET') checkCsrf(req);
      const user = getUser(req);
      if (!r.pub) {
        if (!user) throw new HttpError(401, 'Please log in first.');
        if (user.must_change && !r.allowMustChange) throw new HttpError(403, 'Please change your password first.', 'must_change');
        if (!r.roles.includes(user.role)) throw new HttpError(403, 'You do not have permission to do this.');
      }
      const params = {}; r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readBody(req) : {};
      return sendJson(res, 200, await r.handler({ params, query: url.searchParams, body, user, req, res }));
    }
    throw new HttpError(404, 'This API does not exist.');
  } catch (e) {
    if (e instanceof HttpError) return sendJson(res, e.status, { error: e.message, code: e.code });
    if (/UNIQUE constraint/i.test(e.message || '')) return sendJson(res, 409, { error: 'This record already exists.' });
    console.error('ZECO CRM error:', e);
    sendJson(res, 500, { error: 'Something went wrong on the server. Check the server console.' });
  }
}
const TYPES = { '.html': 'text/html; charset=utf-8', '.jpg': 'image/jpeg', '.png': 'image/png', '.ico': 'image/x-icon', '.svg': 'image/svg+xml', '.css': 'text/css', '.js': 'text/javascript' };
function serveStatic(req, res, url) {
  let p = url.pathname === '/' ? '/index.html' : url.pathname;
  const file = path.normalize(path.join(PUBLIC, decodeURIComponent(p)));
  if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found');
  }
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, { ...HEADERS, 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
  fs.createReadStream(file).pipe(res);
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) return handleApi(req, res, url);
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  serveStatic(req, res, url);
}).listen(PORT, HOST, () => {
  bootstrapAdmin();
  console.log(`\nZECO Factory CRM is running:  http://localhost:${PORT}\nPress Ctrl + C to stop.\n`);
});
