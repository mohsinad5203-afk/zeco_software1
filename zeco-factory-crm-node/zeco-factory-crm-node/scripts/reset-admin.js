// If you forget the super admin password:   node scripts/reset-admin.js
// Other username:                           node scripts/reset-admin.js myname
const L = require('../lib');
const username = process.argv[2] || 'superadmin';
const pw = L.randomPassword(), hash = L.hashPw(pw);
const u = L.row('SELECT id FROM users WHERE username=?', [username]);
if (u) {
  L.run("UPDATE users SET password_hash=?, must_change=1, active=1, role='super_admin' WHERE id=?", [hash, u.id]);
  L.run('DELETE FROM sessions WHERE user_id=?', [u.id]);
} else {
  L.run("INSERT INTO users (username,name,role,password_hash,must_change) VALUES (?,?,'super_admin',?,1)", [username, 'Super Admin', hash]);
}
console.log(`\nNew password for super admin "${username}": ${pw}\nYou must change it after logging in.\n`);
