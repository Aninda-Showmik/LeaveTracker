// Usage: node reset-password.js EMPLOYEE_ID NEW_PASSWORD
const { DatabaseSync } = require("node:sqlite"), crypto = require("crypto"), path = require("path");
const [id, pw] = process.argv.slice(2);
if (!id || !pw || pw.length < 6) { console.log("Usage: node reset-password.js EMPLOYEE_ID NEW_PASSWORD (6+ characters)"); process.exit(1); }
const db = new DatabaseSync(path.join(__dirname, "leave.db"));
const u = db.prepare("SELECT id FROM users WHERE emp_id=?").get(id);
if (!u) { console.log("No such employee ID."); process.exit(1); }
const salt = crypto.randomBytes(16).toString("hex");
db.prepare("UPDATE users SET salt=?, hash=? WHERE id=?").run(salt, crypto.scryptSync(pw, salt, 64).toString("hex"), u.id);
db.prepare("DELETE FROM sessions WHERE user_id=?").run(u.id);
console.log("Password reset for " + id + ". Ask them to change it after logging in.");
