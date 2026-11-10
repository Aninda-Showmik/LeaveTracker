const { DatabaseSync } = require("node:sqlite");
const db = new DatabaseSync("leave.db");
console.log("Users:");
console.table(db.prepare("SELECT id, emp_id, name, created FROM users").all());
console.log("Entries:");
console.table(db.prepare("SELECT id, user_id, type, date, days, note FROM entries ORDER BY id DESC").all());