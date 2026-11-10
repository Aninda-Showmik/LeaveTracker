const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto"), os = require("os");
const { DatabaseSync } = require("node:sqlite");
const PORT = process.env.PORT || 3000;
const CODE = process.env.REGISTER_CODE || ""; // optional invite code required to create accounts
const db = new DatabaseSync(process.env.DB_FILE || path.join(__dirname, "leave.db"));
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, emp_id TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
  salt TEXT NOT NULL, hash TEXT NOT NULL,
  earned REAL DEFAULT 0, sick REAL DEFAULT 14, casual REAL DEFAULT 10, late_limit INTEGER DEFAULT 3, early_limit INTEGER DEFAULT 3,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL, date TEXT NOT NULL, days REAL NOT NULL DEFAULT 1, note TEXT DEFAULT '',
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id, date);
CREATE TABLE IF NOT EXISTS year_settings(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, year INTEGER NOT NULL,
  earned REAL DEFAULT 0, sick REAL DEFAULT 14, casual REAL DEFAULT 10, late_limit INTEGER DEFAULT 0, early_limit INTEGER DEFAULT 0,
  PRIMARY KEY(user_id, year));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL);
`);
const TYPES = new Set(["sick", "casual", "earned", "late", "early"]);
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");
const send = (res, code, obj, headers = {}) => { res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise((ok, no) => { let b = ""; req.on("data", c => { b += c; if (b.length > 100000) { req.destroy(); no(new Error("too large")); } }); req.on("end", () => { try { ok(b ? JSON.parse(b) : {}); } catch (e) { no(e); } }); });
const cookie = req => Object.fromEntries((req.headers.cookie || "").split(";").map(s => s.trim().split("=")).filter(a => a[0]));
const attempts = new Map();
const limited = ip => { const n = Date.now(), a = attempts.get(ip) || { c: 0, t: n + 600000 }; if (n > a.t) { a.c = 0; a.t = n + 600000; } attempts.set(ip, a); return a.c >= 10; };
const fail = ip => { const a = attempts.get(ip); if (a) a.c++; };
const SESSION_MS = 30 * 864e5;
function startSession(res, userId, body, code = 200) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(sha(token), userId, Date.now());
  send(res, code, body, { "Set-Cookie": `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}` });
}
function sessionUser(req) {
  const t = cookie(req).sid; if (!t) return null;
  const s = db.prepare("SELECT user_id, created FROM sessions WHERE token_hash=?").get(sha(t));
  if (!s || Date.now() - s.created > SESSION_MS) return null;
  return db.prepare("SELECT * FROM users WHERE id=?").get(s.user_id);
}
const pub = u => ({ empId: u.emp_id, name: u.name, earned: u.earned, sick: u.sick, casual: u.casual, late: u.late_limit, early: u.early_limit });
const num = (v, d = 0, min = 0, max = 366) => { v = Number(v); return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : d; };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x"), p = url.pathname, ip = req.socket.remoteAddress;
  try {
    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(fs.readFileSync(path.join(__dirname, "public", "index.html")));
    }
    if (!p.startsWith("/api/")) return send(res, 404, { error: "Not found" });
    if (p === "/api/info") return send(res, 200, { codeRequired: !!CODE });

    if (p === "/api/register" && req.method === "POST") {
      const b = await readBody(req);
      const empId = String(b.empId || "").trim(), name = String(b.name || "").trim(), pw = String(b.password || "");
      if (CODE && b.code !== CODE) return send(res, 403, { error: "Invalid invite code." });
      if (!empId || !name) return send(res, 400, { error: "Enter employee ID and name." });
      if (empId.length > 40 || name.length > 80) return send(res, 400, { error: "Employee ID or name is too long." });
      if (pw.length < 6) return send(res, 400, { error: "Password must be at least 6 characters." });
      if (db.prepare("SELECT 1 FROM users WHERE emp_id=?").get(empId)) return send(res, 409, { error: "This employee ID is already registered." });
      const salt = crypto.randomBytes(16).toString("hex");
      const r = db.prepare("INSERT INTO users(emp_id,name,salt,hash,earned,sick,casual,late_limit,early_limit) VALUES(?,?,?,?,?,?,?,?,?)")
        .run(empId, name, salt, hashPw(pw, salt), num(b.earned), num(b.sick, 14), num(b.casual, 10), num(b.late, 3, 0, 31), num(b.early, 3, 0, 31));
      return startSession(res, Number(r.lastInsertRowid), pub(db.prepare("SELECT * FROM users WHERE id=?").get(Number(r.lastInsertRowid))), 201);
    }
    if (p === "/api/login" && req.method === "POST") {
      if (limited(ip)) return send(res, 429, { error: "Too many attempts. Try again in a few minutes." });
      const b = await readBody(req);
      const u = db.prepare("SELECT * FROM users WHERE emp_id=?").get(String(b.empId || "").trim());
      const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(String(b.password || ""), u.salt), "hex"), Buffer.from(u.hash, "hex"));
      if (!ok) { fail(ip); return send(res, 401, { error: "Wrong employee ID or password." }); }
      return startSession(res, u.id, pub(u));
    }
    const u = sessionUser(req);
    if (p === "/api/logout" && req.method === "POST") {
      const t = cookie(req).sid; if (t) db.prepare("DELETE FROM sessions WHERE token_hash=?").run(sha(t));
      return send(res, 200, { ok: true }, { "Set-Cookie": "sid=; HttpOnly; Path=/; Max-Age=0" });
    }
    if (!u) return send(res, 401, { error: "Not signed in." });

    if (p === "/api/me" && req.method === "GET") return send(res, 200, pub(u));
    if (p === "/api/me" && req.method === "PUT") {
      const b = await readBody(req);
      db.prepare("UPDATE users SET name=?, earned=?, sick=?, casual=?, late_limit=?, early_limit=? WHERE id=?")
        .run(String(b.name || u.name).trim().slice(0, 80) || u.name, num(b.earned), num(b.sick), num(b.casual), num(b.late, 3, 0, 31), num(b.early, 3, 0, 31), u.id);
      return send(res, 200, pub(db.prepare("SELECT * FROM users WHERE id=?").get(u.id)));
    }
    if (p === "/api/password" && req.method === "POST") {
      const b = await readBody(req);
      if (!crypto.timingSafeEqual(Buffer.from(hashPw(String(b.current || ""), u.salt), "hex"), Buffer.from(u.hash, "hex"))) return send(res, 401, { error: "Current password is wrong." });
      if (String(b.next || "").length < 6) return send(res, 400, { error: "New password must be at least 6 characters." });
      const salt = crypto.randomBytes(16).toString("hex");
      db.prepare("UPDATE users SET salt=?, hash=? WHERE id=?").run(salt, hashPw(String(b.next), salt), u.id);
      db.prepare("DELETE FROM sessions WHERE user_id=?").run(u.id);
      return startSession(res, u.id, { ok: true });
    }
    let ym = p.match(/^\/api\/year\/(\d{4})$/);
    if (ym && req.method === "GET") {
      const r = db.prepare("SELECT earned,sick,casual,late_limit,early_limit FROM year_settings WHERE user_id=? AND year=?").get(u.id, Number(ym[1]));
      return send(res, 200, r ? { saved: true, earned: r.earned, sick: r.sick, casual: r.casual, late: r.late_limit, early: r.early_limit } : { saved: false, earned: 0, sick: 14, casual: 10, late: 0, early: 0 });
    }
    if (ym && req.method === "PUT") {
      const b = await readBody(req);
      db.prepare("INSERT INTO year_settings(user_id,year,earned,sick,casual,late_limit,early_limit) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,year) DO UPDATE SET earned=excluded.earned, sick=excluded.sick, casual=excluded.casual, late_limit=excluded.late_limit, early_limit=excluded.early_limit")
        .run(u.id, Number(ym[1]), num(b.earned), num(b.sick), num(b.casual), num(b.late, 0, 0, 31), num(b.early, 0, 0, 31));
      return send(res, 200, { ok: true });
    }
    if (p === "/api/entries/bulk" && req.method === "POST") {
      const b = await readBody(req), dates = [...new Set(Array.isArray(b.dates) ? b.dates : [])].slice(0, 120);
      if (!TYPES.has(b.type) || !dates.length || dates.some(d => !/^\d{4}-\d{2}-\d{2}$/.test(d))) return send(res, 400, { error: "Pick a type and at least one date." });
      const days = ["late", "early"].includes(b.type) ? 1 : (Number(b.days) === 0.5 ? 0.5 : 1), note = String(b.note || "").slice(0, 300);
      const ins = db.prepare("INSERT INTO entries(user_id,type,date,days,note) VALUES(?,?,?,?,?)");
      db.exec("BEGIN"); try { for (const d of dates) ins.run(u.id, b.type, d, days, note); db.exec("COMMIT"); } catch (e) { db.exec("ROLLBACK"); throw e; }
      return send(res, 201, { added: dates.length });
    }
    if (p === "/api/entries" && req.method === "GET")
      return send(res, 200, db.prepare("SELECT id,type,date,days,note FROM entries WHERE user_id=? ORDER BY date DESC, id DESC").all(u.id));
    if (p === "/api/entries" && req.method === "POST") {
      const b = await readBody(req);
      if (!TYPES.has(b.type) || !/^\d{4}-\d{2}-\d{2}$/.test(b.date || "")) return send(res, 400, { error: "Invalid type or date." });
      const days = ["late", "early"].includes(b.type) ? 1 : num(b.days, 1, 0.5, 60);
      const r = db.prepare("INSERT INTO entries(user_id,type,date,days,note) VALUES(?,?,?,?,?)").run(u.id, b.type, b.date, days, String(b.note || "").slice(0, 300));
      return send(res, 201, { id: Number(r.lastInsertRowid) });
    }
    const m = p.match(/^\/api\/entries\/(\d+)$/);
    if (m && req.method === "DELETE") {
      db.prepare("DELETE FROM entries WHERE id=? AND user_id=?").run(Number(m[1]), u.id);
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: "Not found" });
  } catch (e) { send(res, 400, { error: "Bad request." }); }
});
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Leave Records running. Open on this computer: http://localhost:${PORT}`);
  for (const l of Object.values(os.networkInterfaces()).flat()) if (l && l.family === "IPv4" && !l.internal) console.log(`Colleagues on the same network open: http://${l.address}:${PORT}`);
  if (CODE) console.log("Invite code is required to create accounts.");
});
