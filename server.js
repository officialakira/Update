// ============================================================
//  ROBLOX KEY SYSTEM — Backend Service
//  Endpoints:
//    POST /api/getkey          -> generate a key (HWID bound, 24h)
//    GET  /api/validate        -> ?key=XXX&hwid=YYY  (used by Roblox script)
//    GET  /api/stats           -> public stats
//    Admin (require x-admin-password header):
//    GET  /api/admin/keys      -> list all keys
//    POST /api/admin/create    -> create custom/permanent key
//    POST /api/admin/revoke    -> revoke a key
//    POST /api/admin/reset-hwid-> unbind HWID from a key
// ============================================================

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------- CONFIG (edit these) -------------------
const CONFIG = {
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || "hexscriptofficial111", // CHANGE THIS!
  KEY_LIFETIME_HOURS: 24,       // how long free keys last
  KEY_PREFIX: "HEX",            // HexScript key prefix
  MAX_KEYS_PER_HWID: 1,         // active keys allowed per device
  CHECKPOINTS_REQUIRED: 2,      // "ad checkpoint" steps on the website
};
// ------------------------------------------------------------

const DB_FILE = path.join(__dirname, "keys.json");

// ----- tiny JSON "database" -----
let db = { keys: {}, sessions: {}, stats: { generated: 0, validations: 0 } };
function loadDB() {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); } catch (e) { saveDB(); }
}
function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
loadDB();
setInterval(saveDB, 15000); // periodic flush

// ----- helpers -----
function makeKey() {
  const raw = crypto.randomBytes(12).toString("hex").toUpperCase();
  return `${CONFIG.KEY_PREFIX}-${raw.slice(0, 8)}-${raw.slice(8, 16)}-${raw.slice(16, 24)}`;
}

function now() { return Date.now(); }

function cleanExpired() {
  for (const [k, v] of Object.entries(db.keys)) {
    if (v.expiresAt !== null && v.expiresAt < now() && !v.permanent) {
      delete db.keys[k];
    }
  }
  for (const [s, v] of Object.entries(db.sessions)) {
    if (v.createdAt + 30 * 60 * 1000 < now()) delete db.sessions[s];
  }
}
setInterval(cleanExpired, 60 * 1000);

function getIP(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0].trim();
}

// simple rate limiter: max N requests per window per IP
const hits = new Map();
function rateLimit(maxReq, windowMs) {
  return (req, res, next) => {
    const key = getIP(req) + "|" + req.path;
    const entry = hits.get(key) || { count: 0, start: now() };
    if (now() - entry.start > windowMs) { entry.count = 0; entry.start = now(); }
    entry.count++;
    hits.set(key, entry);
    if (entry.count > maxReq) {
      return res.status(429).json({ success: false, message: "Rate limited. Slow down." });
    }
    next();
  };
}

function requireAdmin(req, res, next) {
  const pw = req.headers["x-admin-password"] || req.query.password;
  if (pw !== CONFIG.ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ============================================================
//  CHECKPOINT FLOW (simulates Linkvertise/ad checkpoints)
//  The website calls /api/checkpoint to advance a session,
//  then /api/getkey when all checkpoints are done.
// ============================================================

app.post("/api/session", rateLimit(20, 60000), (req, res) => {
  const sessionId = crypto.randomBytes(16).toString("hex");
  db.sessions[sessionId] = { checkpoint: 0, createdAt: now(), ip: getIP(req) };
  res.json({ success: true, sessionId, checkpointsRequired: CONFIG.CHECKPOINTS_REQUIRED });
});

app.post("/api/checkpoint", rateLimit(30, 60000), (req, res) => {
  const { sessionId } = req.body || {};
  const s = db.sessions[sessionId];
  if (!s) return res.status(400).json({ success: false, message: "Invalid session. Refresh the page." });
  // anti-bypass: minimum 3 seconds between checkpoints
  if (s.lastCheckpointAt && now() - s.lastCheckpointAt < 3000) {
    return res.status(400).json({ success: false, message: "Too fast — complete the checkpoint properly." });
  }
  s.checkpoint = Math.min(s.checkpoint + 1, CONFIG.CHECKPOINTS_REQUIRED);
  s.lastCheckpointAt = now();
  res.json({ success: true, checkpoint: s.checkpoint, done: s.checkpoint >= CONFIG.CHECKPOINTS_REQUIRED });
});

// ============================================================
//  KEY GENERATION
// ============================================================
app.post("/api/getkey", rateLimit(10, 60000), (req, res) => {
  const { sessionId, hwid } = req.body || {};
  const s = db.sessions[sessionId];

  if (!s) return res.status(400).json({ success: false, message: "Invalid session. Refresh the page." });
  if (s.checkpoint < CONFIG.CHECKPOINTS_REQUIRED) {
    return res.status(400).json({ success: false, message: "Complete all checkpoints first." });
  }

  const boundHwid = (hwid && String(hwid).slice(0, 128)) || null;

  // If this HWID already has an active key, return it instead of making a new one
  if (boundHwid) {
    const existing = Object.entries(db.keys).find(
      ([, v]) => v.hwid === boundHwid && (v.permanent || v.expiresAt > now()) && !v.revoked
    );
    if (existing) {
      return res.json({
        success: true,
        key: existing[0],
        expiresAt: existing[1].expiresAt,
        message: "You already have an active key.",
      });
    }
  }

  const key = makeKey();
  const expiresAt = now() + CONFIG.KEY_LIFETIME_HOURS * 3600 * 1000;
  db.keys[key] = {
    createdAt: now(),
    expiresAt,
    hwid: boundHwid,        // null until first validation if not provided
    ip: getIP(req),
    permanent: false,
    revoked: false,
    uses: 0,
  };
  db.stats.generated++;
  delete db.sessions[sessionId]; // one key per session
  saveDB();

  res.json({ success: true, key, expiresAt, lifetimeHours: CONFIG.KEY_LIFETIME_HOURS });
});

// ============================================================
//  KEY VALIDATION  (called by the Roblox script)
// ============================================================
app.get("/api/validate", rateLimit(60, 60000), (req, res) => {
  const key = String(req.query.key || "").trim();
  const hwid = String(req.query.hwid || "").trim().slice(0, 128);

  db.stats.validations++;
  const entry = db.keys[key];

  if (!entry) return res.json({ valid: false, message: "Invalid key." });
  if (entry.revoked) return res.json({ valid: false, message: "Key has been revoked." });
  if (!entry.permanent && entry.expiresAt < now()) {
    delete db.keys[key];
    return res.json({ valid: false, message: "Key expired. Get a new one." });
  }

  // HWID lock: bind on first use, enforce afterwards
  if (hwid) {
    if (!entry.hwid) {
      entry.hwid = hwid;
    } else if (entry.hwid !== hwid) {
      return res.json({ valid: false, message: "Key is locked to another device (HWID mismatch)." });
    }
  }

  entry.uses++;
  entry.lastUsedAt = now();
  res.json({
    valid: true,
    message: "Key is valid!",
    permanent: entry.permanent,
    expiresAt: entry.permanent ? null : entry.expiresAt,
    timeLeftSeconds: entry.permanent ? null : Math.floor((entry.expiresAt - now()) / 1000),
  });
});

// ============================================================
//  PUBLIC STATS
// ============================================================
app.get("/api/stats", (req, res) => {
  cleanExpired();
  res.json({
    activeKeys: Object.keys(db.keys).length,
    totalGenerated: db.stats.generated,
    totalValidations: db.stats.validations,
    keyLifetimeHours: CONFIG.KEY_LIFETIME_HOURS,
  });
});

// ============================================================
//  ADMIN API
// ============================================================
app.get("/api/admin/keys", requireAdmin, (req, res) => {
  cleanExpired();
  const list = Object.entries(db.keys).map(([key, v]) => ({
    key,
    hwid: v.hwid,
    ip: v.ip,
    permanent: v.permanent,
    revoked: v.revoked,
    uses: v.uses,
    createdAt: v.createdAt,
    expiresAt: v.expiresAt,
    lastUsedAt: v.lastUsedAt || null,
  }));
  list.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ success: true, keys: list, stats: db.stats });
});

app.post("/api/admin/create", requireAdmin, (req, res) => {
  const { permanent, hours, customKey, note } = req.body || {};
  const key = customKey ? String(customKey).trim().toUpperCase() : makeKey();
  if (db.keys[key]) return res.status(400).json({ success: false, message: "Key already exists." });
  db.keys[key] = {
    createdAt: now(),
    expiresAt: permanent ? null : now() + (Number(hours) || CONFIG.KEY_LIFETIME_HOURS) * 3600 * 1000,
    hwid: null,
    ip: "admin",
    permanent: !!permanent,
    revoked: false,
    uses: 0,
    note: note || null,
  };
  db.stats.generated++;
  saveDB();
  res.json({ success: true, key });
});

app.post("/api/admin/revoke", requireAdmin, (req, res) => {
  const { key } = req.body || {};
  if (!db.keys[key]) return res.status(404).json({ success: false, message: "Key not found." });
  db.keys[key].revoked = true;
  saveDB();
  res.json({ success: true });
});

app.post("/api/admin/delete", requireAdmin, (req, res) => {
  const { key } = req.body || {};
  if (!db.keys[key]) return res.status(404).json({ success: false, message: "Key not found." });
  delete db.keys[key];
  saveDB();
  res.json({ success: true });
});

app.post("/api/admin/reset-hwid", requireAdmin, (req, res) => {
  const { key } = req.body || {};
  if (!db.keys[key]) return res.status(404).json({ success: false, message: "Key not found." });
  db.keys[key].hwid = null;
  saveDB();
  res.json({ success: true });
});

// ============================================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Key system running on http://0.0.0.0:${PORT}`);
  console.log(`Admin password: ${CONFIG.ADMIN_PASSWORD} (set ADMIN_PASSWORD env var to change)`);
});
