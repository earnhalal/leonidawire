/* Leonida Wire API shared helpers (Vercel serverless).
   Talks to Firebase over REST, signed in as a dedicated Auth user
   (the "API user"). Env vars: WL_API_KEY (project web API key),
   WL_API_EMAIL, WL_API_PASSWORD. Database rules grant access to that
   user's uid only — no service-account key is used anywhere. */
const crypto = require("crypto");

const DB_URL = "https://leonidawire-default-rtdb.asia-southeast1.firebasedatabase.app";

let cachedToken = null;
let tokenExpiry = 0;

async function signIn() {
  if (cachedToken && Date.now() < tokenExpiry - 60_000) return cachedToken;
  const key = process.env.WL_API_KEY;
  const email = process.env.WL_API_EMAIL;
  const password = process.env.WL_API_PASSWORD;
  if (!key || !email || !password) throw new Error("API user env vars are not set");
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + key, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, returnSecureToken: true }),
  });
  if (!r.ok) throw new Error("API user sign-in failed");
  const j = await r.json();
  cachedToken = j.idToken;
  tokenExpiry = Date.now() + Number(j.expiresIn || 3600) * 1000;
  return cachedToken;
}

async function dbCall(method, path, body, retry = true) {
  const token = await signIn();
  const r = await fetch(DB_URL + "/" + path + ".json?auth=" + token, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401 && retry) {
    cachedToken = null;
    return dbCall(method, path, body, false);
  }
  if (!r.ok) throw new Error("db " + method + " " + path + " -> " + r.status);
  return r.status === 200 ? r.json().catch(() => null) : null;
}
const dbGet = (path) => dbCall("GET", path);
const dbSet = (path, value) => dbCall("PUT", path, value);
const dbUpdate = (path, value) => dbCall("PATCH", path, value);
const dbRemove = (path) => dbCall("DELETE", path);

function hashSecret(secret, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(secret), salt, 64, (err, key) => (err ? reject(err) : resolve(key.toString("hex"))));
  });
}
function newSalt() { return crypto.randomBytes(16).toString("hex"); }
async function verifySecret(secret, salt, expectedHex) {
  const got = await hashSecret(secret, salt);
  const a = Buffer.from(got, "hex");
  const b = Buffer.from(expectedHex, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 200_000) { reject(new Error("too large")); req.destroy(); } });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}
function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(obj));
}
function clientIp(req) {
  const fwd = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return fwd || req.socket?.remoteAddress || "unknown";
}
function ipKey(ip) { return crypto.createHash("sha256").update(ip).digest("hex").slice(0, 24); }

async function rateLimited(ip, action, max = 300, windowMs = 10 * 60 * 1000) {
  const key = ipKey(ip) + "_" + String(action).replace(/[^a-zA-Z0-9-]/g, "");
  const rec0 = (await dbGet("_rl/" + key)) || { count: 0, since: Date.now() };
  const now = Date.now();
  const rec = now - rec0.since > windowMs ? { count: 0, since: now } : rec0;
  return { limited: rec.count >= max, key, rec, now };
}
async function recordFailure(key, rec, now) {
  await dbSet("_rl/" + key, { count: (rec.count || 0) + 1, since: rec.since || now });
}

module.exports = {
  dbGet, dbSet, dbUpdate, dbRemove,
  hashSecret, newSalt, verifySecret, readBody, send, clientIp,
  rateLimited, recordFailure,
};
