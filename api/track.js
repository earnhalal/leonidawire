/* Leonida Wire analytics — the site's own live counting (no waiting
   for Google Search Console). Same pattern as WishLink's stats.
   POST /api/track {device, page, ref, type:"visit"|"ping"}
     visit — one page view: daily + total counters, per-post views,
             country / device / source breakdowns, hourly buckets.
     ping  — heartbeat every 30s from an open page; powers "Live now".
   POST /api/track {type:"setpin", pin} — one-time stats PIN setup.
   POST /api/track {type:"stats", pin} — dashboard payload.
   Data (RTDB):
     stats_days/<YYYY-MM-DD> = {visits, uniques, pages:{<slug>:n},
       countries:{}, devtypes:{}, oses:{}, browsers:{}, sources:{}}
     stats_total = same shape (all time)
     stats_hours/<day>/<HH> = n
     stats_devices/<device> = {first, last, days:{<day>:1}, cc, dtype, os, browser}
     stats_live/<device> = last heartbeat ts
     stats_visitors/<device> = {ip, cc, city, dtype, os, browser, first, last,
       visits, sessions, pv:{<page>:views},
       sess:[{t, pages:{<page>:{s:secs, sc:scrollMax}}}] (newest first, max 8;
       a new session starts after 30 min of inactivity)}
     stats_bots/<bot name> = {name, n, last, cc, city, ip} — crawlers and AI
       agents are counted SEPARATELY (day/total "bots" maps + this
       last-seen index), never inside the human numbers. They arrive via
       the JS tracker (bots that render pages) and via POST {type:"botlog"}
       from the edge middleware (bots that only fetch HTML).
     stats_admin = {salt, hash} (stats PIN, scrypt)
   Days follow Asia/Karachi (PKT = UTC+5). */
const {
  dbGet, dbSet, dbRemove, readBody, send, clientIp,
  rateLimited, recordFailure, hashSecret, newSalt, verifySecret,
} = require("./_lib");

const DEV_RE = /^[a-zA-Z0-9-]{8,40}$/;
const PAGE_RE = /^[a-z0-9-]{1,40}$/;
const LIVE_WINDOW = 90 * 1000;
const SESSION_GAP = 30 * 60 * 1000;
const MAX_SESS = 8;

function blankVisitor() {
  return { ip: "", cc: "??", city: "", dtype: "", os: "", browser: "", first: 0, last: 0, visits: 0, sessions: 0, pv: {}, sess: [] };
}
/* Returns the visitor's current session record, starting (and counting)
   a new one when the last activity is older than SESSION_GAP. */
function ensureSession(v, now) {
  if (!Array.isArray(v.sess)) v.sess = [];
  if (!v.sess.length || !v.last || now - v.last > SESSION_GAP) {
    v.sess.unshift({ t: now, pages: {} });
    v.sessions = (v.sessions || 0) + 1;
    if (v.sess.length > MAX_SESS) v.sess.length = MAX_SESS;
  }
  if (!v.sess[0].pages) v.sess[0].pages = {};
  return v.sess[0];
}

function pktDay(ts) {
  return new Date(ts + 5 * 3600 * 1000).toISOString().slice(0, 10);
}
function visitCountry(req) {
  const cc = String((req.headers && req.headers["x-vercel-ip-country"]) || "").toUpperCase();
  return /^[A-Z]{2}$/.test(cc) ? cc : "??";
}
/* Vercel also sends the visitor's city (URL-encoded, ISP-based, so it
   is an approximation — sometimes the nearest big city, sometimes
   empty). Sanitized before it is stored or shown. */
function cleanCity(raw) {
  let s = String(raw || "");
  try { s = decodeURIComponent(s); } catch (e) { /* keep raw */ }
  s = s.replace(/[<>\u0000-\u001f]/g, "").trim().slice(0, 60);
  return s;
}
function visitCity(req) {
  return cleanCity(req.headers && req.headers["x-vercel-ip-city"]);
}
function visitDevice(req) {
  const ua = String((req.headers && req.headers["user-agent"]) || "");
  let type = "Desktop";
  if (/iPad|Tablet|PlayBook|Silk/i.test(ua) || (/Android/i.test(ua) && !/Mobile/i.test(ua))) type = "Tablet";
  else if (/Mobi|Android|iPhone|iPod|Windows Phone/i.test(ua)) type = "Mobile";
  let os = "Other";
  if (/Android/i.test(ua)) os = "Android";
  else if (/iPhone|iPad|iPod/i.test(ua)) os = "iOS";
  else if (/Windows/i.test(ua)) os = "Windows";
  else if (/Mac OS|Macintosh/i.test(ua)) os = "Mac";
  else if (/Linux/i.test(ua)) os = "Linux";
  let browser = "Other";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/SamsungBrowser/i.test(ua)) browser = "Samsung";
  else if (/OPR\/|Opera/i.test(ua)) browser = "Opera";
  else if (/Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Chrome\//i.test(ua)) browser = "Chrome";
  else if (/Safari\//i.test(ua)) browser = "Safari";
  return { type, os, browser };
}
function visitSource(ref) {
  const r = String(ref || "").toLowerCase();
  if (!r) return "Direct";
  if (r.includes("leonidawire.pp.ua")) return "Direct";
  if (r.includes("whatsapp") || r.includes("wa.me")) return "WhatsApp";
  if (r.includes("facebook") || r.includes("fb.")) return "Facebook";
  if (r.includes("instagram")) return "Instagram";
  if (r.includes("tiktok")) return "TikTok";
  if (r.includes("t.me") || r.includes("telegram")) return "Telegram";
  if (r.includes("youtube") || r.includes("youtu.be")) return "YouTube";
  if (r.includes("google")) return "Google";
  return "Other";
}
function bumpMap(map, key) {
  const m = Object.assign({}, map || {});
  m[key] = (m[key] || 0) + 1;
  return m;
}
function blankRec() {
  return { visits: 0, uniques: 0, pages: {}, countries: {}, devtypes: {}, oses: {}, browsers: {}, sources: {}, bots: {} };
}
/* Known crawlers / AI agents by user-agent. Returns a display name or
   null for what looks like a human browser. Display names avoid the
   characters Firebase keys forbid (. $ # [ ] /). */
function botName(ua) {
  const u = String(ua || "");
  if (!u) return null;
  const rules = [
    [/GPTBot/i, "GPTBot (OpenAI)"],
    [/OAI-SearchBot/i, "OpenAI SearchBot"],
    [/ChatGPT-User/i, "ChatGPT user agent"],
    [/ClaudeBot/i, "ClaudeBot (Anthropic)"],
    [/Claude-Web|anthropic-ai/i, "Claude (Anthropic)"],
    [/PerplexityBot/i, "PerplexityBot"],
    [/Perplexity-User/i, "Perplexity user agent"],
    [/CCBot/i, "CCBot (Common Crawl)"],
    [/Google-Extended/i, "Google-Extended (AI)"],
    [/Googlebot/i, "Googlebot"],
    [/Bingbot/i, "Bingbot"],
    [/Applebot-Extended/i, "Applebot (AI)"],
    [/Applebot/i, "Applebot"],
    [/Meta-ExternalAgent/i, "Meta AI agent"],
    [/facebookexternalhit/i, "Facebook crawler"],
    [/Twitterbot/i, "Twitterbot"],
    [/LinkedInBot/i, "LinkedInBot"],
    [/DuckDuckBot/i, "DuckDuckBot"],
    [/YandexBot/i, "YandexBot"],
    [/Baiduspider/i, "Baiduspider"],
    [/Bytespider/i, "Bytespider (TikTok)"],
    [/Amazonbot/i, "Amazonbot"],
    [/cohere-ai/i, "Cohere AI"],
    [/Diffbot/i, "Diffbot"],
    [/ImagesiftBot/i, "ImagesiftBot"],
    [/PetalBot/i, "PetalBot"],
    [/SemrushBot/i, "SemrushBot"],
    [/AhrefsBot/i, "AhrefsBot"],
    [/MJ12bot/i, "MJ12bot"],
    [/DotBot/i, "DotBot"],
    [/DataForSeoBot/i, "DataForSEO Bot"],
    [/ia_archiver|archive\.org_bot/i, "Internet Archive"],
    [/MistralAI/i, "Mistral AI"],
    [/YouBot/i, "YouBot"],
    [/HeadlessChrome/i, "Headless Chrome"],
    [/python-requests|python-urllib|Go-http-client|axios|node-fetch|okhttp|curl\/|wget/i, "Script tool"],
  ];
  for (const rule of rules) if (rule[0].test(u)) return rule[1];
  if (/bot|crawl|spider|slurp|fetcher|scraper/i.test(u)) return "Other bot";
  return null;
}
/* Count one bot visit: day + total "bots" maps and the last-seen index.
   Human counters (visits/uniques/pages/...) are NOT touched. */
async function recordBot(name, cc, ip, city) {
  const now = Date.now();
  const day = pktDay(now);
  const dayRec = Object.assign(blankRec(), (await dbGet("stats_days/" + day)) || {});
  dayRec.bots = bumpMap(dayRec.bots, name);
  await dbSet("stats_days/" + day, dayRec);
  const total = Object.assign(blankRec(), (await dbGet("stats_total")) || {});
  total.bots = bumpMap(total.bots, name);
  await dbSet("stats_total", total);
  const prev = (await dbGet("stats_bots/" + name)) || {};
  await dbSet("stats_bots/" + name, {
    name, n: (prev.n || 0) + 1, last: now,
    cc: cc || prev.cc || "??", ip: ip || prev.ip || "", city: city || prev.city || "",
  });
}
function outRec(rec, date) {
  const r = Object.assign(blankRec(), rec || {});
  if (date) r.date = date;
  return r;
}

async function buildStats() {
  const now = Date.now();
  const today = pktDay(now);
  const yesterday = pktDay(now - 86400000);
  const days = (await dbGet("stats_days")) || {};
  const total = (await dbGet("stats_total")) || blankRec();
  const liveMap = (await dbGet("stats_live")) || {};
  let live = 0;
  const stale = [];
  for (const dev of Object.keys(liveMap)) {
    const ts = liveMap[dev] || 0;
    if (now - ts <= LIVE_WINDOW) live++;
    else if (now - ts > 10 * 60 * 1000) stale.push(dev);
  }
  for (const dev of stale.slice(0, 50)) dbRemove("stats_live/" + dev).catch(() => {});
  const last7 = [];
  for (let i = 6; i >= 0; i--) {
    const d = pktDay(now - i * 86400000);
    const rec = days[d] || {};
    last7.push({ d, visits: rec.visits || 0, uniques: rec.uniques || 0 });
  }
  const hours = (await dbGet("stats_hours/" + today)) || {};
  const vMap = (await dbGet("stats_visitors")) || {};
  const visitors = Object.keys(vMap).map((dev) => {
    const v = Object.assign(blankVisitor(), vMap[dev] || {});
    const pages = {};
    let totalSecs = 0;
    const sessOut = [];
    (v.sess || []).forEach((s) => {
      let ss = 0;
      Object.keys(s.pages || {}).forEach((pg) => {
        const e = s.pages[pg] || {};
        pages[pg] = pages[pg] || { v: 0, s: 0, sc: 0 };
        pages[pg].s += e.s || 0;
        pages[pg].sc = Math.max(pages[pg].sc, e.sc || 0);
        ss += e.s || 0;
      });
      totalSecs += ss;
      sessOut.push({ t: s.t || 0, s: ss });
    });
    Object.keys(v.pv || {}).forEach((pg) => {
      pages[pg] = pages[pg] || { v: 0, s: 0, sc: 0 };
      pages[pg].v = v.pv[pg] || 0;
    });
    return {
      ip: v.ip || "", cc: v.cc || "??", city: v.city || "", dtype: v.dtype || "", os: v.os || "", browser: v.browser || "",
      first: v.first || 0, last: v.last || 0, visits: v.visits || 0, sessions: v.sessions || 0,
      totalSecs, pages, sess: sessOut,
    };
  }).sort((a, b) => (b.last || 0) - (a.last || 0)).slice(0, 50);
  const botsMap = (await dbGet("stats_bots")) || {};
  const bots = Object.keys(botsMap).map((k) => botsMap[k]).filter(Boolean)
    .sort((a, b) => (b.last || 0) - (a.last || 0)).slice(0, 20);
  return {
    live,
    today: outRec(days[today], today),
    yesterday: outRec(days[yesterday], yesterday),
    total: outRec(total),
    last7, hours, visitors, bots,
  };
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return send(res, 405, { error: "method" });
  try {
    const b = await readBody(req);
    const type = String(b.type || "");

    if (type === "setpin") {
      const pin = String(b.pin || "");
      if (!/^\d{4,8}$/.test(pin)) return send(res, 400, { error: "PIN must be 4-8 digits" });
      const existing = await dbGet("stats_admin");
      if (existing) return send(res, 409, { error: "PIN already set" });
      const salt = newSalt();
      const hash = await hashSecret(pin, salt);
      await dbSet("stats_admin", { salt, hash });
      return send(res, 200, { ok: true });
    }

    if (type === "resetpin") {
      /* factory reset, guarded by the CURRENT stats PIN: clears the PIN
         and all counters (used once after the launch E2E test; also lets
         the owner change his PIN later) */
      const admin = await dbGet("stats_admin");
      if (!admin) return send(res, 200, { ok: true });
      const okPin = await verifySecret(String(b.pin || ""), admin.salt, admin.hash);
      if (!okPin) return send(res, 401, { error: "Wrong PIN" });
      await dbRemove("stats_admin");
      await dbRemove("stats_days");
      await dbRemove("stats_total");
      await dbRemove("stats_devices");
      await dbRemove("stats_live");
      await dbRemove("stats_hours");
      await dbRemove("stats_visitors");
      await dbRemove("stats_bots");
      return send(res, 200, { ok: true, reset: true });
    }

    if (type === "stats") {
      const admin = await dbGet("stats_admin");
      if (!admin) return send(res, 200, { setup: true });
      const okPin = await verifySecret(String(b.pin || ""), admin.salt, admin.hash);
      if (!okPin) return send(res, 401, { error: "Wrong PIN" });
      return send(res, 200, await buildStats());
    }

    if (type === "botlog") {
      /* from the edge middleware: a crawler that only fetched the HTML
         (no JavaScript). UA, IP and country arrive in the body because
         the middleware's own request would hide the originals. */
      const name = botName(b.ua);
      if (!name) return send(res, 200, { ok: true });
      const ipB = String(b.ip || "").slice(0, 64);
      const guardB = await rateLimited(ipB || "botlog", "track", 300, 10 * 60 * 1000);
      if (guardB.limited) return send(res, 200, { ok: true });
      await recordFailure(guardB.key, guardB.rec, guardB.now).catch(() => {});
      const ccRaw = String(b.cc || "").toUpperCase();
      await recordBot(name, /^[A-Z]{2}$/.test(ccRaw) ? ccRaw : "??", ipB, cleanCity(b.city));
      return send(res, 200, { ok: true });
    }

    /* ---- visit / ping ---- */
    const device = String(b.device || "");
    if (!DEV_RE.test(device)) return send(res, 400, { error: "bad device" });
    const page = String(b.page || "home").toLowerCase();
    if (!PAGE_RE.test(page)) return send(res, 400, { error: "bad page" });
    if (type !== "visit" && type !== "ping") return send(res, 400, { error: "bad type" });

    const ip = clientIp(req);
    const guard = await rateLimited(ip, "track", 300, 10 * 60 * 1000);
    if (guard.limited) return send(res, 200, { ok: true });
    await recordFailure(guard.key, guard.rec, guard.now).catch(() => {});

    /* Bots that DO run JavaScript land here too — count them as bots,
       never as people, and never in the live/visitor records. */
    const bot = botName(req.headers && req.headers["user-agent"]);
    if (bot) {
      if (type === "visit") await recordBot(bot, visitCountry(req), ip, visitCity(req));
      return send(res, 200, { ok: true });
    }

    const now = Date.now();
    await dbSet("stats_live/" + device, now);
    if (type === "ping") {
      /* per-visitor detail: how long this page stayed open + how far
         it was scrolled (cumulative values, stored with max semantics) */
      const secs = Math.max(0, Math.min(86400, parseInt(b.secs, 10) || 0));
      const scroll = Math.max(0, Math.min(100, parseInt(b.scroll, 10) || 0));
      const v = Object.assign(blankVisitor(), (await dbGet("stats_visitors/" + device)) || {});
      const cur = ensureSession(v, now);
      const ent = cur.pages[page] || { s: 0, sc: 0 };
      ent.s = Math.max(ent.s || 0, secs);
      ent.sc = Math.max(ent.sc || 0, scroll);
      cur.pages[page] = ent;
      const vdP = visitDevice(req);
      v.ip = ip; v.cc = visitCountry(req);
      v.city = visitCity(req) || v.city;
      v.dtype = vdP.type; v.os = vdP.os; v.browser = vdP.browser;
      if (!v.first) v.first = now;
      v.last = now;
      await dbSet("stats_visitors/" + device, v);
      return send(res, 200, { ok: true });
    }

    const day = pktDay(now);
    const devRec = await dbGet("stats_devices/" + device);
    const isNewDevice = !devRec;
    const isNewToday = !(devRec && devRec.days && devRec.days[day]);

    const cc = visitCountry(req);
    const vd = visitDevice(req);
    const src = visitSource(b.ref);

    const hourKey = String(new Date(now + 5 * 3600 * 1000).getUTCHours()).padStart(2, "0");
    const prevHour = (await dbGet("stats_hours/" + day + "/" + hourKey)) || 0;
    await dbSet("stats_hours/" + day + "/" + hourKey, prevHour + 1).catch(() => {});

    const dayRec = Object.assign(blankRec(), (await dbGet("stats_days/" + day)) || {});
    dayRec.visits += 1;
    dayRec.uniques += isNewToday ? 1 : 0;
    dayRec.pages = bumpMap(dayRec.pages, page);
    dayRec.countries = bumpMap(dayRec.countries, cc);
    dayRec.devtypes = bumpMap(dayRec.devtypes, vd.type);
    dayRec.oses = bumpMap(dayRec.oses, vd.os);
    dayRec.browsers = bumpMap(dayRec.browsers, vd.browser);
    dayRec.sources = bumpMap(dayRec.sources, src);
    await dbSet("stats_days/" + day, dayRec);

    const total = Object.assign(blankRec(), (await dbGet("stats_total")) || {});
    total.visits += 1;
    total.uniques += isNewDevice ? 1 : 0;
    total.pages = bumpMap(total.pages, page);
    total.countries = bumpMap(total.countries, cc);
    total.devtypes = bumpMap(total.devtypes, vd.type);
    total.oses = bumpMap(total.oses, vd.os);
    total.browsers = bumpMap(total.browsers, vd.browser);
    total.sources = bumpMap(total.sources, src);
    await dbSet("stats_total", total);

    const daysMap = (devRec && devRec.days) || {};
    daysMap[day] = 1;
    await dbSet("stats_devices/" + device, {
      first: devRec ? devRec.first || now : now,
      last: now,
      days: daysMap,
      cc, dtype: vd.type, os: vd.os, browser: vd.browser,
    });

    /* per-visitor detail: repeat history (visits + sessions) */
    const v = Object.assign(blankVisitor(), (await dbGet("stats_visitors/" + device)) || {});
    const cur = ensureSession(v, now);
    if (!cur.pages[page]) cur.pages[page] = { s: 0, sc: 0 };
    v.visits = (v.visits || 0) + 1;
    v.pv = bumpMap(v.pv, page);
    v.ip = ip; v.cc = cc;
    v.city = visitCity(req) || v.city;
    v.dtype = vd.type; v.os = vd.os; v.browser = vd.browser;
    if (!v.first) v.first = now;
    v.last = now;
    await dbSet("stats_visitors/" + device, v);
    return send(res, 200, { ok: true });
  } catch (e) {
    return send(res, 500, { error: "track failed" });
  }
};
