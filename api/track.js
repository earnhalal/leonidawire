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
     stats_admin = {salt, hash} (stats PIN, scrypt)
   Days follow Asia/Karachi (PKT = UTC+5). */
const {
  dbGet, dbSet, dbRemove, readBody, send, clientIp,
  rateLimited, recordFailure, hashSecret, newSalt, verifySecret,
} = require("./_lib");

const DEV_RE = /^[a-zA-Z0-9-]{8,40}$/;
const PAGE_RE = /^[a-z0-9-]{1,40}$/;
const LIVE_WINDOW = 90 * 1000;

function pktDay(ts) {
  return new Date(ts + 5 * 3600 * 1000).toISOString().slice(0, 10);
}
function visitCountry(req) {
  const cc = String((req.headers && req.headers["x-vercel-ip-country"]) || "").toUpperCase();
  return /^[A-Z]{2}$/.test(cc) ? cc : "??";
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
  return { visits: 0, uniques: 0, pages: {}, countries: {}, devtypes: {}, oses: {}, browsers: {}, sources: {} };
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
  return {
    live,
    today: outRec(days[today], today),
    yesterday: outRec(days[yesterday], yesterday),
    total: outRec(total),
    last7, hours,
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
      return send(res, 200, { ok: true, reset: true });
    }

    if (type === "stats") {
      const admin = await dbGet("stats_admin");
      if (!admin) return send(res, 200, { setup: true });
      const okPin = await verifySecret(String(b.pin || ""), admin.salt, admin.hash);
      if (!okPin) return send(res, 401, { error: "Wrong PIN" });
      return send(res, 200, await buildStats());
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

    const now = Date.now();
    await dbSet("stats_live/" + device, now);
    if (type === "ping") return send(res, 200, { ok: true });

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
    return send(res, 200, { ok: true });
  } catch (e) {
    return send(res, 500, { error: "track failed" });
  }
};
