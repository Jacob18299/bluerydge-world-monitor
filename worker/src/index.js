/**
 * Bluerydge World Monitor — Phase 3 collector & API (config-driven, with persistent memory).
 *
 * MEMORY MODEL:
 *  - D1 (binding DB): the switchboard `sources`, plus permanent history in `signals`,
 *    `vulns`, `movement_counts`, `ingest_runs`. Signals are inserted once by a stable id;
 *    later sightings only bump last_seen/seen_count — nothing is ever forgotten.
 *  - KV (binding SIGNALS): fast cache of the served payload + latest aircraft positions +
 *    per-CVE CVSS cache + previous region scores (for trend).
 *  - R2 (binding ARCHIVE): raw per-run feed snapshots + historical aircraft positions, date-
 *    prefixed (raw/YYYY/MM/DD, positions/YYYY/MM/DD). Cold storage / replay; guarded no-op if unbound.
 *
 * INSIGHT NOTES: buildPayload() runs attachInsights(), which reads 14–31 days of D1 history and
 *   attaches a short, plain-English `.note` to a signal when it spots recurrence, clustering, or a
 *   build-up vs baseline. Conservative observations for a human to assess — never predictions.
 *
 * ENDPOINTS:
 *  - GET  /api/signals   -> recent (7d) signals/vulns/regions (with insight notes) for the dashboard
 *  - GET  /api/insights  -> just the signals that currently carry an insight note (verification)
 *  - GET  /api/movement  -> latest aircraft positions for the (off-by-default) map layer
 *  - GET  /api/sources   -> per-source health for the Admin & Sources page
 *  - POST /api/admin/source {key, enabled}  -> flip a source on/off (needs x-admin-token)
 *  - POST /api/assistant  -> chat assistant (free Workers AI)
 *  - GET  /refresh       -> run an ingest now (handy for first populate / debugging)
 *
 * If anything fails, callers fall back gracefully and the dashboard keeps its baked-in data.
 */

// ===================== region maps =====================
const REGION_COORDS = {
  'Middle East':   { lat: 29,  lon: 45 },
  'Asia-Pacific':  { lat: 18,  lon: 120 },
  'Europe':        { lat: 52,  lon: 16 },
  'Australia':     { lat: -25, lon: 134 },
  'North America': { lat: 40,  lon: -100 },
  'South America': { lat: -15, lon: -60 },
  'Africa':        { lat: 2,   lon: 20 },
};
const RISK_REGIONS = ['Middle East', 'Asia-Pacific', 'Europe', 'Australia', 'North America', 'South America'];

const COUNTRY_REGION = {
  'united states': ['North America', 38, -97], 'usa': ['North America', 38, -97],
  'canada': ['North America', 56, -106], 'mexico': ['North America', 23, -102],
  'united kingdom': ['Europe', 54, -2], 'uk': ['Europe', 54, -2], 'england': ['Europe', 52, -1],
  'ukraine': ['Europe', 49, 32], 'russia': ['Europe', 61, 90], 'germany': ['Europe', 51, 10],
  'france': ['Europe', 47, 2], 'italy': ['Europe', 42, 13], 'spain': ['Europe', 40, -4],
  'poland': ['Europe', 52, 19], 'netherlands': ['Europe', 52, 5], 'sweden': ['Europe', 62, 15],
  'israel': ['Middle East', 32, 35], 'iran': ['Middle East', 32, 53], 'iraq': ['Middle East', 33, 44],
  'syria': ['Middle East', 35, 38], 'lebanon': ['Middle East', 34, 36], 'yemen': ['Middle East', 15, 48],
  'saudi arabia': ['Middle East', 24, 45], 'turkey': ['Middle East', 39, 35], 'qatar': ['Middle East', 25, 51],
  'united arab emirates': ['Middle East', 24, 54], 'palestine': ['Middle East', 31.5, 34.5],
  'china': ['Asia-Pacific', 35, 103], 'japan': ['Asia-Pacific', 37, 138], 'south korea': ['Asia-Pacific', 36, 128],
  'north korea': ['Asia-Pacific', 40, 127], 'india': ['Asia-Pacific', 22, 79], 'taiwan': ['Asia-Pacific', 24, 121],
  'vietnam': ['Asia-Pacific', 16, 106], 'philippines': ['Asia-Pacific', 13, 122], 'indonesia': ['Asia-Pacific', -2, 118],
  'singapore': ['Asia-Pacific', 1.3, 104], 'pakistan': ['Asia-Pacific', 30, 70], 'thailand': ['Asia-Pacific', 15, 101],
  'australia': ['Australia', -25, 134], 'new zealand': ['Australia', -41, 174],
  'brazil': ['South America', -10, -52], 'argentina': ['South America', -34, -64], 'colombia': ['South America', 4, -73],
  'venezuela': ['South America', 7, -66], 'chile': ['South America', -33, -71], 'peru': ['South America', -10, -76],
  'nigeria': ['Africa', 9, 8], 'egypt': ['Africa', 27, 30], 'south africa': ['Africa', -29, 24],
  'kenya': ['Africa', 0, 38], 'ethiopia': ['Africa', 9, 40], 'sudan': ['Africa', 15, 30], 'libya': ['Africa', 27, 17],
};

const REGION_KEYWORDS = [
  ['Middle East', ['israel', 'iran', 'gaza', 'hamas', 'hezbollah', 'lebanon', 'syria', 'iraq', 'yemen', 'saudi', 'qatar', 'tehran', 'palestin', 'houthi']],
  ['Australia',   ['australia', 'australian', 'canberra', 'sydney', 'melbourne', 'acsc', ' asd ', 'new zealand']],
  ['Asia-Pacific',['china', 'chinese', 'beijing', 'japan', 'korea', 'taiwan', 'india', 'vietnam', 'philippines', 'indonesia', 'singapore', 'pakistan', 'hong kong']],
  ['Europe',      ['ukraine', 'russia', 'russian', 'moscow', 'kyiv', 'germany', 'france', 'britain', 'british', ' uk ', 'england', 'poland', 'nato', 'europe', 'eu ']],
  ['South America',['brazil', 'argentina', 'venezuela', 'colombia', 'chile', 'peru']],
  ['Africa',      ['nigeria', 'egypt', 'kenya', 'ethiopia', 'south africa', 'sudan', 'libya', 'somalia']],
  ['North America',['united states', 'u.s.', 'american', 'washington', 'canada', 'fbi', 'cisa', 'nsa', 'pentagon']],
];

// OpenSky bounding boxes (conflict-relevant + home region). [lamin, lomin, lamax, lomax]
const OPENSKY_BOXES = [
  { region: 'Middle East',  box: [12, 25, 42, 60] },
  { region: 'Asia-Pacific', box: [18, 105, 45, 145] },
  { region: 'Europe',       box: [44, 20, 60, 45] },
  { region: 'Australia',    box: [-44, 112, -10, 154] },
];
// Rough military callsign prefixes (heuristic only — flagged conservatively for human review).
const MIL_CALLSIGN = ['RCH', 'CNV', 'RRR', 'ASCOT', 'CFC', 'RFR', 'BAF', 'GAF', 'IAM', 'NATO', 'FORTE', 'HOMER', 'REDEYE', 'PYTHON', 'GRZLY', 'JAKE', 'SLAM', 'QID', 'MMF'];

// ===================== helpers =====================
function nowIso() { return new Date().toISOString(); }
function relTime(date) {
  const ms = Date.now() - date.getTime();
  if (!isFinite(ms) || ms < 0) return 'just now';
  const m = Math.round(ms / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return m + 'm ago';
  const h = Math.round(m / 60);
  if (h < 24) return h + 'h ago';
  const d = Math.round(h / 24);
  return d + (d === 1 ? ' day ago' : ' days ago');
}
function parseDate(s) { const d = s ? new Date(s) : new Date(NaN); return isNaN(d.getTime()) ? new Date() : d; }
function decodeEntities(s) {
  return (s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'")
    .replace(/&#x27;/g, "'").replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/\s+/g, ' ').trim();
}
function clip(s, n) { s = (s || '').trim(); return s.length > n ? s.slice(0, n - 1).trim() + '…' : s; }
function hash(str) { let h = 2166136261 >>> 0; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } return h.toString(36); }
function safeConfig(s) { try { return JSON.parse(s || '{}'); } catch (_) { return {}; } }

function sevFromText(t) {
  t = (t || '').toLowerCase();
  if (/zero-?day|0-day|actively exploited|in the wild|ransomware|emergency|critical/.test(t)) return 'CRITICAL';
  if (/vulnerab|exploit|cve-|breach|backdoor|malware|attack|hack|compromis|data leak|espionage|spyware/.test(t)) return 'HIGH';
  return 'MEDIUM';
}
function regionFromText(t) {
  const s = ' ' + (t || '').toLowerCase() + ' ';
  for (const [bucket, kws] of REGION_KEYWORDS) for (const kw of kws) if (s.includes(kw)) return bucket;
  return 'North America';
}
function regionForSource(src, text) {
  if (src.region_rule && src.region_rule.indexOf('fixed:') === 0) return src.region_rule.slice(6);
  return regionFromText(text);
}
function jitter(base, i, span) { return base + (((i * 7) % 9) - 4) * span; }
async function safeFetch(url, opts) {
  try {
    const r = await fetch(url, Object.assign({ headers: { 'user-agent': 'BluerydgeWorldMonitor/1.0 (+pages.dev)' } }, opts || {}));
    if (!r.ok) return { ok: false, status: r.status, res: null };
    return { ok: true, status: r.status, res: r };
  } catch (e) { return { ok: false, status: 0, res: null, err: String((e && e.message) || e) }; }
}
function parseFeed(xml) {
  if (!xml) return [];
  const items = [];
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
  for (const b of blocks) {
    const pick = (tag) => { const m = b.match(new RegExp('<' + tag + '[^>]*>([\\s\\S]*?)<\\/' + tag + '>', 'i')); return m ? decodeEntities(m[1]) : ''; };
    let link = pick('link');
    if (!link) { const lm = b.match(/<link[^>]*href="([^"]+)"/i); if (lm) link = lm[1]; }
    const title = pick('title'); if (!title) continue;
    items.push({ title, link, date: pick('pubDate') || pick('published') || pick('updated') || pick('dc:date'), desc: pick('description') || pick('summary') || pick('content') });
  }
  return items;
}

// ===================== source collectors =====================
// Each returns { events:[], vulns:[], count, error } and is given the source row `src`.

async function collectKEV(src, env) {
  const out = { events: [], vulns: [], count: 0, error: null };
  const cfg = safeConfig(src.config);
  const f = await safeFetch(src.url);
  if (!f.ok) { out.error = 'fetch failed (' + (f.status || f.err) + ')'; return out; }
  let data; try { data = await f.res.json(); } catch (e) { out.error = 'bad json'; return out; }
  const list = (data.vulnerabilities || []).slice().sort((a, b) => (b.dateAdded || '').localeCompare(a.dateAdded || ''));
  const top = list.slice(0, cfg.limit || 12);
  const nvdOn = await sourceEnabled(env, 'nvd');
  let nvdBudget = nvdOn ? (safeConfig((await getSource(env, 'nvd') || {}).config).budget || 5) : 0;
  for (const v of top) {
    let cvss = '', vector = '';
    const cacheKey = 'cvss:' + v.cveID;
    let cached = null; try { cached = await env.SIGNALS.get(cacheKey, 'json'); } catch (_) {}
    if (cached) { cvss = cached.cvss; vector = cached.vector; }
    else if (nvdBudget > 0) {
      nvdBudget--;
      const nf = await safeFetch('https://services.nvd.nist.gov/rest/json/2.0/cves/2.0?cveId=' + encodeURIComponent(v.cveID));
      if (nf.ok) {
        try { const nd = await nf.res.json(); const metrics = nd.vulnerabilities && nd.vulnerabilities[0] && nd.vulnerabilities[0].cve.metrics; const mm = metrics && (metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2); if (mm && mm[0]) { cvss = String(mm[0].cvssData.baseScore); const av = mm[0].cvssData.attackVector; vector = av ? (av.charAt(0) + av.slice(1).toLowerCase()) + ' attack vector' : ''; } } catch (_) {}
        try { await env.SIGNALS.put(cacheKey, JSON.stringify({ cvss, vector }), { expirationTtl: 60 * 60 * 24 * 14 }); } catch (_) {}
      }
    }
    const ransomware = (v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
    const score = parseFloat(cvss);
    let sev = 'HIGH';
    if (!isNaN(score)) sev = score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : 'MEDIUM';
    if (ransomware && sev !== 'CRITICAL') sev = 'CRITICAL';
    out.vulns.push({
      cve: v.cveID, sev, name: clip(v.vulnerabilityName || (v.vendorProject + ' ' + v.product), 90),
      cvss: cvss || 'KEV', status: ransomware ? 'Actively exploited (ransomware)' : 'Actively exploited',
      impact: clip(v.shortDescription, 130), affected: clip(((v.vendorProject || '') + ' ' + (v.product || '')).trim(), 120),
      descr: clip(v.shortDescription, 260),
      vector: vector || 'Listed on CISA’s Known Exploited Vulnerabilities catalog — confirmed exploited in the wild.',
      action: clip(v.requiredAction, 260) || 'Apply the vendor patch and follow CISA guidance.',
      date: v.dateAdded,
    });
  }
  // top few as map pins
  out.vulns.slice(0, cfg.pins || 5).forEach((vv, i) => {
    const bucket = RISK_REGIONS[i % RISK_REGIONS.length]; const c = REGION_COORDS[bucket];
    out.events.push({ id: 'kev:' + vv.cve, source_key: src.key, cat: 'vuln', sev: vv.sev, region: 'Global advisory, ' + bucket, lat: jitter(c.lat, i, 1.4), lon: jitter(c.lon, i + 2, 1.4), source: 'CISA KEV', url: 'https://nvd.nist.gov/vuln/detail/' + vv.cve, title: vv.name + ' (' + vv.cve + ')', blurb: vv.descr, rec: vv.action, eventDate: vv.date });
  });
  out.count = out.vulns.length;
  return out;
}

async function collectRSS(src) {
  const out = { events: [], vulns: [], count: 0, error: null };
  const cfg = safeConfig(src.config);
  let f = await safeFetch(src.url);
  if (!f.ok && cfg.fallbackUrl) f = await safeFetch(cfg.fallbackUrl);
  if (!f.ok) { out.error = 'fetch failed (' + (f.status || f.err) + ')'; return out; }
  const items = parseFeed(await f.res.text()).slice(0, cfg.limit || 6);
  items.forEach((it, i) => {
    const text = it.title + ' ' + it.desc; const tl = text.toLowerCase();
    let cat = src.category || 'cyber';
    if (/\bics\b|scada|industrial control|operational technology|\bot\b|infrastructure/.test(tl)) cat = 'infra';
    else if (/defen[cs]e|military|navy|army|missile|warfare|troops/.test(tl)) cat = 'defence';
    const region = regionForSource(src, text); const c = REGION_COORDS[region] || REGION_COORDS['North America'];
    out.events.push({ id: 'rss:' + src.key + ':' + hash(it.link || it.title), source_key: src.key, cat, sev: sevFromText(text), region: src.name + ', ' + region, lat: jitter(c.lat, i, 1.3), lon: jitter(c.lon, i + 1, 1.3), source: src.name, url: it.link, title: clip(it.title, 110), blurb: clip(it.desc, 220) || clip(it.title, 220), rec: 'Review against your environment; confirm exposure before acting.', eventDate: it.date });
  });
  out.count = out.events.length;
  return out;
}

async function collectGDELT(src) {
  const out = { events: [], vulns: [], count: 0, error: null };
  const cfg = safeConfig(src.config);
  const q = '(conflict OR military OR airstrike OR offensive OR missile OR ceasefire OR troops OR sanctions OR "armed forces")';
  const url = src.url + '?query=' + encodeURIComponent(q) + '&mode=ArtList&maxrecords=40&format=json&sort=DateDesc&timespan=24H';
  const f = await safeFetch(url);
  if (!f.ok) { out.error = 'fetch failed (' + (f.status || f.err) + ')'; return out; }
  let data; try { data = await f.res.json(); } catch (e) { out.error = 'bad json'; return out; }
  const seen = new Set(); let i = 0;
  for (const a of (data.articles || [])) {
    if ((a.language || '').toLowerCase() !== 'english') continue;
    const title = decodeEntities(a.title); const key = title.toLowerCase().slice(0, 50);
    if (!title || seen.has(key)) continue; seen.add(key);
    const country = (a.sourcecountry || '').toLowerCase(); const map = COUNTRY_REGION[country];
    let region, lat, lon;
    if (map) { region = map[0]; lat = map[1]; lon = map[2]; } else { region = regionFromText(title); const c = REGION_COORDS[region]; lat = c.lat; lon = c.lon; }
    const tl = title.toLowerCase();
    const cat = /military|missile|troops|defen[cs]e|navy|army|warfare|nato|nuclear|weapon|airstrike/.test(tl) ? 'defence' : 'geo';
    out.events.push({ id: 'gdelt:' + hash(a.url || title), source_key: src.key, cat, sev: sevFromText(title), region: (a.sourcecountry || region) + ', ' + region, lat: jitter(lat, i, 1.1), lon: jitter(lon, i + 1, 1.1), source: a.domain || 'GDELT', url: a.url, title: clip(title, 110), blurb: clip(title, 200), rec: 'Geopolitical signal — monitor for regional escalation and supply-chain knock-on effects.', eventDate: a.seendate });
    if (++i >= (cfg.limit || 12)) break;
  }
  out.count = out.events.length;
  return out;
}

// OpenSky: aircraft positions -> movement_counts baselines + latest-positions snapshot + anomaly signals.
async function collectOpenSky(src, env, runTs, force) {
  const out = { events: [], vulns: [], count: 0, error: null, positions: [], counts: [] };
  // Sample once per hour (top of the hour) to stay within the free anonymous credit budget.
  if (!force && new Date(runTs).getUTCMinutes() >= 15) { out.error = null; out.skipped = 'hourly cadence'; return out; }
  let total = 0, anyOk = false, lastErr = null;
  for (const b of OPENSKY_BOXES) {
    const [lamin, lomin, lamax, lomax] = b.box;
    const f = await safeFetch(src.url + '?lamin=' + lamin + '&lomin=' + lomin + '&lamax=' + lamax + '&lomax=' + lomax);
    if (!f.ok) { lastErr = 'fetch failed (' + (f.status || f.err) + ')'; continue; }
    let data; try { data = await f.res.json(); } catch (_) { lastErr = 'bad json'; continue; }
    anyOk = true;
    const states = data.states || [];
    let mil = 0;
    for (const s of states) {
      const lon = s[5], lat = s[6], cs = (s[1] || '').trim(), country = s[2], onGround = s[8];
      if (lat == null || lon == null) continue;
      const isMil = MIL_CALLSIGN.some(p => cs.toUpperCase().startsWith(p));
      if (isMil) mil++;
      if (out.positions.length < 600) out.positions.push({ lat, lon, cs, country, mil: isMil ? 1 : 0, region: b.region });
    }
    total += states.length;
    out.counts.push({ region: b.region, kind: 'air_total', count: states.length });
    out.counts.push({ region: b.region, kind: 'mil_air', count: mil });
  }
  if (!anyOk) { out.error = lastErr || 'no boxes returned'; return out; }
  out.count = total;
  // store latest positions for the live layer (KV; R2 archival added once enabled)
  try { await env.SIGNALS.put('movement-latest', JSON.stringify({ generatedAt: runTs, aircraft: out.positions })); } catch (_) {}
  return out;
}

// ===================== D1 ingestion =====================
async function ingestSignals(env, events, runTs) {
  if (!events.length) return { added: 0, updated: 0 };
  const stmts = [];
  for (const e of events) {
    const t = e.eventDate ? parseDate(e.eventDate).toISOString() : runTs;
    stmts.push(env.DB.prepare(
      `INSERT INTO signals (id, source_key, cat, sev, region, lat, lon, title, blurb, rec, source, url, first_seen, last_seen, seen_count, extra)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13,1,?14)
       ON CONFLICT(id) DO UPDATE SET last_seen=?13, seen_count=seen_count+1, sev=?4, title=?8, blurb=?9, rec=?10, region=?5, lat=?6, lon=?7`
    ).bind(e.id, e.source_key || null, e.cat, e.sev, e.region, e.lat, e.lon, e.title, e.blurb, e.rec, e.source, e.url || null, t, JSON.stringify(e.extra || {})));
  }
  // count how many are new (best-effort): query existing ids first
  let added = 0;
  try {
    const ids = events.map(e => e.id);
    const placeholders = ids.map((_, i) => '?' + (i + 1)).join(',');
    const existing = await env.DB.prepare('SELECT id FROM signals WHERE id IN (' + placeholders + ')').bind(...ids).all();
    const have = new Set((existing.results || []).map(r => r.id));
    added = ids.filter(id => !have.has(id)).length;
  } catch (_) {}
  await env.DB.batch(stmts);
  return { added, updated: events.length - added };
}

async function ingestVulns(env, vulns, runTs) {
  if (!vulns.length) return;
  const stmts = vulns.map(v => env.DB.prepare(
    `INSERT INTO vulns (cve, source_key, sev, name, cvss, status, impact, affected, descr, vector, action, first_seen, last_seen, seen_count)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?12,1)
     ON CONFLICT(cve) DO UPDATE SET last_seen=?12, seen_count=seen_count+1, sev=?3, cvss=?5, status=?6`
  ).bind(v.cve, 'cisa_kev', v.sev, v.name, v.cvss, v.status, v.impact, v.affected, v.descr, v.vector, v.action, v.date ? parseDate(v.date).toISOString() : runTs));
  await env.DB.batch(stmts);
}

async function ingestMovementCounts(env, counts, runTs) {
  if (!counts.length) return;
  const stmts = counts.map(c => env.DB.prepare('INSERT INTO movement_counts (ts, region, kind, count) VALUES (?1,?2,?3,?4)').bind(runTs, c.region, c.kind, c.count));
  await env.DB.batch(stmts);
}

// Conservative anomaly flags: current count well above this region/kind's own recent baseline.
async function detectMovementAnomalies(env, counts, runTs) {
  const events = [];
  const today = runTs.slice(0, 10);
  for (const c of counts) {
    if (c.kind !== 'mil_air' && c.kind !== 'air_total') continue;
    let rows;
    try { rows = await env.DB.prepare('SELECT count FROM movement_counts WHERE region=?1 AND kind=?2 AND ts < ?3 ORDER BY ts DESC LIMIT 24').bind(c.region, c.kind, runTs).all(); } catch (_) { continue; }
    const hist = (rows.results || []).map(r => r.count);
    if (hist.length < 6) continue; // need a real baseline first
    const mean = hist.reduce((a, b) => a + b, 0) / hist.length;
    const variance = hist.reduce((a, b) => a + (b - mean) * (b - mean), 0) / hist.length;
    const sd = Math.sqrt(variance);
    const minAbs = c.kind === 'mil_air' ? 5 : 60;
    const threshold = Math.max(mean * 2, mean + 2.5 * sd, minAbs);
    if (c.count >= threshold && c.count >= minAbs) {
      const co = REGION_COORDS[c.region] || REGION_COORDS['North America'];
      const label = c.kind === 'mil_air' ? 'military aircraft' : 'aircraft';
      events.push({
        id: 'anomaly:' + c.region + ':' + c.kind + ':' + today,
        source_key: 'opensky', cat: 'defence', sev: c.kind === 'mil_air' ? 'HIGH' : 'MEDIUM',
        region: 'Movement watch, ' + c.region, lat: co.lat, lon: co.lon, source: 'Movement anomaly (OpenSky)',
        url: null,
        title: '⚠ Movement anomaly: elevated ' + label + ' activity near ' + c.region,
        blurb: 'Currently ' + c.count + ' ' + label + ' detected near ' + c.region + ', vs a recent baseline of ~' + Math.round(mean) + '. This is an automated anomaly flag, not a prediction.',
        rec: 'Anomaly flag for analyst review only — verify against known exercises, holidays or routine operations before drawing conclusions.',
        eventDate: runTs,
      });
    }
  }
  return events;
}

// ===================== sources helpers =====================
async function getEnabledSources(env) {
  const r = await env.DB.prepare('SELECT * FROM sources WHERE enabled=1 ORDER BY sort').all();
  return r.results || [];
}
async function getSource(env, key) {
  const r = await env.DB.prepare('SELECT * FROM sources WHERE key=?1').bind(key).first();
  return r || null;
}
async function sourceEnabled(env, key) { const s = await getSource(env, key); return !!(s && s.enabled); }
async function updateSourceStatus(env, key, ok, count, error, runTs) {
  try {
    if (ok) await env.DB.prepare('UPDATE sources SET last_fetch=?2, last_success=?2, last_item_count=?3, last_error=NULL, consecutive_errors=0, updated_at=?2 WHERE key=?1').bind(key, runTs, count || 0).run();
    else await env.DB.prepare('UPDATE sources SET last_fetch=?2, last_error=?3, consecutive_errors=consecutive_errors+1, updated_at=?2 WHERE key=?1').bind(key, runTs, String(error || 'error')).run();
  } catch (_) {}
}

// ===================== main collect =====================
async function collect(env, opts) {
  opts = opts || {};
  const runTs = nowIso();
  const sources = await getEnabledSources(env);
  let allEvents = [], allVulns = [], allCounts = [], allPositions = [], ok = 0, failed = 0, rawByKey = {};

  for (const src of sources) {
    if (src.type === 'nvd_enrich') { continue; } // used inside KEV, not standalone
    let res;
    try {
      if (src.type === 'kev') res = await collectKEV(src, env);
      else if (src.type === 'rss') res = await collectRSS(src);
      else if (src.type === 'gdelt') res = await collectGDELT(src);
      else if (src.type === 'opensky') res = await collectOpenSky(src, env, runTs, opts.forceMovement);
      else res = { events: [], vulns: [], count: 0, error: 'unknown type ' + src.type };
    } catch (e) { res = { events: [], vulns: [], count: 0, error: String((e && e.message) || e) }; }

    if (res.skipped) { continue; } // e.g. opensky off-cadence — don't mark failed
    if (res.error) { failed++; await updateSourceStatus(env, src.key, false, 0, res.error, runTs); }
    else { ok++; await updateSourceStatus(env, src.key, true, res.count, null, runTs); }

    if (res.events && res.events.length) allEvents = allEvents.concat(res.events);
    if (res.vulns && res.vulns.length) allVulns = allVulns.concat(res.vulns);
    if (res.counts && res.counts.length) allCounts = allCounts.concat(res.counts);
    if (res.positions && res.positions.length) allPositions = allPositions.concat(res.positions);
    rawByKey[src.key] = { count: res.count, error: res.error || null };
  }

  // Movement baselines + anomaly flags
  if (allCounts.length) {
    await ingestMovementCounts(env, allCounts, runTs);
    const anomalies = await detectMovementAnomalies(env, allCounts, runTs);
    if (anomalies.length) allEvents = allEvents.concat(anomalies);
  }

  // Persist to permanent memory
  const ing = await ingestSignals(env, allEvents, runTs);
  await ingestVulns(env, allVulns, runTs);

  // Archive to R2 if the bucket is bound (no-op otherwise). D1 keeps the structured,
  // queryable records; R2 holds the bulky raw JSON so we can rebuild/replay history later.
  //   raw/YYYY/MM/DD/<ts>.json        — full per-run snapshot (feed health + normalised events + vulns)
  //   positions/YYYY/MM/DD/<ts>.json  — historical aircraft positions for that run (skipped when empty)
  let archiveErr = null; // surfaced in /refresh response for ops visibility (not shown on dashboard)
  try {
    if (env.ARCHIVE) {
      const day = runTs.slice(0, 10).replace(/-/g, '/');          // YYYY/MM/DD prefix -> cheap date browsing
      const stamp = runTs.replace(/[:.]/g, '-');
      await env.ARCHIVE.put('raw/' + day + '/' + stamp + '.json', JSON.stringify({
        runTs, rawByKey,
        events: allEvents, vulns: allVulns,
        counts: allCounts,
        summary: { events: allEvents.length, vulns: allVulns.length, sources_ok: ok, sources_failed: failed },
      }), { httpMetadata: { contentType: 'application/json' } });
      if (allPositions.length) {
        await env.ARCHIVE.put('positions/' + day + '/' + stamp + '.json', JSON.stringify({
          runTs, count: allPositions.length, aircraft: allPositions,
        }), { httpMetadata: { contentType: 'application/json' } });
      }
    } else { archiveErr = 'ARCHIVE binding undefined'; }
  } catch (e) { archiveErr = String((e && e.message) || e); }

  // Record the run
  try { await env.DB.prepare('INSERT INTO ingest_runs (started_at, finished_at, sources_ok, sources_failed, signals_added, signals_updated, note) VALUES (?1,?1,?2,?3,?4,?5,?6)').bind(runTs, ok, failed, ing.added, ing.updated, 'ok').run(); } catch (_) {}

  // Refresh the served cache (also acts as fallback)
  const payload = await buildPayload(env);
  try { await env.SIGNALS.put('signals-latest', JSON.stringify(payload)); } catch (_) {}
  return { runTs, sources_ok: ok, sources_failed: failed, added: ing.added, updated: ing.updated, events: allEvents.length, vulns: allVulns.length, positions: allPositions.length, archiveErr };
}

// ===================== insight notes (memory-based observations) =====================
// Plain-English observations derived from accumulated history (D1). These are CONSERVATIVE
// pattern flags for a human to assess — never predictions. Each is attached as `.note` on the
// relevant signal so it surfaces in the detail drawer. When nothing is notable, no note is set,
// so the dashboard looks exactly as before. Three kinds:
//   • Recurrence   — "similar activity was recorded in this area before, on <date>"
//   • Clustering   — "3rd defence incident affecting <region> this month"
//   • Build-up     — "air traffic toward <region> is above its 14-day average"
const CAT_NOUN = { cyber: 'cyber', vuln: 'vulnerability', geo: 'geopolitical', defence: 'defence', infra: 'infrastructure' };
function regionBucket(region) {
  const s = String(region || '').trim();
  const i = s.lastIndexOf(',');
  return (i >= 0 ? s.slice(i + 1) : s).trim();
}
function shortDate(iso) {
  try { return parseDate(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }); }
  catch (_) { return String(iso || '').slice(0, 10); }
}
function ordinalWord(n) { const s = ['th', 'st', 'nd', 'rd'], v = n % 100; return n + (s[(v - 20) % 10] || s[v] || s[0]); }
const DAY_MS = 86400000;

// Tunables kept deliberately strict so notes stay rare and meaningful (signal, not noise).
const CLUSTER_MIN = 3;     // need at least this many notable incidents to call it a pattern
const CLUSTER_MAX = 30;    // above this it's just background volume, not a "cluster" worth flagging
const PRIOR_MIN = 1;       // proximity recurrence: at least one earlier nearby sighting
const PRIOR_MAX = 8;       // ...but not so many that it's just routine activity for the area
const PERSIST_MIN_DAYS = 3;// an item that keeps reappearing for this many days is "ongoing"

async function attachInsights(env, EVENTS) {
  if (!EVENTS.length) return;
  const nowMonth = nowIso().slice(0, 7);

  // Pull 31 days of signal history once (rolling window for recurrence + clustering).
  let hist = [];
  try {
    hist = (await env.DB.prepare(
      "SELECT id, region, cat, sev, lat, lon, first_seen, last_seen FROM signals WHERE last_seen >= datetime('now','-31 days') ORDER BY first_seen ASC LIMIT 4000"
    ).all()).results || [];
  } catch (_) { hist = []; }

  const histById = {};
  // Clustering only counts NOTABLE incidents (HIGH/CRITICAL) — otherwise routine news volume
  // makes every coarse region "cluster". "3rd critical cyber incident in Middle East" is a
  // signal; "859th geopolitical item in North America" is not.
  const clusters = {};                 // "bucket|cat" -> [ids] this calendar month, first_seen ASC
  for (const h of hist) {
    histById[h.id] = h;
    if ((h.first_seen || '').slice(0, 7) === nowMonth && (h.sev === 'HIGH' || h.sev === 'CRITICAL')) {
      const k = regionBucket(h.region) + '|' + h.cat;
      (clusters[k] || (clusters[k] = [])).push(h.id);
    }
  }

  // Build-up: 14-day air-traffic baseline per region vs the latest reading.
  const buildup = {};                  // bucket -> {latest, avg}
  try {
    const mv = (await env.DB.prepare(
      "SELECT region, count, ts FROM movement_counts WHERE kind='air_total' AND ts >= datetime('now','-14 days') ORDER BY ts ASC"
    ).all()).results || [];
    const byRegion = {};
    for (const r of mv) (byRegion[r.region] || (byRegion[r.region] = [])).push(r.count);
    for (const region in byRegion) {
      const arr = byRegion[region];
      if (arr.length < 6) continue;    // need a real baseline
      const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
      const latest = arr[arr.length - 1];
      if (avg >= 40 && latest >= avg * 1.5) buildup[region] = { latest, avg: Math.round(avg) };
    }
  } catch (_) {}

  const buildupUsed = {};              // one build-up note per region, to avoid repetition
  for (const ev of EVENTS) {
    const bucket = regionBucket(ev.region);
    const cat = ev.cat;
    const noun = CAT_NOUN[cat] || 'related';
    const sig = histById[ev.id];
    const clauses = [];

    // --- Recurrence (1): same physical area seen before ---
    // Only for location-based categories (defence/infra) with real coords, a TIGHT box, and a
    // small number of priors — that's a genuine "aircraft/vessel back in this area", not volume.
    let gotRecurrence = false;
    if (sig && (cat === 'defence' || cat === 'infra') && typeof ev.lat === 'number' && typeof ev.lon === 'number') {
      const cutoff = parseDate(sig.first_seen).getTime() - DAY_MS * 0.8;   // strictly earlier sighting
      const priors = [];
      for (const h of hist) {
        if (h.id === sig.id || h.cat !== cat) continue;
        if (typeof h.lat !== 'number' || typeof h.lon !== 'number') continue;
        if (parseDate(h.first_seen).getTime() > cutoff) continue;
        if (Math.abs(h.lat - ev.lat) <= 1 && Math.abs(h.lon - ev.lon) <= 1.5) priors.push(h);
      }
      if (priors.length >= PRIOR_MIN && priors.length <= PRIOR_MAX) {
        const p = priors[priors.length - 1];   // most recent earlier sighting (hist is ASC)
        const daysAgo = Math.max(1, Math.round((parseDate(sig.first_seen).getTime() - parseDate(p.first_seen).getTime()) / DAY_MS));
        clauses.push('similar ' + noun + ' activity was recorded in this same area before — most recently on ' + shortDate(p.first_seen) + ' (' + daysAgo + ' day' + (daysAgo === 1 ? '' : 's') + ' earlier)');
        gotRecurrence = true;
      }
    }
    // --- Recurrence (2): the same item keeps reappearing across days (ongoing) ---
    if (!gotRecurrence && sig) {
      const spanDays = Math.round((parseDate(sig.last_seen).getTime() - parseDate(sig.first_seen).getTime()) / DAY_MS);
      if (spanDays >= PERSIST_MIN_DAYS) {
        clauses.push('this signal first appeared on ' + shortDate(sig.first_seen) + ' (' + spanDays + ' days ago) and is still active');
      }
    }

    // --- Clustering: Nth NOTABLE incident affecting this region/sector this month ---
    if (ev.sev === 'HIGH' || ev.sev === 'CRITICAL') {
      const cl = clusters[bucket + '|' + cat];
      if (cl && cl.length >= CLUSTER_MIN && cl.length <= CLUSTER_MAX) {
        const idx = cl.indexOf(ev.id);
        if (idx >= 0) clauses.push('this is the ' + ordinalWord(idx + 1) + ' higher-severity ' + noun + ' incident affecting ' + bucket + ' this month (' + cl.length + ' so far)');
      }
    }

    // --- Build-up vs baseline: elevated air traffic toward this region (one note per region) ---
    if (cat === 'defence' && buildup[bucket] && !buildupUsed[bucket]) {
      const b = buildup[bucket];
      clauses.push('air traffic toward ' + bucket + ' is running above its 14-day average (' + b.latest + ' vs ~' + b.avg + ')');
      buildupUsed[bucket] = true;
    }

    if (clauses.length) {
      ev.note = 'Observation — ' + clauses.slice(0, 2).join('; ') + '. Automated pattern flag for a human to assess, not a prediction.';
    }
  }
}

// ===================== build served payload from D1 (last 7 days) =====================
async function buildPayload(env) {
  const sigRows = (await env.DB.prepare("SELECT * FROM signals WHERE last_seen >= datetime('now','-7 days') ORDER BY last_seen DESC LIMIT 300").all()).results || [];
  const vulnRows = (await env.DB.prepare("SELECT * FROM vulns WHERE last_seen >= datetime('now','-45 days') ORDER BY last_seen DESC LIMIT 20").all()).results || [];

  const EVENTS = sigRows.map(r => ({ id: r.id, cat: r.cat, sev: r.sev, region: r.region, lat: r.lat, lon: r.lon, time: relTime(parseDate(r.first_seen)), source: r.source, title: r.title, blurb: r.blurb, rec: r.rec, url: r.url }));

  // Memory-based insight notes: attach short, conservative observations where history warrants.
  try { await attachInsights(env, EVENTS); } catch (_) {}
  const VULNS = vulnRows.map(r => ({ sev: r.sev, name: r.name, cve: r.cve, impact: r.impact, cvss: r.cvss, status: r.status, published: relTime(parseDate(r.first_seen)), affected: r.affected, desc: r.descr, vector: r.vector, action: r.action }));

  // Region risk from current events, with trend vs previous run.
  let prev = null; try { prev = await env.SIGNALS.get('signals-latest', 'json'); } catch (_) {}
  const prevScores = {}; ((prev && prev.REGIONS) || []).forEach(r => { prevScores[r.name] = r.score; });
  const weight = { CRITICAL: 18, HIGH: 10, MEDIUM: 4 };
  const REGIONS = RISK_REGIONS.map(name => {
    let w = 0; for (const e of EVENTS) if ((e.region || '').indexOf(name) >= 0) w += (weight[e.sev] || 4);
    const score = Math.max(5, Math.min(100, Math.round(28 + w)));
    const p = prevScores[name]; let tr = 'up';
    if (typeof p === 'number') { tr = score >= p + 3 ? 'up' : score <= p - 3 ? 'down' : 'flat'; }
    const c = REGION_COORDS[name];
    return { name, score, tr, lat: c.lat, lon: c.lon };
  });
  return { generatedAt: nowIso(), counts: { events: EVENTS.length, vulns: VULNS.length }, EVENTS, VULNS, REGIONS };
}

// ===================== HTTP =====================
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, x-admin-token' };
function jsonRes(obj, status) { return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=60', ...CORS } }); }

async function handleAssistant(request, env) {
  let body; try { body = await request.json(); } catch (_) { body = {}; }
  const sys = String(body.sys || 'You are a helpful assistant for a threat-monitoring dashboard.').slice(0, 4000);
  const msgs = Array.isArray(body.messages) ? body.messages : [];
  const messages = [{ role: 'system', content: sys }];
  for (const m of msgs.slice(-12)) { const role = m.role === 'user' ? 'user' : 'assistant'; const content = String(m.text != null ? m.text : (m.content || '')).slice(0, 2000); if (content) messages.push({ role, content }); }
  const models = ['@cf/meta/llama-3.3-70b-instruct-fp8-fast', '@cf/meta/llama-3.1-8b-instruct'];
  let reply = '', lastErr = '';
  for (const model of models) { try { const ai = await env.AI.run(model, { messages, max_tokens: 400, temperature: 0.4 }); reply = String((ai && (ai.response != null ? ai.response : ai.result)) || '').trim(); if (reply) break; } catch (e) { lastErr = String((e && e.message) || e); } }
  if (!reply) return new Response(JSON.stringify({ reply: '', error: lastErr || 'no reply' }), { status: 502, headers: { 'content-type': 'application/json', ...CORS } });
  return new Response(JSON.stringify({ reply }), { headers: { 'content-type': 'application/json', ...CORS } });
}

export default {
  async scheduled(event, env, ctx) { ctx.waitUntil(collect(env)); },

  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    try {
      if (p === '/api/assistant' && request.method === 'POST') return handleAssistant(request, env);

      if (p === '/refresh') { const r = await collect(env, { forceMovement: url.searchParams.get('movement') === '1' }); return jsonRes({ ok: true, ...r }); }

      if (p === '/api/signals' || p === '/' || p === '/signals') {
        try { const payload = await buildPayload(env); return jsonRes(payload); }
        catch (e) { const body = await env.SIGNALS.get('signals-latest'); if (body) return new Response(body, { headers: { 'content-type': 'application/json', ...CORS } }); return jsonRes({ error: 'no data', detail: String(e && e.message || e) }, 503); }
      }

      if (p === '/api/movement') { const body = await env.SIGNALS.get('movement-latest'); return body ? new Response(body, { headers: { 'content-type': 'application/json', ...CORS } }) : jsonRes({ generatedAt: null, aircraft: [] }); }

      // Verification helper: just the signals that currently carry an insight note.
      if (p === '/api/insights') {
        const payload = await buildPayload(env);
        const withNotes = (payload.EVENTS || []).filter(e => e.note).map(e => ({ id: e.id, region: e.region, cat: e.cat, sev: e.sev, title: e.title, note: e.note }));
        return jsonRes({ generatedAt: payload.generatedAt, count: withNotes.length, insights: withNotes });
      }

      if (p === '/api/sources') {
        const rows = (await env.DB.prepare('SELECT key,name,type,category,region_rule,reliability,enabled,last_fetch,last_success,last_item_count,last_error,consecutive_errors,sort FROM sources ORDER BY sort').all()).results || [];
        const runs = (await env.DB.prepare('SELECT started_at,sources_ok,sources_failed,signals_added FROM ingest_runs ORDER BY id DESC LIMIT 1').all()).results || [];
        return jsonRes({ sources: rows, lastRun: runs[0] || null });
      }

      if (p === '/api/admin/source' && request.method === 'POST') {
        const token = request.headers.get('x-admin-token') || '';
        if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return jsonRes({ ok: false, error: 'unauthorized' }, 401);
        let body; try { body = await request.json(); } catch (_) { body = {}; }
        if (!body.key) return jsonRes({ ok: false, error: 'missing key' }, 400);
        await env.DB.prepare('UPDATE sources SET enabled=?2, updated_at=?3 WHERE key=?1').bind(body.key, body.enabled ? 1 : 0, nowIso()).run();
        const s = await getSource(env, body.key);
        return jsonRes({ ok: true, key: body.key, enabled: s ? s.enabled : null });
      }

      return new Response('Bluerydge World Monitor collector. Try /api/signals', { headers: CORS });
    } catch (e) {
      return jsonRes({ error: String((e && e.message) || e) }, 500);
    }
  },
};
