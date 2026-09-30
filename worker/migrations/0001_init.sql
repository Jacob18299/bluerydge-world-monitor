-- Bluerydge World Monitor — Phase 3 persistent memory schema.
-- Safe to re-run (IF NOT EXISTS / INSERT OR IGNORE).

-- The master switchboard: one row per feed. Add a new source by inserting a row here.
CREATE TABLE IF NOT EXISTS sources (
  key                TEXT PRIMARY KEY,            -- stable slug, e.g. 'cisa_kev'
  name               TEXT NOT NULL,               -- display name
  type               TEXT NOT NULL,               -- parser: kev | nvd_enrich | rss | gdelt | opensky
  url                TEXT,                        -- feed URL (if applicable)
  category           TEXT,                        -- default cat: cyber|vuln|geo|defence|infra
  region_rule        TEXT DEFAULT 'auto',         -- 'auto' or 'fixed:<Bucket>'
  reliability        TEXT DEFAULT 'reputable',    -- official|reputable|aggregator|experimental
  enabled            INTEGER NOT NULL DEFAULT 1,  -- 1 = on, 0 = off (admin toggle)
  config             TEXT DEFAULT '{}',           -- JSON: extra params (limit, query, bbox, source label, cat)
  last_fetch         TEXT,                        -- ISO time of last attempt
  last_success       TEXT,                        -- ISO time of last successful fetch
  last_item_count    INTEGER DEFAULT 0,           -- items returned last run
  last_error         TEXT,                        -- last error message (NULL if healthy)
  consecutive_errors INTEGER DEFAULT 0,
  sort               INTEGER DEFAULT 100,
  created_at         TEXT DEFAULT (datetime('now')),
  updated_at         TEXT DEFAULT (datetime('now'))
);

-- Long-term memory of every event. Insert once by stable id; later sightings bump last_seen.
CREATE TABLE IF NOT EXISTS signals (
  id          TEXT PRIMARY KEY,
  source_key  TEXT,
  cat         TEXT,
  sev         TEXT,
  region      TEXT,
  lat         REAL,
  lon         REAL,
  title       TEXT,
  blurb       TEXT,
  rec         TEXT,
  source      TEXT,
  url         TEXT,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  seen_count  INTEGER NOT NULL DEFAULT 1,
  extra       TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_signals_last_seen ON signals(last_seen);
CREATE INDEX IF NOT EXISTS idx_signals_cat       ON signals(cat);
CREATE INDEX IF NOT EXISTS idx_signals_source    ON signals(source_key);

-- Long-term memory of vulnerabilities.
CREATE TABLE IF NOT EXISTS vulns (
  cve         TEXT PRIMARY KEY,
  source_key  TEXT,
  sev         TEXT,
  name        TEXT,
  cvss        TEXT,
  status      TEXT,
  impact      TEXT,
  affected    TEXT,
  descr       TEXT,
  vector      TEXT,
  action      TEXT,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  seen_count  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_vulns_last_seen ON vulns(last_seen);

-- Tiny tallies per run -> baselines for movement anomaly flags.
CREATE TABLE IF NOT EXISTS movement_counts (
  ts      TEXT NOT NULL,
  region  TEXT NOT NULL,
  kind    TEXT NOT NULL,   -- mil_air | cargo_air | other_air | vessel
  count   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_move_region_kind_ts ON movement_counts(region, kind, ts);

-- One row per cron run, for the Admin health view.
CREATE TABLE IF NOT EXISTS ingest_runs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at      TEXT,
  finished_at     TEXT,
  sources_ok      INTEGER DEFAULT 0,
  sources_failed  INTEGER DEFAULT 0,
  signals_added   INTEGER DEFAULT 0,
  signals_updated INTEGER DEFAULT 0,
  note            TEXT
);

-- ---- Seed the sources switchboard (idempotent) ----
INSERT OR IGNORE INTO sources (key, name, type, url, category, region_rule, reliability, enabled, config, sort) VALUES
 ('cisa_kev',  'CISA Known Exploited Vulnerabilities', 'kev',     'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'vuln',    'auto',             'official',     1, '{"limit":12,"pins":5}',                 10),
 ('nvd',       'NVD (CVSS enrichment)',                'nvd_enrich','https://services.nvd.nist.gov/rest/json/2.0/cves/2.0',                              'vuln',    'auto',             'official',     1, '{"budget":5}',                          20),
 ('thn',       'The Hacker News',                      'rss',     'https://feeds.feedburner.com/TheHackersNews',                                       'cyber',   'auto',             'reputable',    1, '{"limit":6}',                           30),
 ('bleeping',  'BleepingComputer',                     'rss',     'https://www.bleepingcomputer.com/feed/',                                            'cyber',   'auto',             'reputable',    1, '{"limit":6}',                           40),
 ('cisa_adv',  'CISA Advisories',                      'rss',     'https://www.cisa.gov/cybersecurity-advisories/all.xml',                             'cyber',   'fixed:North America','official',   1, '{"limit":5}',                           50),
 ('acsc',      'ACSC (Australia)',                     'rss',     'https://www.cyber.gov.au/rss/alerts',                                               'defence', 'fixed:Australia',  'official',     1, '{"limit":5,"fallbackUrl":"https://www.cyber.gov.au/rss/news"}', 60),
 ('gdelt',     'GDELT (geopolitical)',                 'gdelt',   'https://api.gdeltproject.org/api/v2/doc/doc',                                       'geo',     'auto',             'aggregator',   1, '{"limit":12}',                          70),
 ('opensky',   'OpenSky Network (aircraft)',           'opensky', 'https://opensky-network.org/api/states/all',                                        'defence', 'auto',             'experimental', 1, '{"layer":"aircraft","anomaly":true}',   80);
