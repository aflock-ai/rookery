-- D1 schema for the edge capture sidecar (functions/_middleware.ts) and the
-- behavioral beacon (functions/cl/e.ts). D1 is OPTIONAL — both functions also
-- write to Workers Analytics Engine (binding ANALYTICS) and always log; D1 is the
-- exact, long-retention store (Workers Analytics Engine keeps only ~3 months).
-- Apply:  wrangler d1 execute cilock-analytics --remote --file=schema.sql

-- Full page loads (entry points), captured server-side by the middleware.
CREATE TABLE IF NOT EXISTS visits (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,        -- epoch ms
  visitor_id    TEXT,                    -- first-party persistent id (cl_vid) -> repeat visitors
  session_id    TEXT,
  is_returning  INTEGER,                 -- 1 if cl_vid already existed on this request ("returning" is a SQLite reserved word)
  ip            TEXT,
  asn           INTEGER,
  as_org        TEXT,                    -- Cloudflare asOrganization
  country       TEXT,
  region        TEXT,
  city          TEXT,
  network_class TEXT,                    -- residential|datacenter|apple_relay|cgnat|corporate|mobile|tor|unknown
  bot_class     TEXT,                    -- human|verified_crawler|crawler|suspected_bot
  tls_fp        TEXT,                    -- self-computed JA4-style TLS fingerprint
  bot_score     INTEGER,                 -- Cloudflare bot score (Enterprise only; null otherwise)
  path          TEXT,
  referer       TEXT,
  user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS idx_visits_ts      ON visits(ts);
CREATE INDEX IF NOT EXISTS idx_visits_visitor ON visits(visitor_id);
CREATE INDEX IF NOT EXISTS idx_visits_session ON visits(session_id);
CREATE INDEX IF NOT EXISTS idx_visits_asorg   ON visits(as_org);

-- Behavioral events from the first-party client beacon: in-SPA route changes
-- (pv), engagement on tab-hide (eng, with dwell + scroll), and search queries.
CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,
  visitor_id    TEXT,
  session_id    TEXT,
  type          TEXT,                    -- pv|eng|search
  path          TEXT,
  query         TEXT,                    -- search query (type=search only)
  dwell_ms      INTEGER,                 -- time on page (eng)
  scroll        INTEGER,                 -- max scroll depth 0..100 (eng)
  vw            INTEGER,                 -- viewport width  (device-class hint)
  vh            INTEGER,                 -- viewport height
  country       TEXT,
  network_class TEXT,
  bot_class     TEXT,
  referer       TEXT,
  ua            TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_visitor ON events(visitor_id);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_path    ON events(path);
