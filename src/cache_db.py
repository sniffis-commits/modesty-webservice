"""SQLite storage for the NSFW stack: analysis cache + known-domain DB.

One file, WAL mode, stdlib only: fast enough for a scan cache, and the
file itself IS the free downloadable database.

Provenance model
----------------
Every blocked/known domain points at a row in ``sources`` (id-based, not
free text) and optionally at a ``scan_types`` row:

* external blocklist -> ``sources.slug`` such as ``stevenblack-porn``
* our own live scan  -> ``sources.slug = 'self'`` + a scan type
  (``text`` / ``image`` / ``website`` / ``dns-badwords``)
* community review   -> ``sources.slug = 'community'``

``sources.display_name`` and ``sources.license`` carry the human-readable
name and the redistribution terms.  The legacy ``known_domains.source``
text column is retained for backwards compatibility and is kept in sync
with the source slug.
"""

import json
import os
import sqlite3
import threading
import time


def _text(value, limit=2000):
    """Stores a value as text: strings as they are, dicts as compact JSON.

    The reason is a sentence; the evidence is a small dict (the caller
    keeps it minimal).  Both are capped so no blob can sneak in.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        try:
            value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError):
            value = str(value)
    value = str(value)
    return value[:limit]


SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_cache (
  target TEXT PRIMARY KEY,
  scanner TEXT NOT NULL,
  rating INTEGER,
  error TEXT,
  details TEXT,
  elapsed REAL DEFAULT 0,
  created_utc REAL NOT NULL,
  expires_utc REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS known_domains (
  domain TEXT PRIMARY KEY,
  rating INTEGER NOT NULL,
  source TEXT NOT NULL,
  updated_utc REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  license TEXT,
  license_url TEXT,
  url TEXT,
  kind TEXT NOT NULL DEFAULT 'external',   -- self | external | community
  notes TEXT
);
CREATE TABLE IF NOT EXISTS scan_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT
);
CREATE TABLE IF NOT EXISTS domain_ratings (
  domain TEXT PRIMARY KEY,
  rating INTEGER NOT NULL,
  source_id INTEGER,
  scan_type_id INTEGER,
  reason TEXT,
  evidence TEXT,
  updated_utc REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS removed_domains (
  domain TEXT PRIMARY KEY,
  reason TEXT,
  removed_utc REAL NOT NULL,
  removed_by TEXT
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS media_hashes (
  hash TEXT PRIMARY KEY,
  algo TEXT NOT NULL DEFAULT 'sha256',
  rating INTEGER,
  error TEXT,
  details TEXT,
  elapsed REAL DEFAULT 0,
  bytes INTEGER DEFAULT 0,
  created_utc REAL NOT NULL,
  last_seen_utc REAL,
  media_type TEXT,
  mime_sniffed TEXT,
  mime_claimed TEXT,
  ext TEXT,
  container TEXT,
  duration_sec REAL,
  type_mismatch INTEGER DEFAULT 0,
  problem_count INTEGER DEFAULT 0,
  source_id INTEGER,
  scan_type_id INTEGER,
  reason TEXT,
  evidence TEXT,
  synthetic INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS media_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT NOT NULL UNIQUE,
  filename TEXT,
  original_path TEXT,
  size INTEGER DEFAULT 0,
  mtime REAL,
  device TEXT,
  first_seen_utc REAL NOT NULL,
  last_seen_utc REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_files_hash ON media_files (hash);
CREATE TABLE IF NOT EXISTS media_problems (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT NOT NULL,
  kind TEXT NOT NULL,          -- frame | subtitle
  timecode REAL,
  timecode_end REAL,
  frame_index INTEGER,
  line_no INTEGER,
  score REAL,
  rating INTEGER,
  keyword TEXT,
  text TEXT,
  class TEXT,                  -- the model's class (porn/hentai/sexy/...)
  created_utc REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_problems_hash ON media_problems (hash);

-- Phase 9: the IMDb Top 200 catalog (title + IMDb ID only, no hashes or
-- ratings of our own).  Kept in the product DB so the open API can answer
-- "what is this film?" without a second database.
CREATE TABLE IF NOT EXISTS title_catalog (
  imdb_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  ranking REAL,
  rank INTEGER,
  created_utc REAL NOT NULL
);
-- Results reported through POST /v1/sample, matched by IMDb ID.  The last
-- submission per (imdb_id, hash) is kept; this is a quality ledger, not a
-- source of official verdicts.
CREATE TABLE IF NOT EXISTS v1_scan_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  imdb_id TEXT NOT NULL,
  hash TEXT NOT NULL,
  rating INTEGER,
  verdict TEXT,
  media_type TEXT,
  filename TEXT,
  created_utc REAL NOT NULL,
  UNIQUE (imdb_id, hash)
);
CREATE INDEX IF NOT EXISTS idx_v1_submissions_imdb ON v1_scan_submissions (imdb_id);
"""

# (slug, display_name, license, license_url, url, kind, notes)
SOURCE_SEEDS = (
    ("self", "Self scan (our scanner)", "MIT (own code)", None, None, "self",
     "Domains blocked by a live scan of this project; the scan type is stored "
     "in known_domains.scan_type_id."),
    ("community", "Community submissions", "MIT (site terms)", None, None,
     "community", "Reviewer-approved community reports."),
    ("stevenblack-porn", "StevenBlack porn alternate",
     "MIT compilation (upstream lists vary)", "https://github.com/StevenBlack/hosts",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
     "external", "StevenBlack aggregates third-party lists; MIT covers the "
     "compilation, not necessarily every input."),
    ("firebog-prigent-adult", "Firebog mirror of Prigent-Adult",
     "Academic list; commercial redistribution unverified", None,
     "https://v.firebog.net/hosts/Prigent-Adult.txt", "external",
     "Université Toulouse Capitole list mirrored by Firebog; no formal OSI "
     "license on the mirror."),
    ("unknown", "Unknown / legacy import", "unknown", None, None, "external",
     "Placeholder for source values that predate the sources table."),
)

# (slug, display_name, description)
SCAN_TYPE_SEEDS = (
    ("text", "Text / meta keywords", "Adult keyword hit in page text or meta tags."),
    ("image", "Image model", "ONNX NSFW/gender/face image classification."),
    ("website", "Website scan", "Full website scan (text + images)."),
    ("dns-badwords", "DNS badwords", "Hostname matched the badword list; no fetch or model load."),
    ("dns-liveness", "DNS liveness", "DNS/whois liveness check only."),
    ("manual", "Manual / imported", "Imported or manually curated entry."),
    ("video", "Video scan", "Media scanner: sampled frames + subtitles."),
    ("audio", "Audio scan", "Media scanner: acoustic profile + subtitles."),
)

DEFAULT_SOURCE = "unknown"


class CacheDB:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # One connection shared across server threads: serialize use so
        # commits don't collide with "database is locked" (a soak test at
        # 12 concurrent scans reproduced exactly that).
        # Re-entrant: helpers such as backfill_source_ids() call sources()
        # while already holding the lock.
        self.lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self._seed_sources()
        self.conn.commit()

    # -- schema upgrades / seeds ---------------------------------------
    def _columns(self, table):
        return {row["name"] for row in
                self.conn.execute("PRAGMA table_info(%s)" % table)}

    def _ensure_column(self, table, column, ddl):
        if column not in self._columns(table):
            self.conn.execute("ALTER TABLE %s ADD COLUMN %s %s"
                              % (table, column, ddl))

    def _migrate(self):
        """Additive migrations: never rewrite the 4.7M-row domain table."""
        self._ensure_column("known_domains", "source_id", "INTEGER")
        self._ensure_column("known_domains", "scan_type_id", "INTEGER")
        self._ensure_column("known_domains", "reason", "TEXT")
        self._ensure_column("known_domains", "evidence", "TEXT")
        self._ensure_column("analysis_cache", "source_id", "INTEGER")
        self._ensure_column("analysis_cache", "scan_type_id", "INTEGER")
        self._ensure_column("domain_ratings", "reason", "TEXT")
        self._ensure_column("domain_ratings", "evidence", "TEXT")
        self._ensure_column("media_problems", "class", "TEXT")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_known_domains_source "
            "ON known_domains (source_id)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_known_domains_scan_type "
            "ON known_domains (scan_type_id)")
        self._migrate_media_hashes()

    def _migrate_media_hashes(self):
        """Media hashes never expire, and they carry the file type.

        The old table had a NOT NULL ``expires_utc`` (the analysis cache
        TTL) - media results live forever, so the table is rebuilt without
        it and the new type columns are added.
        """
        cols = self._columns("media_hashes")
        if "expires_utc" in cols:
            self.conn.execute("DROP TABLE IF EXISTS media_hashes_migrate")
            self.conn.execute(
                "CREATE TABLE media_hashes_migrate (\n"
                "  hash TEXT PRIMARY KEY,\n"
                "  algo TEXT NOT NULL DEFAULT 'sha256',\n"
                "  rating INTEGER,\n"
                "  error TEXT,\n"
                "  details TEXT,\n"
                "  elapsed REAL DEFAULT 0,\n"
                "  bytes INTEGER DEFAULT 0,\n"
                "  created_utc REAL NOT NULL,\n"
                "  last_seen_utc REAL,\n"
                "  media_type TEXT,\n"
                "  mime_sniffed TEXT,\n"
                "  mime_claimed TEXT,\n"
                "  ext TEXT,\n"
                "  container TEXT,\n"
                "  duration_sec REAL,\n"
                "  type_mismatch INTEGER DEFAULT 0,\n"
                "  problem_count INTEGER DEFAULT 0,\n"
                "  source_id INTEGER,\n"
                "  scan_type_id INTEGER,\n"
                "  reason TEXT,\n"
                "  evidence TEXT)")
            self.conn.execute(
                "INSERT OR REPLACE INTO media_hashes_migrate "
                "(hash, algo, rating, error, details, elapsed, bytes, created_utc) "
                "SELECT hash, algo, rating, error, details, elapsed, bytes, "
                "created_utc FROM media_hashes")
            self.conn.execute("DROP TABLE media_hashes")
            self.conn.execute("ALTER TABLE media_hashes_migrate "
                              "RENAME TO media_hashes")
        for column, ddl in (("last_seen_utc", "REAL"),
                            ("media_type", "TEXT"),
                            ("mime_sniffed", "TEXT"),
                            ("mime_claimed", "TEXT"),
                            ("ext", "TEXT"),
                            ("container", "TEXT"),
                            ("duration_sec", "REAL"),
                            ("type_mismatch", "INTEGER DEFAULT 0"),
                            ("problem_count", "INTEGER DEFAULT 0"),
                            ("source_id", "INTEGER"),
                            ("scan_type_id", "INTEGER"),
                            ("reason", "TEXT"),
                            ("evidence", "TEXT"),
                            ("synthetic", "INTEGER DEFAULT 0")):
            self._ensure_column("media_hashes", column, ddl)
        self._migrate_media_files()

    def _migrate_media_files(self):
        """`media_files.hash` must be UNIQUE - the upsert relies on it."""
        if "media_files" not in {row[0] for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}:
            return
        unique = False
        for row in self.conn.execute("PRAGMA index_list(media_files)"):
            if row[2]:                       # unique index
                for info in self.conn.execute("PRAGMA index_info(%s)" % row[1]):
                    if info[2] == "hash":
                        unique = True
        if unique:
            return
        self.conn.execute("DROP TABLE IF EXISTS media_files_migrate")
        self.conn.execute(
            "CREATE TABLE media_files_migrate (\n"
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            "  hash TEXT NOT NULL UNIQUE,\n"
            "  filename TEXT,\n"
            "  original_path TEXT,\n"
            "  size INTEGER DEFAULT 0,\n"
            "  mtime REAL,\n"
            "  device TEXT,\n"
            "  first_seen_utc REAL NOT NULL,\n"
            "  last_seen_utc REAL NOT NULL)")
        self.conn.execute(
            "INSERT OR REPLACE INTO media_files_migrate "
            "(id, hash, filename, original_path, size, mtime, device,"
            " first_seen_utc, last_seen_utc) "
            "SELECT id, hash, filename, original_path, size, mtime, device,"
            " first_seen_utc, last_seen_utc FROM media_files")
        self.conn.execute("DROP TABLE media_files")
        self.conn.execute("ALTER TABLE media_files_migrate "
                          "RENAME TO media_files")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_media_files_hash "
                          "ON media_files (hash)")

    def _seed_sources(self):
        sql = ("INSERT OR IGNORE INTO sources "
               "(slug, display_name, license, license_url, url, kind, notes) "
               "VALUES (?,?,?,?,?,?,?)")
        self.conn.executemany(sql, SOURCE_SEEDS)
        self.conn.executemany(
            "INSERT OR IGNORE INTO scan_types (slug, display_name, description) "
            "VALUES (?,?,?)", SCAN_TYPE_SEEDS)

    def source_id(self, slug):
        """Returns the source id for a slug, creating a placeholder if new."""
        slug = (slug or DEFAULT_SOURCE).strip().lower()
        with self.lock:
            row = self.conn.execute(
                "SELECT id FROM sources WHERE slug = ?", (slug,)).fetchone()
            if row:
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO sources (slug, display_name, license, kind, notes) "
                "VALUES (?,?,?,?,?)",
                (slug, slug, "unknown", "external",
                 "Auto-created from a legacy/free-text source value."))
            self.conn.commit()
            return cur.lastrowid

    def scan_type_id(self, slug):
        """Returns the scan-type id for a slug, creating a placeholder."""
        if not slug:
            return None
        slug = str(slug).strip().lower()
        with self.lock:
            row = self.conn.execute(
                "SELECT id FROM scan_types WHERE slug = ?", (slug,)).fetchone()
            if row:
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO scan_types (slug, display_name) VALUES (?,?)",
                (slug, slug))
            self.conn.commit()
            return cur.lastrowid

    def source_info(self, source_id=None, slug=None):
        """Returns {id, slug, display_name, license, ...} or None."""
        with self.lock:
            if source_id is not None:
                row = self.conn.execute(
                    "SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
            elif slug is not None:
                row = self.conn.execute(
                    "SELECT * FROM sources WHERE slug = ?", (slug,)).fetchone()
            else:
                row = None
        return dict(row) if row else None

    def scan_type_info(self, scan_type_id=None, slug=None):
        with self.lock:
            if scan_type_id is not None:
                row = self.conn.execute(
                    "SELECT * FROM scan_types WHERE id = ?", (scan_type_id,)).fetchone()
            elif slug is not None:
                row = self.conn.execute(
                    "SELECT * FROM scan_types WHERE slug = ?", (slug,)).fetchone()
            else:
                row = None
        return dict(row) if row else None

    def sources(self):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def scan_types(self):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM scan_types ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def removed_domains(self):
        """Domains an admin removed - a rebuild must not bring them back."""
        try:
            rows = self.conn.execute("SELECT domain FROM removed_domains").fetchall()
        except sqlite3.Error:
            return set()
        return {row["domain"] for row in rows}

    def backfill_source_ids(self):
        """One-time: map legacy known_domains.source text to sources.id."""
        total = 0
        with self.lock:
            for source in self.sources():
                cur = self.conn.execute(
                    "UPDATE known_domains SET source_id = ? "
                    "WHERE source_id IS NULL AND source = ?",
                    (source["id"], source["slug"]))
                total += cur.rowcount
            self.conn.commit()
        return total

    # -- analysis cache -------------------------------------------------
    def get_cached(self, target):
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM analysis_cache WHERE target = ?", (target,)).fetchone()
        if row and row["expires_utc"] > time.time() and row["rating"] is not None:
            return dict(row)
        return None

    def put_cached(self, target, scanner, rating, error, details_json,
                   elapsed, ttl_days=30, source_id=None, scan_type_id=None):
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO analysis_cache "
                "(target, scanner, rating, error, details, elapsed,"
                " created_utc, expires_utc, source_id, scan_type_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (target, scanner, rating, error, details_json, elapsed, now,
                 now + ttl_days * 86400, source_id, scan_type_id))
            self.conn.commit()

    # -- known domains (DNS-blocker imports + manual entries) -----------
    def lookup_domain(self, domain):
        """Exact match, then parent walk (sub.example.com -> example.com).

        Returns provenance as ids *and* display data.  Legacy rows whose
        ``source_id`` has not been backfilled still resolve via the
        ``source`` slug text.
        """
        domain = (domain or "").lower().strip().rstrip(".")
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            with self.lock:
                row = self.conn.execute(
                    "SELECT k.rating, k.source, k.source_id, k.scan_type_id,"
                    " k.reason, k.evidence,"
                    " COALESCE(s.id, s2.id) AS resolved_source_id,"
                    " COALESCE(s.slug, s2.slug, k.source) AS source_slug,"
                    " COALESCE(s.display_name, s2.display_name) AS source_name,"
                    " COALESCE(s.license, s2.license) AS source_license,"
                    " t.slug AS scan_type, t.display_name AS scan_type_name"
                    " FROM known_domains k"
                    " LEFT JOIN sources s ON s.id = k.source_id"
                    " LEFT JOIN sources s2 ON s2.slug = k.source"
                    " LEFT JOIN scan_types t ON t.id = k.scan_type_id"
                    " WHERE k.domain = ?", (candidate,)).fetchone()
            if row:
                source_slug = row["source_slug"] or row["source"]
                return {
                    "domain": candidate,
                    "rating": row["rating"],
                    "source": source_slug,
                    "source_id": row["resolved_source_id"],
                    "source_name": row["source_name"] or source_slug,
                    "license": row["source_license"],
                    "scan_type": row["scan_type"],
                    "scan_type_id": row["scan_type_id"],
                    "reason": row["reason"],
                    "evidence": row["evidence"],
                }
        return None

    def add_domains(self, rows):
        """rows: iterable of (domain, rating, source[, scan_type]).

        ``source`` may be a slug (recommended) or a numeric source id.
        ``scan_type`` is an optional slug/id.  Returns insert count.
        """
        now = time.time()
        source_cache = {}
        type_cache = {}
        data = []
        for row in rows:
            domain, rating, source = row[0], row[1], row[2]
            scan_type = row[3] if len(row) > 3 else None
            if isinstance(source, int):
                src_id = source
                src_slug = None
            else:
                src_slug = str(source)
                if src_slug not in source_cache:
                    source_cache[src_slug] = self.source_id(src_slug)
                src_id = source_cache[src_slug]
            if scan_type is None:
                type_id = None
            elif isinstance(scan_type, int):
                type_id = scan_type
            else:
                if scan_type not in type_cache:
                    type_cache[scan_type] = self.scan_type_id(scan_type)
                type_id = type_cache[scan_type]
            data.append((domain, rating, src_slug or str(source), src_id,
                         type_id, now))
        with self.lock:
            cur = self.conn.executemany(
                "INSERT OR REPLACE INTO known_domains "
                "(domain, rating, source, source_id, scan_type_id, updated_utc) "
                "VALUES (?,?,?,?,?,?)", data)
            self.conn.commit()
        return cur.rowcount

    def record_self_block(self, domain, rating=10, scan_type="website",
                          reason=None, evidence=None):
        """Records a domain blocked by our own scan, preserving an existing
        external source if the domain was already known.

        ``reason`` is the human explanation ("why is this blocked?") and
        ``evidence`` the minimal machine-readable facts behind it.  Both
        are admin-only (the public API never returns them).
        """
        domain = (domain or "").lower().strip().rstrip(".")
        if not domain:
            return False
        now = time.time()
        src_id = self.source_id("self")
        type_id = self.scan_type_id(scan_type)
        with self.lock:
            self.conn.execute(
                "INSERT INTO known_domains "
                "(domain, rating, source, source_id, scan_type_id, reason, "
                "evidence, updated_utc) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET "
                " rating = excluded.rating,"
                " updated_utc = excluded.updated_utc,"
                " scan_type_id = COALESCE(excluded.scan_type_id,"
                "                          known_domains.scan_type_id),"
                " reason = COALESCE(excluded.reason, known_domains.reason),"
                " evidence = COALESCE(excluded.evidence, known_domains.evidence)",
                (domain, int(rating), "self", src_id, type_id,
                 _text(reason), _text(evidence), now))
            self.conn.commit()
        return True

    def record_scan_result(self, domain, rating, scan_type="website",
                           reason=None, evidence=None):
        """Records the unsafe-content rating we measured for a domain.

        `known_domains` holds the *blocked* list (rating 10 mostly); this
        table holds every rating our own scans produced — including the
        rating 1 results — so the site and the API can answer "what is this
        domain rated?" instead of "not in the open DB".
        """
        domain = (domain or "").lower().strip().rstrip(".")
        if not domain or rating is None:
            return False
        now = time.time()
        src_id = self.source_id("self")
        type_id = self.scan_type_id(scan_type)
        with self.lock:
            self.conn.execute(
                "INSERT INTO domain_ratings "
                "(domain, rating, source_id, scan_type_id, reason, evidence, "
                "updated_utc) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET "
                " rating = excluded.rating,"
                " source_id = excluded.source_id,"
                " scan_type_id = excluded.scan_type_id,"
                " reason = COALESCE(excluded.reason, domain_ratings.reason),"
                " evidence = COALESCE(excluded.evidence, domain_ratings.evidence),"
                " updated_utc = excluded.updated_utc",
                (domain, int(rating), src_id, type_id,
                 _text(reason), _text(evidence), now))
            self.conn.commit()
        return True

    def lookup_rating(self, domain):
        """The unsafe-content rating of a domain: known_domains first (blocks),
        then our own scan results (any rating, including rating 1)."""
        domain = (domain or "").lower().strip().rstrip(".")
        if not domain:
            return None
        hit = self.lookup_domain(domain)
        if hit:
            hit["blocked"] = hit["rating"] is not None and hit["rating"] >= 10
            return hit
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            with self.lock:
                row = self.conn.execute(
                    "SELECT r.domain, r.rating, r.source_id, r.scan_type_id,"
                    " r.reason, r.evidence,"
                    " s.slug AS source_slug, s.display_name AS source_name,"
                    " s.license AS source_license,"
                    " t.slug AS scan_type, t.display_name AS scan_type_name"
                    " FROM domain_ratings r"
                    " LEFT JOIN sources s ON s.id = r.source_id"
                    " LEFT JOIN scan_types t ON t.id = r.scan_type_id"
                    " WHERE r.domain = ?", (candidate,)).fetchone()
            if row:
                return {"domain": candidate, "rating": row["rating"],
                        "source": row["source_slug"] or "self",
                        "source_id": row["source_id"],
                        "source_name": row["source_name"] or "Self scan (our scanner)",
                        "license": row["source_license"],
                        "scan_type": row["scan_type"],
                        "scan_type_id": row["scan_type_id"],
                        "reason": row["reason"],
                        "evidence": row["evidence"],
                        "blocked": row["rating"] >= 10}
        return None

    # -- content hashes (same bytes, any name/URL -> same result) -----
    def get_by_hash(self, hex_digest):
        """Media results never expire: the same bytes are the same file."""
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM media_hashes WHERE hash = ?",
                ((hex_digest or "").lower(),)).fetchone()
        if row and row["rating"] is not None:
            return dict(row)
        return None

    def get_community_ratings(self, hex_digest):
        """Returns community-approved ratings for a hash, or an empty list.

        The old query selected ``source`` and ``verdict`` columns that the
        current ``media_hashes`` schema does not have (it stores a
        ``source_id`` and derives the verdict word from the rating).  That
        made every ``GET /v1/hash/<sha>`` crash with "no such column" and
        close the connection without a response.  Join ``sources`` by slug
        instead and derive the verdict word from the rating.
        """
        with self.lock:
            rows = self.conn.execute(
                "SELECT m.rating AS rating, COUNT(*) AS cnt "
                "FROM media_hashes m "
                "JOIN sources s ON s.id = m.source_id "
                "WHERE m.hash = ? AND s.slug = 'community' "
                "GROUP BY m.rating",
                ((hex_digest or "").lower(),)).fetchall()
        try:
            from nsfw_scanner import verdict_for
        except Exception:
            verdict_for = None
        out = []
        for row in rows:
            out.append({
                "rating": row["rating"],
                "verdict": verdict_for(row["rating"]) if verdict_for else None,
                "count": row["cnt"],
            })
        return out

    def put_hash(self, hex_digest, rating, error, details_json, elapsed,
                 size=0, algo="sha256", ttl_days=None, media_type=None,
                 mime_sniffed=None, mime_claimed=None, ext=None,
                 container=None, duration_sec=None, type_mismatch=False,
                 problem_count=0, source_id=None, scan_type_id=None,
                 reason=None, evidence=None, synthetic=False):
        """Stores a scan result for a content hash (no expiry)."""
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO media_hashes "
                "(hash, algo, rating, error, details, elapsed, bytes,"
                " created_utc, last_seen_utc, media_type, mime_sniffed,"
                " mime_claimed, ext, container, duration_sec, type_mismatch,"
                " problem_count, source_id, scan_type_id, reason, evidence,"
                " synthetic) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (hex_digest.lower(), algo, rating, error, details_json, elapsed,
                 size, now, now, media_type, mime_sniffed, mime_claimed, ext,
                 container, duration_sec, 1 if type_mismatch else 0,
                 int(problem_count or 0), source_id, scan_type_id,
                 _text(reason), _text(evidence), 1 if synthetic else 0))
            self.conn.commit()

    def stats(self):
        with self.lock:
            out = {
                "cached_targets": self.conn.execute(
                    "SELECT COUNT(*) FROM analysis_cache").fetchone()[0],
                "hashed_media": self.conn.execute(
                    "SELECT COUNT(*) FROM media_hashes").fetchone()[0],
                "media_problems": self.conn.execute(
                    "SELECT COUNT(*) FROM media_problems").fetchone()[0],
                "known_domains": self.conn.execute(
                    "SELECT COUNT(*) FROM known_domains").fetchone()[0],
                "sources": self.conn.execute(
                    "SELECT COUNT(*) FROM sources").fetchone()[0],
                "scan_types": self.conn.execute(
                    "SELECT COUNT(*) FROM scan_types").fetchone()[0],
            }
        out["db_bytes"] = os.path.getsize(self.path)
        return out

    # -- media bookkeeping ---------------------------------------------
    def put_media_file(self, hex_digest, filename=None, original_path=None,
                       size=0, mtime=None, device=None):
        """Records the file name behind a hash.  **Admin only** - file names
        are personal data and never leave this table."""
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT INTO media_files "
                "(hash, filename, original_path, size, mtime, device,"
                " first_seen_utc, last_seen_utc) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(hash) DO UPDATE SET "
                " filename = COALESCE(excluded.filename, media_files.filename),"
                " original_path = COALESCE(excluded.original_path, media_files.original_path),"
                " size = excluded.size, mtime = excluded.mtime,"
                " last_seen_utc = excluded.last_seen_utc",
                (hex_digest.lower(), filename, original_path, int(size or 0),
                 mtime, device, now, now))
            self.conn.commit()
        return True

    def media_files(self, hex_digest=None, limit=100):
        """The admin-only file list behind the hashes."""
        sql = "SELECT * FROM media_files"
        params = []
        if hex_digest:
            sql += " WHERE hash = ?"
            params.append(hex_digest.lower())
        sql += " ORDER BY last_seen_utc DESC LIMIT ?"
        params.append(int(limit))
        with self.lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def put_media_problems(self, hex_digest, problems):
        """Stores the problem areas of a media file (frame / subtitle hits)."""
        now = time.time()
        rows = []
        for problem in problems or []:
            rows.append((hex_digest.lower(), problem.get("kind") or "frame",
                         problem.get("timecode"), problem.get("timecode_end"),
                         problem.get("frame_index"), problem.get("line_no"),
                         problem.get("score"), problem.get("rating"),
                         problem.get("keyword"), (problem.get("text") or "")[:400],
                         (problem.get("class") or "")[:20],
                         now))
        with self.lock:
            self.conn.execute("DELETE FROM media_problems WHERE hash = ?",
                              (hex_digest.lower(),))
            self.conn.executemany(
                "INSERT INTO media_problems "
                "(hash, kind, timecode, timecode_end, frame_index, line_no,"
                " score, rating, keyword, text, class, created_utc) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.conn.commit()
        return len(rows)

    def media_problems(self, hex_digest, limit=500):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM media_problems WHERE hash = ? "
                "ORDER BY timecode LIMIT ?",
                (hex_digest.lower(), int(limit))).fetchall()
        return [dict(row) for row in rows]

    # -- Phase 9: IMDb title catalog + open-API submissions -------------
    def seed_title_catalog(self, rows):
        """Seeds (rank, imdb_id, title) rows; never overwrites existing ones.

        The catalog is metadata only: no hash and no rating of ours.  A film
        stays unrated until a real release is scanned.
        """
        now = time.time()
        added = 0
        with self.lock:
            for rank, imdb_id, title in rows:
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO title_catalog "
                    "(imdb_id, title, rank, created_utc) VALUES (?,?,?,?)",
                    (imdb_id, title, int(rank), now))
                added += cur.rowcount
            self.conn.commit()
        return added

    def get_title_catalog(self, imdb_id=None, limit=200):
        """One catalog row by IMDb ID, or the first ``limit`` of them."""
        with self.lock:
            if imdb_id:
                row = self.conn.execute(
                    "SELECT * FROM title_catalog WHERE imdb_id = ?",
                    (imdb_id,)).fetchone()
                return dict(row) if row else None
            rows = self.conn.execute(
                "SELECT * FROM title_catalog ORDER BY rank LIMIT ?",
                (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    def record_v1_submission(self, imdb_id, hex_digest, rating, verdict,
                             media_type=None, filename=None):
        """Records a result reported through POST /v1/sample, by IMDb ID."""
        now = time.time()
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO v1_scan_submissions "
                "(imdb_id, hash, rating, verdict, media_type, filename,"
                " created_utc) VALUES (?,?,?,?,?,?,?)",
                (imdb_id, hex_digest.lower(), rating, verdict,
                 media_type, _text(filename, 255), now))
            self.conn.commit()

    def get_v1_submissions(self, imdb_id, limit=20):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM v1_scan_submissions WHERE imdb_id = ? "
                "ORDER BY created_utc DESC LIMIT ?",
                (imdb_id, int(limit))).fetchall()
        return [dict(row) for row in rows]

    def close(self):
        with self.lock:
            self.conn.close()
