"""Scan queue: add sites, process one batch, or run as a background worker.

The queue lives in the site's app DB (``packages/nsfw-website/data/app.sqlite``)
so the PHP scanner page and this CLI share it; provenance and blocked
domains are written to the product DB (``nsfw.sqlite``).

Pipeline per item:

1. **DNS badwords** — an obviously adult hostname (``pornhub.com``,
   ``xxx-...``) is rated 10 from the name alone: no fetch, no ONNX models.
2. **DNS liveness** — dead/parked domains are dropped before any scan.
3. **Full scan** — only for ``kind=url`` and only if the domain is alive.
   A rating-10 result is recorded back into ``known_domains`` with
   ``source=self`` + the scan type that decided it.

Usage (from the repo root)::

    run.bat scan-add pornhub.com
    run.bat scan-once                       # process one batch, then exit
    run.bat scan-worker                     # loop forever (background job)
    run.bat scan-queue                      # show the queue

Direct::

    python packages/nsfw-webservice/src/scan_queue.py once --limit 10
    python packages/nsfw-webservice/src/scan_queue.py add example.com --kind url
    python packages/nsfw-webservice/src/scan_queue.py worker --interval 30

Where to run the background job: ``run.bat scan-worker`` in a service
window, Windows Task Scheduler (``schtasks``), or cron on Linux:

    */5 * * * * cd /path/to/NSFW && ./run.sh scan-once --limit 50
"""

import argparse
import hashlib
import os
import sqlite3
import sys
import tempfile
import time
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "nsfw-lib", "src")))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "nsfw-webservice", "src")))

import check_domains  # noqa: E402
import nsfw_scanner  # noqa: E402
from cache_db import CacheDB  # noqa: E402

QUEUE_COLUMNS = (
    ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("target", "TEXT NOT NULL UNIQUE"),
    ("kind", "TEXT NOT NULL DEFAULT 'url'"),
    ("status", "TEXT NOT NULL DEFAULT 'pending'"),
    ("priority", "INTEGER NOT NULL DEFAULT 0"),
    ("source_id", "INTEGER"),
    ("scan_type_id", "INTEGER"),
    ("rating", "INTEGER"),
    ("outcome", "TEXT"),
    ("liveness", "TEXT"),
    ("error", "TEXT"),
    ("note", "TEXT"),
    ("added_utc", "REAL"),
    ("started_utc", "REAL"),
    ("finished_utc", "REAL"),
    ("attempts", "INTEGER NOT NULL DEFAULT 0"),
)

QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'url',
  status TEXT NOT NULL DEFAULT 'pending',
  priority INTEGER NOT NULL DEFAULT 0,
  source_id INTEGER,
  scan_type_id INTEGER,
  rating INTEGER,
  outcome TEXT,
  liveness TEXT,
  error TEXT,
  note TEXT,
  added_utc REAL,
  started_utc REAL,
  finished_utc REAL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scan_queue_status ON scan_queue (status, priority);
"""

VALID_KINDS = ("url", "dns", "badwords", "media")
KIND_HELP = ("url = badwords + liveness + full scan, "
             "dns = badwords + liveness only, "
             "badwords = name check only, "
             "media = local video/audio file or a media URL")


def default_product_db():
    return os.path.normpath(os.path.join(HERE, "..", "data", "nsfw.sqlite"))


def default_app_db():
    return os.path.normpath(os.path.join(HERE, "..", "..", "nsfw-website",
                                         "data", "app.sqlite"))


# ------------------------------------------------------------------ queue --

def app_conn(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(QUEUE_SCHEMA)
    _migrate_queue(conn)
    conn.commit()
    return conn


def _migrate_queue(conn):
    """Additive migration: the queue keeps two separate facts per item.

    ``outcome``  — what the pipeline did (scanned / blocked-badwords / …)
    ``liveness`` — whether the domain still exists (alive / dead / parked)

    Older queue files stored the outcome in a ``verdict`` column; the table
    is rebuilt without it (the column is copied into ``outcome`` first).
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_queue)")}
    if "verdict" in cols:
        def pick(name, default=None):
            if name not in cols:
                return "NULL"
            if default is None:
                return name
            return "COALESCE(%s, %s)" % (name, default)

        outcome_expr = ("COALESCE(outcome, verdict)" if "outcome" in cols
                        else "verdict")
        select = ", ".join([
            pick("id"), pick("target", "''"), pick("kind", "'url'"),
            pick("status", "'pending'"), pick("priority", "0"),
            pick("source_id"), pick("scan_type_id"), pick("rating"),
            outcome_expr, pick("liveness"), pick("error"), pick("note"),
            pick("added_utc"), pick("started_utc"), pick("finished_utc"),
            pick("attempts", "0")])
        conn.execute("DROP TABLE IF EXISTS scan_queue_migrate")
        conn.execute(
            "CREATE TABLE scan_queue_migrate (\n%s)" % ",\n".join(
                "  %s %s" % (name, ddl) for name, ddl in QUEUE_COLUMNS))
        conn.execute(
            "INSERT INTO scan_queue_migrate (id, target, kind, status, priority,"
            " source_id, scan_type_id, rating, outcome, liveness, error, note,"
            " added_utc, started_utc, finished_utc, attempts) "
            "SELECT %s FROM scan_queue" % select)
        conn.execute("DROP TABLE scan_queue")
        conn.execute("ALTER TABLE scan_queue_migrate RENAME TO scan_queue")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_queue_status "
                     "ON scan_queue (status, priority)")
        cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_queue)")}
    if "outcome" not in cols:
        conn.execute("ALTER TABLE scan_queue ADD COLUMN outcome TEXT")
    if "liveness" not in cols:
        conn.execute("ALTER TABLE scan_queue ADD COLUMN liveness TEXT")


def normalize_target(target, kind="url"):
    text = (target or "").strip()
    if kind == "media":
        # A local path keeps its case (the file name is stored with it);
        # a URL is only trimmed.
        if text.lower().startswith(("http://", "https://")):
            return text.rstrip("/")
        return text
    text = text.lower()
    text = text.split("://", 1)[-1]
    return text.rstrip("/")


def host_of(target):
    text = normalize_target(target)
    parsed = urlparse("//" + text)
    return (parsed.hostname or text.split("/", 1)[0]).rstrip(".")


def queue_add(conn, target, kind="url", note="", priority=0):
    target = normalize_target(target, kind)
    if not target:
        raise ValueError("empty target")
    kind = kind if kind in VALID_KINDS else "url"
    if kind == "media" and not (os.path.isfile(target) or
                                target.lower().startswith(("http://", "https://"))):
        raise ValueError("media targets must be a local file or an http(s) URL")
    row = conn.execute("SELECT id, status FROM scan_queue WHERE target = ?",
                       (target,)).fetchone()
    now = time.time()
    if row:
        if row["status"] in ("done", "error", "skipped"):
            # Re-adding a finished target queues it for another run.
            conn.execute(
                "UPDATE scan_queue SET kind = ?, note = ?, priority = ?,"
                " status = 'pending', rating = NULL, outcome = NULL,"
                " liveness = NULL, error = NULL, started_utc = NULL,"
                " finished_utc = NULL WHERE id = ?",
                (kind, note[:400], int(priority), row["id"]))
        else:
            conn.execute(
                "UPDATE scan_queue SET kind = ?, note = ?, priority = ? WHERE id = ?",
                (kind, note[:400], int(priority), row["id"]))
        conn.commit()
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO scan_queue (target, kind, status, priority, note, added_utc) "
        "VALUES (?,?,?,?,?,?)",
        (target, kind, "pending", int(priority), note[:400], now))
    conn.commit()
    return cur.lastrowid, True


def queue_claim(conn, limit, stale_seconds=7200):
    """Atomically claims up to `limit` pending rows and marks them running.

    Rows that were left 'running' by a killed worker (older than
    `stale_seconds`) are put back into the queue first, so a crash never
    strands an item.
    """
    with conn:                     # single transaction
        conn.execute(
            "UPDATE scan_queue SET status = 'pending', started_utc = NULL "
            "WHERE status = 'running' AND started_utc IS NOT NULL "
            "AND started_utc < ?", (time.time() - stale_seconds,))
        rows = conn.execute(
            "SELECT * FROM scan_queue WHERE status = 'pending' "
            "ORDER BY priority DESC, id ASC LIMIT ?", (int(limit),)).fetchall()
        if not rows:
            return []
        ids = [r["id"] for r in rows]
        conn.executemany(
            "UPDATE scan_queue SET status = 'running', started_utc = ?,"
            " attempts = attempts + 1 WHERE id = ?",
            [(time.time(), i) for i in ids])
    return rows


def queue_finish(conn, row_id, status, rating=None, outcome=None, error=None,
                 source_id=None, scan_type_id=None, liveness=None, note=None):
    conn.execute(
        "UPDATE scan_queue SET status = ?, rating = ?, outcome = ?, error = ?,"
        " source_id = COALESCE(?, source_id),"
        " scan_type_id = COALESCE(?, scan_type_id),"
        " liveness = COALESCE(?, liveness),"
        " finished_utc = ?, note = COALESCE(?, note) WHERE id = ?",
        (status, rating, outcome, error, source_id, scan_type_id, liveness,
         time.time(), note, row_id))
    conn.commit()


def queue_counts(conn):
    counts = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, COUNT(*) AS n FROM scan_queue GROUP BY status")}
    for status in ("pending", "running", "done", "error", "skipped"):
        counts.setdefault(status, 0)
    counts["total"] = sum(counts[s] for s in
                          ("pending", "running", "done", "error", "skipped"))
    return counts


# -------------------------------------------------------------- liveness --

def store_health(conn, row):
    check_domains.ensure_health_schema(conn)
    conn.execute(
        "INSERT OR REPLACE INTO domain_health "
        "(domain, status, nxdomain_resolvers, alive_resolvers, whois_server,"
        " whois_registered, whois_expiry_date, whois_registrar, checked_utc, error)"
        " VALUES (:domain, :status, :nxdomain_resolvers, :alive_resolvers,"
        " :whois_server, :whois_registered, :whois_expiry_date,"
        " :whois_registrar, :checked_utc, :error)", dict(row))
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES "
                 "('domain_health_checked_utc', ?)", (time.time(),))
    conn.commit()


# --------------------------------------------------------------- pipeline --

def _sha256_file(path, chunk_size=1048576):
    """Hex sha256 of a file, streamed.  None if unreadable."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _fetch_media(target, opts):
    """Returns (path, temp_path, error) for a media target.

    A local file is used as it is; an http(s) URL is downloaded to a
    temp file first (the media scanner works on files).
    """
    text = (target or "").strip()
    if not text:
        return None, None, "empty target"
    if os.path.isfile(text):
        return os.path.abspath(text), None, None
    if not text.lower().startswith(("http://", "https://")):
        return None, None, ("not a local file and not an http(s) URL: %r"
                            % target)
    try:
        import requests
    except ImportError:
        return None, None, "requests is needed to download media URLs"
    try:
        response = requests.get(text, stream=True, timeout=opts.timeout)
        response.raise_for_status()
    except Exception as exc:
        return None, None, "download failed: %s" % exc
    suffix = os.path.splitext(text.split("?")[0])[1] or ".bin"
    handle = tempfile.NamedTemporaryFile(delete=False, prefix="nsfw_media_",
                                         suffix=suffix)
    temp_path = handle.name
    size = 0
    try:
        for chunk in response.iter_content(1048576):
            if not chunk:
                continue
            size += len(chunk)
            if size > opts.max_bytes:
                handle.close()
                os.unlink(temp_path)
                return None, None, ("file is larger than the %d MB limit"
                                    % (opts.max_bytes // (1024 * 1024)))
            handle.write(chunk)
        handle.close()
    except Exception as exc:
        handle.close()
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        return None, None, "download failed: %s" % exc
    return temp_path, temp_path, None


def _progress_printer():
    """The media scan progress to stderr (the queue's own output).

    The printer itself is the library's - only the format differs (the
    worker log wants one compact line, not the CLI's redrawn bar).
    """
    from nsfw_scanner.scanner import progress_printer

    return progress_printer(style="compact")


def _process_media(app, product, row, opts):
    """Scans a local media file (or a media URL) with the media scanner."""
    target = row["target"]
    info = {"id": row["id"], "target": target, "kind": "media",
            "status": "done", "rating": None, "outcome": None, "liveness": None,
            "scan_type": None, "error": None}

    def finish(status, **kw):
        info.update(kw)
        info["status"] = status
        source_id = product.source_id("self") if info.get("source") == "self" else None
        type_id = product.scan_type_id(info.get("scan_type")) if info.get("scan_type") else None
        queue_finish(app, row["id"], status, info.get("rating"),
                     info.get("outcome"), info.get("error"), source_id, type_id,
                     liveness=info.get("liveness"), note=info.get("note"))
        return info

    path, temp_path, error = _fetch_media(target, opts)
    if error:
        return finish("error", outcome="media-failed", error=error)
    try:
        detected = nsfw_scanner.detect_kind(path)
        if detected["media_type"] not in ("video", "audio"):
            return finish("error", outcome="not-media",
                          error="not a media file (detected %s)"
                                  % detected["media_type"])
        try:
            result = nsfw_scanner.scan_media(
                path, fps=opts.fps, every_frame=opts.every_frame,
                max_frames=opts.max_frames, details=True,
                tiles=opts.tiles, hwaccel=getattr(opts, "hwaccel", "none"),
                progress=_progress_printer())
        except nsfw_scanner.MediaDependencyError as exc:
            return finish("error", outcome="media-failed",
                          error="media scanner unavailable: %s" % exc)
        rating = result.get("rating")
        scan_type = "video" if detected["media_type"] == "video" else "audio"
        problems = result.get("problems") or []
        note = "%s%s · %.1fs · %d problem(s)" % (
            detected["container"] or detected["media_type"],
            " (type mismatch!)" if detected["type_mismatch"] else "",
            result.get("duration_sec") or 0.0, len(problems))
        digest = _sha256_file(path)
        if digest and rating is not None:
            product.put_hash(digest, rating, None, None, 0.0,
                             size=os.path.getsize(path),
                             media_type=detected["media_type"],
                             mime_sniffed=detected["mime_sniffed"],
                             mime_claimed=detected["mime_claimed"],
                             ext=detected["ext"], container=detected["container"],
                             duration_sec=result.get("duration_sec"),
                             type_mismatch=detected["type_mismatch"],
                             problem_count=len(problems),
                             source_id=product.source_id("self"),
                             scan_type_id=product.scan_type_id(scan_type),
                             reason=result.get("reason"),
                             evidence=result.get("evidence"),
                             synthetic=bool(result.get("synthetic")))
            product.put_media_file(digest, filename=os.path.basename(path),
                                   original_path=path,
                                   size=os.path.getsize(path))
            if problems:
                product.put_media_problems(digest, problems)
        return finish("done", rating=rating, outcome="scanned-media",
                      scan_type=scan_type, source="self", note=note)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _scan_type_for(result):
    if isinstance(result, dict):
        if result.get("scanner") == "dns-badwords":
            return "dns-badwords"
        debug = result.get("debug") or {}
        if debug.get("decided_by") == "text-keywords":
            return "text"
        if debug.get("decided_by") in ("max-image-rating", "nsfw-explicit",
                                        "nsfw-revealing", "gender-female",
                                        "nsfw-class-porn", "nsfw-class-hentai",
                                        "nsfw-class-sexy"):
            return "image"
    return "website"


def process_one(app, product, row, opts):
    """Processes one claimed queue row. Returns a printable summary dict."""
    target = row["target"]
    kind = row["kind"]
    bw = nsfw_scanner.domain_badwords(target)
    host = bw["host"] or target.split("/", 1)[0]
    info = {"id": row["id"], "target": target, "kind": kind,
            "status": "done", "rating": None, "outcome": None, "liveness": None,
            "scan_type": None, "error": None}
    liveness = None

    def finish(status, **kw):
        info.update(kw)
        info["status"] = status
        source_id = product.source_id("self") if info.get("source") == "self" else None
        type_id = product.scan_type_id(info.get("scan_type")) if info.get("scan_type") else None
        queue_finish(app, row["id"], status, info.get("rating"),
                     info.get("outcome"), info.get("error"), source_id, type_id,
                     liveness=info.get("liveness"))
        return info

    # Media files (video/audio) go to the media scanner - never through
    # the website path, and never short-circuited on the file name (the
    # point of the queue is to test the media scanner).
    if kind == "media":
        return _process_media(app, product, row, opts)

    # 1. DNS badwords — name alone, no hardware.
    if bw["rating"] is not None:
        if host:
            product.record_scan_result(host, bw["rating"], "dns-badwords")
            if bw["rating"] == 10:
                product.record_self_block(host, 10, "dns-badwords")
        return finish("done", rating=bw["rating"], outcome="blocked-badwords",
                      scan_type="dns-badwords", source="self")
    if kind == "badwords":
        return finish("done", outcome="badwords-clear",
                      scan_type="dns-badwords", source="self")

    # 2. DNS liveness — skip dead/parked domains entirely.
    if not opts.no_liveness:
        row_health = check_domains.evaluate_domain(host, with_whois=not opts.no_whois)
        try:
            store_health(product.conn, row_health)
        except Exception as exc:                    # non-fatal
            info["error"] = f"health store: {exc}"
        liveness = row_health["status"]
        if liveness in ("dead", "parked"):
            return finish("done", outcome="skipped-" + liveness, liveness=liveness,
                          scan_type="dns-liveness", source="self",
                          error="skipped: domain is " + liveness)
        if kind == "dns":
            return finish("done", outcome="dns-checked", liveness=liveness,
                          scan_type="dns-liveness", source="self")

    # 3. Full scan (url only).
    url = target if target.startswith(("http://", "https://")) else "https://" + target
    result = nsfw_scanner.scan(url, max_images=opts.max_images,
                               timeout=opts.timeout, details=True, debug=True)
    if isinstance(result, dict):
        rating, error = result.get("rating"), result.get("error")
    elif isinstance(result, int):
        rating, error = result, None
    else:
        rating, error = None, str(result)
    scan_type = _scan_type_for(result)
    if rating is not None and host:
        # Store every rating we measured (including rating 1) so the site
        # can answer "what is this domain rated?"; a 10 is additionally
        # recorded as a blocked domain.
        product.record_scan_result(host, rating, scan_type,
                                  reason=result.get("reason")
                                  if isinstance(result, dict) else None,
                                  evidence=result.get("evidence")
                                  if isinstance(result, dict) else None)
        if rating == 10:
            product.record_self_block(host, 10, scan_type,
                                      reason=result.get("reason")
                                      if isinstance(result, dict) else None,
                                      evidence=result.get("evidence")
                                      if isinstance(result, dict) else None)
    if rating is None:
        return finish("error", outcome="error", liveness=liveness,
                      scan_type=scan_type, source="self",
                      error=error or "scan failed")
    return finish("done", rating=rating, outcome="scanned", liveness=liveness,
                  scan_type=scan_type, source="self", error=error)


# -------------------------------------------------------------------- CLI --

def _add_common(parser, sub=False):
    """The DB paths work before *and* after the sub-command.

    argparse only accepts global options before the sub-command, but the
    site's "Run once" button calls
    ``scan_queue.py once --limit N --app-db ... --product-db ...``.
    The sub-parsers therefore repeat the options with SUPPRESS as the
    default, so they only override when they are actually given.
    """
    if sub:
        parser.add_argument("--app-db", default=argparse.SUPPRESS,
                            help="scan_queue app DB")
        parser.add_argument("--product-db", default=argparse.SUPPRESS,
                            help="nsfw.sqlite product DB")
        return
    parser.add_argument("--app-db", default=default_app_db(),
                        help="scan_queue app DB (default: %(default)s)")
    parser.add_argument("--product-db", default=default_product_db(),
                        help="nsfw.sqlite product DB (default: %(default)s)")


def _do_add(args):
    app = app_conn(args.app_db)
    print(f"queue DB: {args.app_db}")
    for target in args.targets:
        try:
            row_id, created = queue_add(app, target, args.kind, args.note,
                                        args.priority)
            print(("added" if created else "updated") + f" #{row_id} {target} "
                  f"(kind={args.kind})")
        except ValueError as exc:
            print(f"skipped {target!r}: {exc}")
    print("counts:", queue_counts(app))
    app.close()


def _do_list(args):
    app = app_conn(args.app_db)
    sql = "SELECT * FROM scan_queue"
    params = []
    if args.status != "all":
        sql += " WHERE status = ?"
        params.append(args.status)
    sql += (" ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'running' THEN 1"
            " ELSE 2 END, priority DESC, id DESC LIMIT ?")
    params.append(args.limit)
    rows = app.execute(sql, params).fetchall()
    if not rows:
        print("scan queue is empty — add sites with:")
        print("  run.bat scan-add <domain>        (or the /?p=scanner page)")
        print("  run.bat scan-once                process the queue once")
        print("  run.bat scan-worker              run the background worker")
        print("counts:", queue_counts(app))
        app.close()
        return 0
    print(f"{'id':>4} {'status':<8} {'kind':<8} {'rating':>6}  "
          f"{'outcome':<16} {'liveness':<9} target")
    for r in rows:
        rating = "" if r["rating"] is None else str(r["rating"])
        print(f"{r['id']:>4} {r['status']:<8} {r['kind']:<8} {rating:>6}  "
              f"{(r['outcome'] or ''):<16} {(r['liveness'] or ''):<9} {r['target']}")
    print("counts:", queue_counts(app))
    app.close()
    return 0


def _do_counts(args):
    app = app_conn(args.app_db)
    print(queue_counts(app))
    app.close()
    return 0


def _do_clear(args):
    app = app_conn(args.app_db)
    if args.status == "all":
        deleted = app.execute("DELETE FROM scan_queue").rowcount
    else:
        deleted = app.execute("DELETE FROM scan_queue WHERE status = ?",
                              (args.status,)).rowcount
    app.commit()
    print(f"deleted {deleted} row(s); counts:", queue_counts(app))
    app.close()
    return 0


def _run_batch(args, worker=False):
    app = app_conn(args.app_db)
    product = CacheDB(args.product_db)
    processed = 0
    try:
        while True:
            rows = queue_claim(app, args.limit)
            if not rows:
                counts = queue_counts(app)
                print("scan queue is empty — nothing to do.")
                print("  add:    run.bat scan-add <domain>   (or /?p=scanner)")
                print("  counts:", counts)
                if not worker:
                    return 0
                time.sleep(max(1, int(args.interval)))
                continue
            for row in rows:
                try:
                    info = process_one(app, product, row, args)
                except Exception as exc:      # never kill the worker
                    info = {"id": row["id"], "target": row["target"],
                            "status": "error", "error": repr(exc)}
                    queue_finish(app, row["id"], "error",
                                 error=repr(exc), outcome="exception")
                processed += 1
                print(f"[{info.get('status')}] #{info.get('id')} "
                      f"{info.get('target')} rating={info.get('rating')} "
                      f"outcome={info.get('outcome')} "
                      f"liveness={info.get('liveness')}"
                      + (f" error={info['error']}" if info.get("error") else ""),
                      flush=True)
                if args.scan_delay > 0:
                    time.sleep(args.scan_delay)
            if not worker:
                print(f"processed {processed} item(s); counts:", queue_counts(app))
                return 0
    except KeyboardInterrupt:
        print("\nworker stopped.", flush=True)
        return 0
    finally:
        product.close()
        app.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Modesty scan queue: add sites, run once, or run a worker")
    _add_common(parser)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("add", help="add/update sites in the queue")
    _add_common(p, sub=True)
    p.add_argument("targets", nargs="+")
    p.add_argument("--kind", choices=VALID_KINDS, default="url", help=KIND_HELP)
    p.add_argument("--note", default="")
    p.add_argument("--priority", type=int, default=0)
    p.set_defaults(func=_do_add)

    p = sub.add_parser("list", help="show the queue")
    _add_common(p, sub=True)
    p.add_argument("--status", default="all",
                   choices=("all", "pending", "running", "done", "error", "skipped"))
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=_do_list)

    def _once_defaults(pp):
        pp.add_argument("--limit", type=int, default=10)
        pp.add_argument("--no-whois", action="store_true",
                        help="skip whois during the liveness step (faster)")
        pp.add_argument("--no-liveness", action="store_true",
                        help="skip the DNS liveness step entirely")
        pp.add_argument("--max-images", type=int, default=5)
        pp.add_argument("--timeout", type=int, default=10)
        # media (kind=media)
        pp.add_argument("--fps", type=float, default=1.0,
                        help="media: frames per second to sample "
                             "(default: %(default)s)")
        pp.add_argument("--every-frame", action="store_true",
                        help="media: decode every frame (slow)")
        pp.add_argument("--max-frames", type=int, default=2000,
                        help="media: stop after this many frames "
                             "(default: %(default)s)")
        pp.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024,
                        help="media: download limit for media URLs "
                             "(default: 512 MB)")
        pp.add_argument("--tiles", choices=("3x3", "2x2", "off"), default="off",
                        help="media: also score sub-crops of each frame, so a "
                             "person in a wide shot is not diluted (off by "
                             "default: a tight crop of a face reads as "
                             "'porn' to both models, which invents explicit "
                             "verdicts)")
        pp.add_argument("--hwaccel",
                        choices=("none", "auto", "cuda", "qsv", "d3d11va",
                                 "vaapi"),
                        default="none",
                        help="media: hardware-accelerated decoding ('auto' "
                             "falls back to the software decoder)")
        pp.add_argument("--scan-delay", type=float, default=0.0,
                        help="seconds to wait between scanned items "
                             "(default: 0, no delay). Set this to avoid "
                             "getting blocked by target sites when "
                             "scanning many URLs in a row.")

    p = sub.add_parser("once", help="process one batch then exit")
    _add_common(p, sub=True)
    _once_defaults(p)
    p.set_defaults(func=lambda a: _run_batch(a, worker=False))

    p = sub.add_parser("worker", help="loop forever processing the queue")
    _add_common(p, sub=True)
    _once_defaults(p)
    p.add_argument("--interval", type=int, default=30,
                   help="seconds to sleep when the queue is empty")
    p.set_defaults(func=lambda a: _run_batch(a, worker=True))

    p = sub.add_parser("counts", help="print queue counts")
    _add_common(p, sub=True)
    p.set_defaults(func=_do_counts)

    p = sub.add_parser("clear", help="delete queue rows")
    _add_common(p, sub=True)
    p.add_argument("--status", default="done")
    p.set_defaults(func=_do_clear)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
