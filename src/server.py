"""Modesty - nsfw protection API service over nsfw_scanner + SQLite cache.

Stdlib only (no FastAPI needed for the basics):

  GET  /health          -> {"ok", models, db stats}
  POST /scan            -> {"target","scanner","rating","phrase","elapsed",
                            "cached","blocked",...} (cached answers included)
  GET  /lookup?domain=  -> known-domain rating or {"rating": null}
  GET  /hash/<sha256>    -> previous result for these exact bytes, or miss
  POST /scan             -> JSON {target,...} scanned (hashes local files),
                            {"sha256":...} for a content-hash lookup only, or
                            multipart file upload (field "file")
  GET  /db/download     -> the SQLite file itself (free DB download)
  GET  /                -> frontend demo page (packages/frontend-example/src)

Flow per scan: fresh cache hit -> content-hash hit (uploads/local files)
-> DNS-blocker known domain (rating 10, no scan needed) -> live lib scan
-> stored in cache.  Video and audio files are routed to the media
scanner (ffmpeg based); when ffmpeg is missing the answer says so
instead of guessing.

Run:  python packages/nsfw-webservice/src/server.py [--port 8099] [--db PATH]
"""

from multipart_form import FieldStorage  # stdlib cgi was removed in Python 3.13
import hashlib
import json
import mimetypes
import os
import re
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def _bootstrap():
    try:
        import nsfw_scanner  # noqa: F401
        import cache_db  # noqa: F401
        return
    except ImportError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    sys.path.insert(0, os.path.normpath(os.path.join(here, "..", "..", "nsfw-lib", "src")))


_bootstrap()

import cache_db  # noqa: E402
from nsfw_scanner import (  # noqa: E402
    IMAGE_EXTENSIONS,
    MediaDependencyError,
    detect_kind,
    get_face_session,
    get_sessions,
    pick_scanner,
    rating_phrase,
    scan,
    scan_media,
    verdict_for,
)

DEFAULT_PORT = 8099
# Uploads are streamed to a temp file, so the limit is about disk, not RAM.
MAX_BODY = int(os.environ.get("NSFW_MAX_UPLOAD_BYTES", 1024 * 1024 * 1024))

_IMAGE_MAGIC = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"BM",
                b"II*\x00", b"MM\x00*")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _sha256_path(path, chunk_size=1048576):
    """Hex sha256 of a local file, streamed. None if unreadable."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _media_kind(filename, head):
    """'image', 'video', 'audio' or 'unsupported' for an uploaded file.

    The header decides (the extension is only a hint), so a .jpg that is
    really a video is not scanned as an image.
    """
    ext = os.path.splitext((filename or "").lower())[1]
    if ext in IMAGE_EXTENSIONS:
        return "image"
    head = head or b""
    if head.startswith(_IMAGE_MAGIC):
        return "image"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image"
    return "unsupported"


def _repo_file(*parts):
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", *parts))


def _domain_of(target):
    text = (target or "").strip()
    if not text or os.path.exists(text) or text.lower().startswith("file://"):
        return None
    url = text if re.match(r"^https?://", text, re.IGNORECASE) else "https://" + text
    try:
        host = urlparse(url).hostname
    except Exception:
        return None
    return host.lower().rstrip(".") if host else None


def _scan_type_slug(kind, result):
    """Maps a lib scan result to a `scan_types` slug for provenance."""
    if isinstance(result, dict):
        if result.get("scanner") == "dns-badwords":
            return "dns-badwords"
        if result.get("scanner") == "media-video":
            return "video"
        if result.get("scanner") == "media-audio":
            return "audio"
        debug = result.get("debug") or {}
        if debug.get("decided_by") == "text-keywords":
            return "text"
        if debug.get("decided_by") in ("max-image-rating", "nsfw-explicit",
                                        "nsfw-revealing", "gender-female",
                                        "nsfw-class-porn", "nsfw-class-hentai",
                                        "nsfw-class-sexy"):
            return "image"
    if kind in ("image-file", "image-url"):
        return "image"
    if kind == "media-file":
        media_type = result.get("media_type") if isinstance(result, dict) else None
        return "audio" if media_type == "audio" else "video"
    return "website"


class V1Mixin:
    """The **open** API: ``hash -> result``, three fields, nothing of ours.

    It is deliberately separate from our own API (which answers with our
    internal vocabulary: the evidence, the problems, the provenance).
    This one is meant for *anybody's* product:

        GET  /v1/hash/<sha256>   -> 200 {"hash": "...", "rating": 10,
                                          "verdict": "explicit"}
                                      404 {"hash": "...", "rating": null,
                                          "verdict": null}
        POST /v1/sample           -> 200 {"hash": "...", "rating": 10,
                                          "verdict": "explicit",
                                          "stored": true}

    The routes can be moved to their own process (and their own URL)
    later - see the ``--v1-port`` / ``--v1-only`` options - because the
    heavy part (the scanning) is what needs offloading, not the lookups.
    """

    def _v1_prefix(self):
        return getattr(self.server, "v1_prefix", "/v1")

    def v1_get(self, path):
        """Serves the open API's GET routes.  True when it answered."""
        prefix = self._v1_prefix()
        if not path.startswith(prefix):
            return False
        rest = path[len(prefix):]
        if rest.startswith("/hash/"):
            self._v1_hash(rest[len("/hash/"):])
            return True
        if rest.startswith("/title/"):
            self._v1_title(rest[len("/title/"):])
            return True
        if rest in ("", "/"):
            self._send_json({"api": "nsfw v1",
                             "hash": prefix + "/hash/<sha256>",
                             "title": prefix + "/title/<imdb_id>",
                             "sample": prefix + "/sample"})
            return True
        self._send_json({"error": "not found"}, status=404)
        return True

    def v1_post(self, path):
        """Serves the open API's POST routes.  True when it answered."""
        prefix = self._v1_prefix()
        if not path.startswith(prefix):
            return False
        if path[len(prefix):] != "/sample":
            self._send_json({"error": "not found"}, status=404)
            return True
        self._v1_sample()
        return True

    def _v1_hash(self, hex_digest):
        """The hash lookup: the stored verdict, three fields."""
        hex_digest = (hex_digest or "").strip().lower()
        if not HEX64_RE.match(hex_digest):
            self._send_json({"error": "expected 64 hex chars"}, status=400)
            return
        hit = self.server.db.get_by_hash(hex_digest)
        rating = hit["rating"] if hit else None
        out = {"hash": hex_digest, "rating": rating,
               "verdict": verdict_for(rating)}
        # optional: include community-approved ratings
        if self.server.db.get_community_ratings:
            comm = self.server.db.get_community_ratings(hex_digest)
            if comm:
                out["community"] = comm
        self._send_json(out, status=200 if hit else 404)

    def _v1_title(self, imdb_id):
        """The IMDb catalog entry plus the results reported for that title.

        Catalog rows are metadata only (title + IMDb ID); a title has no
        rating until a real release is scanned.  Submitters are recorded in
        a separate ledger and are never presented as official verdicts.
        """
        imdb_id = (imdb_id or "").strip().lower()
        if not re.match(r"^tt\d+$", imdb_id):
            self._send_json({"error": "expected an IMDb id (tt1234567)"}, status=400)
            return
        entry = self.server.db.get_title_catalog(imdb_id)
        if not entry:
            self._send_json({"imdb_id": imdb_id, "title": None}, status=404)
            return
        out = {"imdb_id": entry["imdb_id"], "title": entry["title"],
               "rank": entry["rank"],
               "submissions": self.server.db.get_v1_submissions(imdb_id)}
        self._send_json(out, status=200)

    def _v1_sample(self):
        """Send a sample: the verdict for the bytes, and whether we kept it."""
        form = FieldStorage(
            fp=self.rfile, headers=self.headers,
            environ={"REQUEST_METHOD": "POST",
                     "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                     "CONTENT_LENGTH": self.headers.get("Content-Length", "0")})
        field = form["file"] if "file" in form else None
        if field is None or not getattr(field, "file", None):
            self._send_json({"error": "multipart upload needs a 'file' part"},
                            status=400)
            return
        filename = os.path.basename(getattr(field, "filename", "") or "upload")
        # Optional IMDb ID: lets a client report a result for a catalog title
        # (Phase 9).  Invalid values are ignored, never trusted as metadata.
        imdb_id = ""
        if "imdb_id" in form:
            raw = getattr(form["imdb_id"], "value", "")
            if isinstance(raw, (list, tuple)):
                raw = raw[0] if raw else ""
            candidate = str(raw or "").strip().lower()
            if re.match(r"^tt\d+$", candidate):
                imdb_id = candidate
        tmp_path = None
        try:
            digest, size = hashlib.sha256(), 0
            with tempfile.NamedTemporaryFile(delete=False,
                                             prefix="nsfw_v1_") as tmp:
                tmp_path = tmp.name
                while True:
                    chunk = field.file.read(1048576)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.server.max_upload_bytes:
                        self._send_json({"error": "file exceeds upload limit"},
                                        status=413)
                        return
                    digest.update(chunk)
                    tmp.write(chunk if isinstance(chunk, bytes) else
                              chunk.encode("utf-8", "ignore"))
            hex_digest = digest.hexdigest()
            db = self.server.db
            hit = db.get_by_hash(hex_digest)
            if hit:
                verdict = verdict_for(hit["rating"])
                out = {"hash": hex_digest, "rating": hit["rating"],
                       "verdict": verdict, "stored": True}
                if imdb_id:
                    db.record_v1_submission(imdb_id, hex_digest, hit["rating"],
                                            verdict, "known", filename)
                    out["imdb_id"] = imdb_id
                self._send_json(out)
                return
            kind = detect_kind(tmp_path)
            media_type = kind["media_type"]
            if media_type not in ("image", "video", "audio"):
                self._send_json({"hash": hex_digest, "rating": None,
                                 "verdict": None, "stored": False},
                                status=415)
                return
            started = time.perf_counter()
            try:
                if media_type in ("video", "audio"):
                    result = scan_media(tmp_path, details=True)
                else:
                    result = scan(tmp_path, timeout=30, details=True)
            except MediaDependencyError as exc:
                self._send_json({"hash": hex_digest, "rating": None,
                                 "verdict": None, "stored": False,
                                 "error": "Error: %s" % exc}, status=501)
                return
            except Exception as exc:
                result = {"rating": None, "error": f"Error: {exc}"}
            elapsed = time.perf_counter() - started
            rating = (result.get("rating") if isinstance(result, dict)
                      else result if isinstance(result, int) else None)
            stored = False
            if rating is not None:
                db.put_hash(hex_digest, rating,
                            result.get("error") if isinstance(result, dict) else None,
                            json.dumps(result) if isinstance(result, dict) else None,
                            elapsed, size=size, media_type=media_type,
                            mime_sniffed=kind["mime_sniffed"],
                            mime_claimed=kind["mime_claimed"])
                stored = True
            verdict = verdict_for(rating)
            out = {"hash": hex_digest, "rating": rating,
                   "verdict": verdict, "stored": stored}
            if imdb_id:
                db.record_v1_submission(imdb_id, hex_digest, rating, verdict,
                                        media_type, filename)
                out["imdb_id"] = imdb_id
            self._send_json(out)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


class Handler(V1Mixin, BaseHTTPRequestHandler):
    server_version = "nsfw-webservice/0.1"

    # -- helpers --------------------------------------------------------
    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    # -- routes ---------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        db = self.server.db

        # the open API first (it lives under its own prefix)
        if self.v1_get(path):
            return

        if path == "/health":
            nsfw, gender = get_sessions()
            self._send_json({"ok": True,
                             "models": {"nsfw": nsfw is not None,
                                        "gender": gender is not None,
                                        "face": get_face_session() is not None},
                             "db": db.path, "stats": db.stats()})
        elif path == "/lookup":
            domain = (query.get("domain") or [""])[0]
            hit = db.lookup_rating(domain) if domain else None
            # the verbose reason is admin-only; the public API never returns it
            out = {"domain": domain, "rating": hit["rating"] if hit else None,
                   "blocked": hit.get("blocked", False) if hit else False,
                   "source": hit["source"] if hit else None,
                   "source_id": hit["source_id"] if hit else None,
                   "source_name": hit["source_name"] if hit else None,
                   "license": hit["license"] if hit else None,
                   "scan_type": hit["scan_type"] if hit else None,
                   "phrase": rating_phrase(hit["rating"]) if hit else "unrated"}
            self._send_json(out, status=200 if hit else 404)
        elif path.startswith("/hash/"):
            hex_digest = path[len("/hash/"):].strip().lower()
            if not HEX64_RE.match(hex_digest):
                self._send_json({"error": "expected 64 hex chars"}, status=400)
                return
            hit = db.get_by_hash(hex_digest)
            if not hit:
                self._send_json({"hash": hex_digest, "rating": None,
                                 "cached": False}, status=404)
                return
            out = {"hash": hex_digest, "rating": hit["rating"],
                   "error": hit["error"], "elapsed": hit["elapsed"],
                   "bytes": hit["bytes"], "cached": True}
            if hit["rating"] is not None:
                out["phrase"] = rating_phrase(hit["rating"])
            if hit["details"]:
                out["details"] = json.loads(hit["details"])
            self._send_json(out)
        elif path == "/db/download":
            if not os.path.exists(db.path):
                self._send_json({"error": "no database built yet"}, status=404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-sqlite3")
            self.send_header("Content-Length", str(os.path.getsize(db.path)))
            self.send_header("Content-Disposition",
                             'attachment; filename="nsfw.sqlite"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if self.command == "HEAD":
                return
            with open(db.path, "rb") as handle:
                while True:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        elif path in ("/", "/index.html", "/app.js"):
            name = "index.html" if path != "/app.js" else "app.js"
            fpath = _repo_file("frontend-example", "src", name)
            if not os.path.exists(fpath):
                self._send_json({"error": "frontend not found"}, status=404)
                return
            with open(fpath, "rb") as handle:
                body = handle.read()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(name)[0] or
                             "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        else:
            self._send_json({"error": "not found"}, status=404)

    do_HEAD = do_GET  # same headers, no body (see guards above)

    def do_POST(self):
        path = urlparse(self.path).path
        # the open API first (it lives under its own prefix)
        if self.v1_post(path):
            return
        if path != "/scan":
            self._send_json({"error": "not found"}, status=404)
            return
        if self.headers.get("Content-Type", "").startswith("multipart/form-data"):
            self._scan_upload()
            return
        body = self._read_json()
        if not (body.get("target") or "").strip() and body.get("sha256"):
            self._lookup_hash(body.get("sha256"))
            return
        target = (body.get("target") or "").strip()
        if not target:
            self._send_json({"error": "missing 'target'"}, status=400)
            return
        max_images = int(body.get("max_images", 5))
        timeout = int(body.get("timeout", 10))
        want_details = bool(body.get("details", False))
        want_debug = bool(body.get("debug", False))
        db = self.server.db

        cached = db.get_cached(target)
        if cached:
            out = {"target": target, "scanner": cached["scanner"],
                   "rating": cached["rating"], "error": cached["error"],
                   "elapsed": cached["elapsed"], "cached": True, "blocked": False,
                   "hash": None}
            if cached["rating"] is not None:
                out["phrase"] = rating_phrase(cached["rating"])
            if want_details and cached["details"]:
                out["details"] = json.loads(cached["details"])
            self._send_json(out)
            return

        kind = pick_scanner(target)

        # Local files are hashed: same bytes under any name hit media_hashes.
        file_hash, file_size = None, 0
        if kind in ("image-file", "media-file"):
            fpath = target[7:] if target.lower().startswith("file://") else target
            file_hash = _sha256_path(fpath)
            file_size = os.path.getsize(fpath) if file_hash else 0
            if file_hash:
                hit = db.get_by_hash(file_hash)
                if hit:
                    out = self._media_hit_out(target, kind, file_hash, hit,
                                              want_details)
                    self._send_json(out)
                    return

        domain = _domain_of(target)
        hit = db.lookup_domain(domain) if domain else None
        if hit:
            out = {"target": target, "scanner": kind, "rating": hit["rating"],
                   "phrase": rating_phrase(hit["rating"]), "elapsed": 0.0,
                   "cached": False, "blocked": True, "block_source": hit["source"],
                   "block_source_id": hit["source_id"],
                   "block_source_name": hit["source_name"],
                   "block_source_license": hit["license"],
                   "block_scan_type": hit["scan_type"],
                   "matched_domain": hit["domain"], "error": None, "hash": file_hash}
            db.put_cached(target, kind, hit["rating"], None,
                          json.dumps({"blocked": True, "source": hit["source"],
                                      "source_name": hit["source_name"],
                                      "license": hit["license"],
                                      "scan_type": hit["scan_type"]}),
                          0.0, ttl_days=90,
                          source_id=hit["source_id"],
                          scan_type_id=hit["scan_type_id"])
            self._send_json(out)
            return

        started = time.perf_counter()
        try:
            result = scan(target, max_images=max_images, timeout=timeout,
                          details=True, debug=want_debug)
        except Exception as exc:  # lib should not raise; stay alive anyway
            result = {"rating": None, "error": f"Error: {exc}"}
        elapsed = time.perf_counter() - started

        if isinstance(result, dict):
            rating, error = result.get("rating"), result.get("error")
        elif isinstance(result, int):
            rating, error = result, None
        else:
            rating, error = None, str(result)

        scan_type_slug = _scan_type_slug(kind, result)
        self_source_id = db.source_id("self")
        self_scan_type_id = db.scan_type_id(scan_type_slug)

        if rating is not None:
            # Never cache failures: a transient DNS/timeout error must not
            # stick for weeks. Errors are re-attempted live every time.
            db.put_cached(target, kind, rating, error,
                          json.dumps(result) if isinstance(result, dict) else None,
                          elapsed, ttl_days=self.server.ttl_days,
                          source_id=self_source_id,
                          scan_type_id=self_scan_type_id)
            if file_hash:
                media_type = (result.get("media_type")
                              if isinstance(result, dict) else None)
                db.put_hash(file_hash, rating, error,
                            json.dumps(result) if isinstance(result, dict) else None,
                            elapsed, size=file_size,
                            media_type=media_type,
                            mime_sniffed=result.get("mime_sniffed")
                            if isinstance(result, dict) else None,
                            mime_claimed=result.get("mime_claimed")
                            if isinstance(result, dict) else None,
                            ext=result.get("ext")
                            if isinstance(result, dict) else None,
                            container=result.get("container")
                            if isinstance(result, dict) else None,
                            duration_sec=result.get("duration_sec")
                            if isinstance(result, dict) else None,
                            type_mismatch=result.get("type_mismatch", False)
                            if isinstance(result, dict) else False,
                            problem_count=result.get("problem_count", 0)
                            if isinstance(result, dict) else 0,
                            source_id=self_source_id,
                            scan_type_id=self_scan_type_id,
                            reason=result.get("reason")
                            if isinstance(result, dict) else None,
                            evidence=result.get("evidence")
                            if isinstance(result, dict) else None,
                            synthetic=bool(result.get("synthetic"))
                            if isinstance(result, dict) else False)
                if media_type in ("video", "audio"):
                    fpath = (target[7:] if target.lower().startswith("file://")
                             else target)
                    db.put_media_file(file_hash,
                                      filename=os.path.basename(fpath),
                                      original_path=fpath, size=file_size,
                                      mtime=os.path.getmtime(fpath)
                                      if os.path.exists(fpath) else None)
                    if isinstance(result, dict) and result.get("problems"):
                        db.put_media_problems(file_hash, result["problems"])
            # Self-scan learning: the rating we measured is stored for every
            # domain we scan (so "what is this site rated?" has an answer),
            # and an explicit 10 is additionally recorded as a blocked domain
            # with source=self + the scan type.  An existing blocklist source
            # is preserved if the domain was already known.
            if domain and rating is not None:
                db.record_scan_result(domain, rating, scan_type_slug,
                                      reason=result.get("reason")
                                      if isinstance(result, dict) else None,
                                      evidence=result.get("evidence")
                                      if isinstance(result, dict) else None)
            if rating == 10 and domain and (kind == "website"
                                            or scan_type_slug == "dns-badwords"):
                db.record_self_block(domain, 10, scan_type_slug,
                                     reason=result.get("reason")
                                     if isinstance(result, dict) else None,
                                     evidence=result.get("evidence")
                                     if isinstance(result, dict) else None)
        out = {"target": target, "scanner": kind, "rating": rating,
               "error": error, "elapsed": round(elapsed, 3),
               "cached": False, "blocked": False, "hash": file_hash,
               "source": "self" if rating is not None else None,
               "scan_type": scan_type_slug if rating is not None else None}
        if rating is not None:
            out["phrase"] = rating_phrase(rating)
        if want_details and isinstance(result, dict):
            out["details"] = result
        self._send_json(out)

    def _media_hit_out(self, target, scanner, file_hash, hit, want_details):
        out = {"target": target, "scanner": scanner, "rating": hit["rating"],
               "error": hit["error"], "elapsed": hit["elapsed"],
               "cached": True, "blocked": False, "hash": file_hash}
        for key in ("media_type", "mime_sniffed", "mime_claimed", "ext",
                    "container", "duration_sec", "problem_count"):
            if key in hit.keys() and hit[key] is not None:
                out[key] = hit[key]
        if hit["rating"] is not None:
            out["phrase"] = rating_phrase(hit["rating"])
        if want_details and hit["details"]:
            out["details"] = json.loads(hit["details"])
        return out

    def _lookup_hash(self, hex_digest):
        """Pure content-hash lookup: no bytes needed, no scan performed."""
        hex_digest = (hex_digest or "").strip().lower()
        db = self.server.db
        if not HEX64_RE.match(hex_digest):
            self._send_json({"error": "expected 64 hex chars"}, status=400)
            return
        hit = db.get_by_hash(hex_digest)
        if not hit:
            self._send_json({"hash": hex_digest, "rating": None,
                             "cached": False}, status=404)
            return
        self._send_json(self._media_hit_out(
            None, hit.get("media_type") or "media", hex_digest, hit,
            want_details=True))

    def _scan_upload(self):
        """Multipart file upload: hash -> media hit, gate, or lib scan."""
        db = self.server.db
        query = parse_qs(urlparse(self.path).query)
        want_details = query.get("details", ["0"])[0] == "1"
        want_debug = query.get("debug", ["0"])[0] == "1"
        form = FieldStorage(
            fp=self.rfile, headers=self.headers,
            environ={"REQUEST_METHOD": "POST",
                     "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                     "CONTENT_LENGTH": self.headers.get("Content-Length", "0")})
        field = form["file"] if "file" in form else None
        if field is None or not getattr(field, "file", None):
            self._send_json({"error": "multipart upload needs a 'file' part"},
                            status=400)
            return
        filename = os.path.basename(getattr(field, "filename", "") or "upload")
        tmp_path = None
        try:
            digest, size = hashlib.sha256(), 0
            with tempfile.NamedTemporaryFile(delete=False,
                                             prefix="nsfw_upload_") as tmp:
                tmp_path = tmp.name
                while True:
                    chunk = field.file.read(1048576)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.server.max_upload_bytes:
                        self._send_json({"error": "file exceeds upload limit"},
                                        status=413)
                        return
                    digest.update(chunk)
                    tmp.write(chunk if isinstance(chunk, bytes) else
                              chunk.encode("utf-8", "ignore"))
            hex_digest = digest.hexdigest()
            hit = db.get_by_hash(hex_digest)
            if hit:
                self._send_json(self._media_hit_out(
                    filename, hit.get("media_type") or "image-file",
                    hex_digest, hit, want_details))
                return
            kind = detect_kind(tmp_path)
            media_type = kind["media_type"]
            if media_type not in ("image", "video", "audio"):
                self._send_json({
                    "target": filename, "scanner": "media", "rating": None,
                    "hash": hex_digest, "cached": False, "blocked": False,
                    "media_type": media_type,
                    "error": "Error: unsupported media type "
                             f"({os.path.splitext(filename)[1] or 'unknown'}); "
                             "images, video and audio are supported"})
                return
            started = time.perf_counter()
            try:
                if media_type in ("video", "audio"):
                    media_options = {"details": True, "debug": want_debug}
                    if media_type == "video":
                        media_options["save_samples"] = False
                        for option, maximum in (
                                ("max_duration_sec", 3600),
                                ("max_frames", 3600)):
                            values = query.get(option)
                            if not values:
                                continue
                            try:
                                value = int(values[0])
                            except (TypeError, ValueError):
                                self._send_json(
                                    {"error": f"{option} must be a positive integer"},
                                    status=400)
                                return
                            if value < 1 or value > maximum:
                                self._send_json(
                                    {"error": f"{option} must be between 1 and {maximum}"},
                                    status=400)
                                return
                            media_options[option] = value
                        fps_values = query.get("fps")
                        if fps_values:
                            try:
                                fps = float(fps_values[0])
                            except (TypeError, ValueError):
                                self._send_json(
                                    {"error": "fps must be a number from 0.1 to 30"},
                                    status=400)
                                return
                            if not 0.1 <= fps <= 30:
                                self._send_json(
                                    {"error": "fps must be a number from 0.1 to 30"},
                                    status=400)
                                return
                            media_options["fps"] = fps
                    result = scan_media(tmp_path, **media_options)
                else:
                    result = scan(tmp_path, timeout=30, details=True,
                                  debug=want_debug)
            except MediaDependencyError as exc:
                self._send_json({
                    "target": filename, "scanner": "media", "rating": None,
                    "hash": hex_digest, "cached": False, "blocked": False,
                    "media_type": media_type, "code": "missing-dependency",
                    "error": "Error: %s" % exc}, status=501)
                return
            except Exception as exc:
                result = {"rating": None, "error": f"Error: {exc}"}
            elapsed = time.perf_counter() - started
            if isinstance(result, dict):
                rating, error = result.get("rating"), result.get("error")
            elif isinstance(result, int):
                rating, error = result, None
            else:
                rating, error = None, str(result)
            if rating is not None:
                db.put_hash(hex_digest, rating, error,
                            json.dumps(result) if isinstance(result, dict) else None,
                            elapsed, size=size,
                            media_type=media_type,
                            mime_sniffed=kind["mime_sniffed"],
                            mime_claimed=kind["mime_claimed"],
                            ext=kind["ext"], container=kind["container"],
                            duration_sec=result.get("duration_sec")
                            if isinstance(result, dict) else None,
                            type_mismatch=kind["type_mismatch"],
                            problem_count=result.get("problem_count", 0)
                            if isinstance(result, dict) else 0,
                            source_id=db.source_id("self"),
                            scan_type_id=db.scan_type_id(
                                "video" if media_type == "video"
                                else "audio" if media_type == "audio"
                                else "image"),
                            reason=result.get("reason")
                            if isinstance(result, dict) else None,
                            evidence=result.get("evidence")
                            if isinstance(result, dict) else None)
                if media_type in ("video", "audio"):
                    db.put_media_file(hex_digest, filename=filename, size=size)
                    if isinstance(result, dict) and result.get("problems"):
                        db.put_media_problems(hex_digest, result["problems"])
            out = {"target": filename,
                   "scanner": result.get("scanner") if isinstance(result, dict)
                   else "image-file",
                   "rating": rating, "error": error,
                   "elapsed": round(elapsed, 3), "cached": False,
                   "blocked": False, "hash": hex_digest,
                   "media_type": media_type,
                   "mime": kind["mime"], "mime_sniffed": kind["mime_sniffed"],
                   "mime_claimed": kind["mime_claimed"], "ext": kind["ext"],
                   "container": kind["container"],
                   "type_mismatch": kind["type_mismatch"]}
            if isinstance(result, dict):
                for key in ("duration_sec", "frame_count", "problem_count",
                            "profile", "subtitles"):
                    if key in result:
                        out[key] = result[key]
            if rating is not None:
                out["phrase"] = rating_phrase(rating)
            if want_details and isinstance(result, dict):
                out["details"] = result
            self._send_json(out)
        finally:
            try:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, *args):  # keep stdout for scan results, not hits
        pass


class V1Handler(V1Mixin, BaseHTTPRequestHandler):
    """A server that answers **only** the open API (the heavy part can be
    offloaded into its own process on its own port)."""

    server_version = "nsfw-webservice/0.1"

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self.v1_get(urlparse(self.path).path)

    def do_POST(self):
        self.v1_post(urlparse(self.path).path)

    do_HEAD = do_GET

    def log_message(self, *args):
        pass


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        description="Modesty - nsfw protection toolkit API service",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--db", default=_repo_file("nsfw-db", "data", "nsfw.sqlite"))
    parser.add_argument("--ttl-days", type=float, default=30)
    parser.add_argument("--max-upload-mb", type=float, default=128,
                        help="Max multipart upload size (default: %(default)s MB)")
    parser.add_argument("--v1-prefix", default="/v1",
                        help="the open API's URL prefix (default: %(default)s)")
    parser.add_argument("--no-v1", action="store_true",
                        help="do not serve the open API at all")
    parser.add_argument("--v1-only", action="store_true",
                        help="serve ONLY the open API on --port (so it can "
                             "run as its own process and be offloaded)")
    parser.add_argument("--v1-port", type=int, default=0,
                        help="serve the open API on this port as well "
                             "(0 = only on --port)")
    args = parser.parse_args(argv)

    def build_server(port, handler):
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        server.db = cache_db.CacheDB(args.db)
        server.ttl_days = args.ttl_days
        server.max_upload_bytes = int(args.max_upload_mb * 1048576)
        server.v1_prefix = args.v1_prefix
        return server

    main_handler = V1Handler if args.v1_only else Handler
    server = build_server(args.port, main_handler)
    print(f"nsfw-webservice on http://127.0.0.1:{args.port} (db: {server.db.path})",
          flush=True)
    if not args.no_v1 and not args.v1_only:
        print(f"  the open API: http://127.0.0.1:{args.port}{args.v1_prefix}/hash/<sha256>",
              flush=True)
    threads = []
    if args.v1_port and not args.v1_only:
        v1 = build_server(args.v1_port, V1Handler)
        print(f"  the open API alone: http://127.0.0.1:{args.v1_port}{args.v1_prefix}/",
              flush=True)
        thread = threading.Thread(target=v1.serve_forever, daemon=True)
        thread.start()
        threads.append((v1, thread))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for extra, _thread in threads:
            extra.shutdown()


if __name__ == "__main__":
    main()
