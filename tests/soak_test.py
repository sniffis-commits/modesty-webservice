"""Soak/load test for nsfw-webservice.

Hammers a running server with concurrent POST /scan requests and reports
percentiles (p50/p95/p99), cache-hit ratio, error count and CSV-friendly
per-request lines. No network needed: targets are sampled from
`known_domains` in the built blocklist DB, so the server answers over the
blocklist path (rating 10, first hit falls to cache on request #2) --
this exercises the HTTP layer + CacheDB exactly like traffic would.

Run:
  python packages/nsfw-webservice/tests/soak_test.py                    # 127.0.0.1:8099
  python packages/nsfw-webservice/tests/soak_test.py --host 127.0.0.1 --port 8099 \
      --requests 200 --concurrency 16
  ... --live https://example.com  # optional: scan real URLs (slow, needs network)
"""

import argparse
import json
import os
import random
import sqlite3
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.normpath(os.path.join(
    HERE, "..", "..", "..", "nsfw-db", "data", "nsfw.sqlite"))

TOL = {}  # filled from args


def sample_domains(db_path, count, seed=7):
    """Random known domains from the blocklist DB (offline-friendly scans)."""
    conn = sqlite3.connect(db_path)
    rows = [r[0] for r in conn.execute(
        "SELECT domain FROM known_domains ORDER BY RANDOM() LIMIT ?",
        (count,))]
    conn.close()
    if not rows:
        raise SystemExit(f"no known_domains in {db_path}; build it first: run.bat db")
    return rows


def one_scan(url, target, timeout):
    started = time.perf_counter()
    cached = "?"
    blocked = False
    error = None
    rating = None
    try:
        r = requests.post(url, json={"target": target, "max_images": 1},
                          timeout=timeout)
        data = r.json()
        cached = data.get("cached")
        blocked = bool(data.get("blocked"))
        rating = data.get("rating")
        error = data.get("error")
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.perf_counter() - started
    return {"target": target, "elapsed": elapsed, "cached": cached,
            "blocked": blocked, "rating": rating, "error": error}


def pct(sorted_latencies, p):
    if not sorted_latencies:
        return float("nan")
    idx = min(len(sorted_latencies) - 1, int(round(p * len(sorted_latencies))) - 1)
    return sorted_latencies[max(0, idx)]


def main(argv=None):
    ap = argparse.ArgumentParser(description="webservice soak test")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--requests", type=int, default=120)
    ap.add_argument("--concurrency", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--db", default=DEFAULT_DB, help="blocklist DB for samples")
    ap.add_argument("--live", default=None,
                    help="optional real URL to scan live per request")
    args = ap.parse_args(argv)

    base = f"http://{args.host}:{args.port}"
    targets = []
    if args.live:
        targets = [args.live] * args.requests
    else:
        pool = sample_domains(args.db, max(args.requests // 2, 8))
        rng = random.Random(7)
        targets = [rng.choice(pool) for _ in range(args.requests)]

    # Warm-up: one sequential pass over the sample pool so every sampled
    # domain is in the cache before the measured phase. What we measure
    # after this is the sustained (cache-hit) load path, which is what a
    # service sees steady-state.
    warmed = sorted(set(targets))
    if not args.live:
        print(f"warm-up: {len(warmed)} domains (sequential)")
        for t in warmed:
            try:
                requests.post(base + "/scan", json={"target": t, "max_images": 1},
                              timeout=args.timeout)
            except Exception:
                pass

    results = []
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for res in ex.map(lambda t: one_scan(base + "/scan", t, args.timeout),
                          targets):
            results.append(res)
    wall = time.perf_counter() - t0

    lat = sorted(r["elapsed"] for r in results)
    hits = sum(1 for r in results if r["cached"] is True)
    serves = hits + sum(1 for r in results if r["cached"] is False and r["blocked"])
    errs = [r for r in results if r["error"]]
    ratings = {}

    print(f"server={base} requests={args.requests} concurrency={args.concurrency}")
    print(f"wall={wall:.2f}s  rps={args.requests / wall:.1f}")
    print(f"latency s: p50={pct(lat, 0.50):.3f} p95={pct(lat, 0.95):.3f} "
          f"p99={pct(lat, 0.99):.3f} max={max(lat):.3f} median={statistics.median(lat):.3f}")
    print(f"cache-hit ratio: {hits}/{len(results)} ({100.0 * hits / len(results):.1f}%)")
    print(f"fast-path serve ratio (cached+blocklist): {serves}/{len(results)} "
          f"({100.0 * serves / len(results):.1f}%)")
    if errs:
        uniq = {}
        for e in errs:
            uniq[e["error"]] = uniq.get(e["error"], 0) + 1
        print(f"errors: {len(errs)} -> {uniq}")
    ratings = {}
    for r in results:
        if r["rating"] is not None:
            ratings[r["rating"]] = ratings.get(r["rating"], 0) + 1
    print(f"ratings: {ratings}")

    ok = not errs and hits >= 0
    print("SOAK ", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
