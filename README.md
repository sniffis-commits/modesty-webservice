<p align="center"><img src="assets/logo.svg" alt="modesty-webservice" width="110" height="110"></p>

# modesty-webservice

> HTTP API service

**Part of the [Modesty toolkit](https://github.com/sniffis-commits/modesty-meta)** — see the
[big README](https://github.com/sniffis-commits/modesty-meta) for the full picture, the rating scale and all repositories.

## What this is

A small Python HTTP service exposing an open, product-agnostic `hash → result` API. Look up a previously scanned file by SHA-256, or submit a result for bytes you scanned elsewhere. Backed by SQLite.

## How to


```bash
pip install modesty_nsfw_scanner
python src/server.py --port 8099
curl http://127.0.0.1:8099/health
curl http://127.0.0.1:8099/v1/hash/<64-hex-sha256>
```
- `GET /v1/hash/<sha256>` — the stored rating/verdict (404 when unknown).
- `POST /v1/sample` — multipart `file` (+ optional `imdb_id`) for a hosted scan.
- `GET /v1/title/<imdb_id>` — catalog entry and reported submissions.
The webservice needs ffmpeg + ffprobe for video. Run with `--no-v1` to serve
only the operator API.


## Layout

| Path | Purpose |
|---|---|
| `src/` | source from the monorepo |
| `tests/` | source from the monorepo |

## More

- Full overview and other repos: [modesty-meta](https://github.com/sniffis-commits/modesty-meta)
- Website: [https://modesty.cia.org.il](https://modesty.cia.org.il)
- Model weights: [modesty-models](https://github.com/sniffis-commits/modesty-models)
- Licence: MIT (see `LICENSE`). Third-party data/model terms are on the
  [site's licence page](https://modesty.cia.org.il/?p=licenses).
