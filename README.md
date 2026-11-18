<p align="center">
  <img src="assets/logo.svg" alt="Modesty" width="110" height="110">
</p>

<p align="center">
  <img src="assets/modesty-brand.svg" alt="Modesty — NSFW protection" width="260">
</p>

# modesty-webservice

> HTTP API service

Python HTTP service exposing the open `/v1` protocol (`/v1/hash`, `/v1/sample`) with a SQLite result cache.

## Layout

| Path | What |
|---|---|
| `src/` | source from the monorepo |
| `tests/` | source from the monorepo |

## Details

| | |
|---|---|
| Language | Python |
| License | MIT |
| Website | [https://modesty.cia.org.il](https://modesty.cia.org.il) |
| Repository map | [REPO_MAP.md](https://github.com/sniffis-commits/nfsw_scanner/blob/main/docs/REPO_MAP.md) |
| Split from | private monorepo `sniffis-commits/nfsw_scanner` |

## Quick start

```sh
python src/server.py --port 8099
```

## About Modesty

Privacy-first NSFW scanner. Local scanning by default; uploads are opt-in.
These public repos are split from a private monorepo — see the
[repository map](https://github.com/sniffis-commits/nfsw_scanner/blob/main/docs/REPO_MAP.md) for the full local-to-GitHub naming. Model weights are
in `modesty-models`; the free domain DB release is in `modesty-db`.

Third-party data/model terms are on the [site's license page](https://modesty.cia.org.il/?p=licenses).
