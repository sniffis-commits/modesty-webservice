<!-- logo -->
<p align="center">
  <img src="https://modesty.eu.org/images/logos/modesty-webservice.svg" alt="Modesty" width="96" height="96">
</p>

# modesty-webservice

> HTTP API service

Python HTTP service exposing the open `/v1` protocol (`/v1/hash`, `/v1/sample`) with a SQLite result cache. Uploaded media is deleted after scanning; hashes and verdicts are retained.

## Details

| | |
|---|---|
| Language | Python |
| License | MIT |
| Website | [https://modesty.eu.org](https://modesty.eu.org) |
| Full repository map | [REPO_MAP.md](https://github.com/sniffis-commits/nfsw_scanner/blob/main/docs/REPO_MAP.md) |
| Status | Scaffold — code is being split from the private monorepo |

## Quick start

```sh
python packages/nsfw-webservice/src/server.py --port 8099
```

## About Modesty

Modesty is a privacy-first NSFW content scanner. Scanning runs locally by
default; uploads are always opt-in. The public packages are split out of the
private monorepo into standalone repositories — see the
[repository map](https://github.com/sniffis-commits/nfsw_scanner/blob/main/docs/REPO_MAP.md) for the full local-to-GitHub naming.

Licensed under MIT. See the website's
[license review](https://modesty.eu.org/?p=licenses) for third-party data and model terms.
