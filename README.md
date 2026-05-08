# attackmap-analyzer-c

C ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

C is more fragmented than language-specific ecosystems — there's no dominant web framework, and routing patterns vary widely. This analyzer captures what regex can reach reliably from common third-party libraries.

- **Web frameworks** — civetweb (`mg_set_request_handler` extracts routes), libmicrohttpd (`MHD_start_daemon` entrypoint), mongoose (`mg_http_listen` entrypoint + `mg_http_match_uri` pseudo-routes), libonion (`onion_url_add` routes)
- **HTTP clients (external calls)** — libcurl (`curl_easy_setopt(handle, CURLOPT_URL, "...")` URL string literals)
- **Databases** — sqlite3 (`sqlite3_open*`), libpq (`PQconnectdb*`, `PQsetdbLogin`), MySQL/MariaDB C client (`mysql_real_connect`, `mariadb_real_connect`), hiredis (`redisConnect*`), MongoDB C driver (`mongoc_client_new`)
- **Auth/crypto** — OpenSSL (TLS context, EVP cipher, RAND), mbedTLS (SSL/X.509), libsodium (`crypto_pwhash`, `crypto_secretbox`, `crypto_aead_*`), Argon2 reference impl (`argon2id_hash_*`), bcrypt-c, scrypt, JWT C libraries (`jwt_encode`, `jwt_decode`)
- **Secrets** — `getenv`, `secure_getenv`, `getenv_s` with secret-shaped names (`*SECRET*`, `*TOKEN*`, `*KEY*`, `*PASSWORD*`, `*PASS*`, `*PWD*`)
- **Service hints** — project name from `CMakeLists.txt` (`project(NAME ...)`)

All emissions populate AttackMap's Signal v2 fields (line numbers + evidence snippets + confidence) so downstream insights can cite `path/to/file.c:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-c.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/c/repo

# Or invoke explicitly:
attackmap analyze /path/to/c/repo --module c
```

## Detection

`detect()` returns true when any `.c` or `.h` file is present in the tree, ignoring `build/`, `.git/`, `_deps/`, `third_party/`, `vendor/`, `external/`, `.cache/`, `out/`, and `node_modules/`. A `CMakeLists.txt` alongside `.cpp` files (and no `.c` files) is **not** claimed by this analyzer — that's the C++ analyzer's territory.

## Coverage notes

- **Marked experimental**: regex-based extraction in C has more false positives than language-with-strict-imports analyzers. Keep the confidence-tier model in mind when consuming output (0.6 keyword sweeps vs. 0.85+ canonical function-name hits).
- **Routes**: civetweb / mongoose / libonion all expose path strings explicitly in their routing API; libmicrohttpd does not (single-callback dispatch on `url`). For libmicrohttpd, only the entrypoint is captured — per-route URLs would need to be regexed out of `if (strcmp(url, "/x") == 0)` patterns inside the answer-callback.
- **HTTP method on routes**: the C web frameworks covered here don't statically declare HTTP methods at registration time (handlers branch on method internally), so all routes are emitted with method `ANY`.
- **OpenSSL EVP / RAND** signals are confidence 0.8 — they're broad indicators of crypto usage but not strong defensive signals on their own.
- **Authorization / Bearer / api_key keyword matches** are tier-0.6 (low confidence). They're useful as supporting evidence for an auth posture, not as load-bearing.
- **Hardcoded `#define JWT_SECRET "abc..."` macros** are not extracted — too noisy. `getenv("JWT_SECRET")` is the canonical pattern we rely on.

## License

MIT
