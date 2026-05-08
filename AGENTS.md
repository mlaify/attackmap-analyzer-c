# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
C ecosystem coverage:

- **Web frameworks**: civetweb (`mg_set_request_handler` routes + `mg_start` entrypoint), libmicrohttpd (`MHD_start_daemon` entrypoint), mongoose (`mg_http_listen` + `mg_http_match_uri` pseudo-routes), libonion (`onion_url_add*` routes)
- **HTTP clients**: libcurl (`CURLOPT_URL` literal extraction)
- **Databases**: sqlite3, libpq, MySQL/MariaDB C client, hiredis, MongoDB C driver
- **Auth/crypto**: OpenSSL (TLS / EVP / RAND), mbedTLS, libsodium (`crypto_pwhash` → argon2; AEAD primitives), Argon2 / bcrypt / scrypt reference impls, JWT C libs
- **Secrets**: `getenv` / `secure_getenv` / `getenv_s` with secret-shaped names

## Out of scope (for now)
- libmicrohttpd per-route extraction — single-callback routing dispatches on `url` inside the handler; we'd need to regex out `if (strcmp(url, "/x") == 0)` patterns to recover paths.
- nginx / Apache HTTP Server module routing — too narrow to justify dedicated patterns.
- Hardcoded `#define JWT_SECRET "abc"` macros — high false-positive rate; we rely on `getenv` as the canonical pattern.
- Custom raw-socket servers (`socket() / bind() / listen() / accept()`) without a framework wrapper — only the `accept()` entrypoint is tagged, low signal.

## Marked experimental
This analyzer is marked `experimental=True` on its metadata because:
- C's lack of namespacing means common identifiers (`Authorization`, `key`, `bearer`) appear in many non-security contexts.
- HTTP-method information is not available at registration time for the supported frameworks; all routes emit method `ANY`.
- Confidence tiering is the primary defense against false-positive overload — see below.

## Confidence policy
- Hash-class auth primitives (`crypto_pwhash`, `argon2id_hash_*`, `bcrypt_*`, `scrypt`) → 0.9
- Canonical TLS / cipher / JWT API hits (`SSL_CTX_new`, `EVP_*`, `jwt_encode`, `mbedtls_ssl_*`) → 0.85
- Generic `EVP` / `RAND` family → 0.8
- Keyword sweeps (`Authorization`, `Bearer`, `api_key`) → 0.6

## C-vs-C++ disambiguation
A repo with a `CMakeLists.txt` next to `.cpp` files but no `.c` files is **not** claimed by this analyzer; the C++ analyzer (`attackmap-analyzer-cpp`) takes precedence. A repo with both `.c` and `.cpp` files is claimed by both — and AttackMap's overlay merges results.

## Testing
Each new extractor needs both a positive test and a negative test (e.g., `getenv("HOME")` is NOT a secret; `curl_easy_setopt(curl, CURLOPT_URL, "/local/path")` is NOT an external call).
