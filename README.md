# attackmap-analyzer-c

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

C ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

C is more fragmented than language-specific ecosystems — there's no dominant web framework, and routing patterns vary widely. This analyzer captures what regex can reach reliably from common third-party libraries.

- **Web frameworks** — civetweb (`mg_set_request_handler` extracts routes), libmicrohttpd (`MHD_start_daemon` entrypoint), mongoose (`mg_http_listen` entrypoint + `mg_http_match_uri` pseudo-routes), libonion (`onion_url_add` routes)
- **HTTP clients (external calls)** — libcurl (`curl_easy_setopt(handle, CURLOPT_URL, "...")` URL string literals)
- **Databases** — sqlite3 (`sqlite3_open*`), libpq (`PQconnectdb*`, `PQsetdbLogin`), MySQL/MariaDB C client (`mysql_real_connect`, `mariadb_real_connect`), hiredis (`redisConnect*`), MongoDB C driver (`mongoc_client_new`)
- **Auth/crypto** — OpenSSL (TLS context, EVP cipher, RAND), mbedTLS (SSL/X.509), libsodium (`crypto_pwhash`, `crypto_secretbox`, `crypto_aead_*`), Argon2 reference impl (`argon2id_hash_*`), bcrypt-c, scrypt, JWT C libraries (`jwt_encode`, `jwt_decode`)
- **Secrets** — `getenv`, `secure_getenv`, `getenv_s` with secret-shaped names (`*SECRET*`, `*TOKEN*`, `*KEY*`, `*PASSWORD*`, `*PASS*`, `*PWD*`)
- **Service hints** — project name from `CMakeLists.txt` (`project(NAME ...)`)
- **Dependencies (SBOM)** — vcpkg, Conan and CMake manifests, so `--cve` reaches native dependencies; unpinned CMake downloads are reported as supply-chain issues (see [Dependencies](#dependencies))

All emissions populate AttackMap's Signal v2 fields (line numbers + evidence snippets + confidence) so downstream insights can cite `path/to/file.c:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-c.git
```

The analyzer is registered with AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

This analyzer is **experimental and opt-in** (`enabled_by_default=False`): installing it does not make it run on every scan. Select it explicitly:

```bash
attackmap analyze /path/to/c/repo -m c
```

## Detection

`detect()` returns true when at least one `.c` file is present in the tree (a lone `.h`, such as an ObjC/Swift bridging header, doesn't count), in a single walk, ignoring `_deps/`, `third_party/`, `external/`, `.cache/` and AttackMap's shared skip list (`build/`, `out/`, `vendor/`, `node_modules/`, `.git/`, ...). Skip directories are matched only *inside* the repo, so a checkout under e.g. `/build/...` is still scanned. Files are walked with `attackmap.sdk.iter_repo_files`, which does not follow symlinks out of the repo, and read with `read_source`, which falls back to cp1252/latin-1 for legacy-encoded sources. A `CMakeLists.txt` alongside `.cpp` files (and no `.c` files) is **not** claimed by this analyzer — that's the C++ analyzer's territory.

### `.h` ownership

`.h` ownership is decided per repo, by the same rule in both the C and C++ analyzers, so exactly one of them analyzes each header whichever of `-m c` / `-m cpp` is selected:

- `.h` belongs to **C++** if the repo has any C++ source or header (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.ipp`, `.tpp`) or a `CMakeLists.txt` that enables CXX (`project(... CXX ...)`, `enable_language(CXX)` or `CMAKE_CXX_STANDARD`). A bare `project(foo)` doesn't count.
- Otherwise `.h` belongs to **C**.
- Files under directories either plugin prunes (`build/`, `third_party/`, `Debug/`, `Release/`, ...) are never markers.

In a mixed repo, `.c` files go to C, and `.cpp`/`.hpp`/... plus `.h` go to C++. Running only one of the two analyzers on a mixed repo leaves the other's files unanalyzed. It never double-counts them.

## Dependencies

`native_deps.py` emits `DependencyHint`s (mlaify/AttackMap#191). The module is shared verbatim with attackmap-analyzer-cpp. Core dedupes identical records when both analyzers run.

| Source | Ecosystem | Version | `dev` |
|---|---|---|---|
| `vcpkg.json` `dependencies` | `vcpkg` | `overrides` pin (`resolved=True`), else `>=` from `version>=`, else empty (the `builtin-baseline` decides; it's recorded in the evidence) | `"host": true` |
| `conanfile.txt` `[requires]` / `[tool_requires]` / `[build_requires]` / `[test_requires]` | `conan` | as written (`1.2.13`, `[>=1.80 <2.0]`) | tool/build/test sections |
| `conanfile.py` `requires = ...`, `self.requires("x/1.0")` and the tool/build/test forms (read as text, never executed) | `conan` | as written | tool/build/test |
| `conan.lock` | `conan` | exact (`resolved=True`) | `build_requires` |
| CMake `FetchContent_Declare` / `ExternalProject_Add` / `CPMAddPackage` | `cmake` | `GIT_TAG`, a CPM version, or a version in the archive URL | test/example manifests, test frameworks |
| CMake `find_package(Name [version] [EXACT])` | `cmake` | `>=version` / `==version` | test/example manifests, test frameworks |

`cmake` is inventory-only in core: it has no OSV database, so `--cve` reports those dependencies as not CVE-checked. `conan` and `vcpkg` map to OSV ConanCenter and vcpkg. Build tools and CMake modules (`Threads`, `PkgConfig`, `Python3`, `Git`...) aren't dependencies.

**Unpinned downloads** are `SupplyChainIssue(kind="mutable_vcs_dependency")` records:

| Download | Severity |
|---|---|
| git download with no `GIT_TAG`, or a `GIT_TAG` that names a branch (`main`, `master`, `develop`...) | medium |
| any other tag or a short SHA | low |
| a full 40-hex commit SHA | not flagged |
| `URL` download without `URL_HASH`/`URL_MD5` | medium |

Values that are CMake variables (`${X}`) are never flagged.

## Coverage notes

- **Marked experimental**: regex-based extraction in C has more false positives than language-with-strict-imports analyzers. Keep the confidence-tier model in mind when consuming output (0.6 keyword sweeps vs. 0.85+ canonical function-name hits).
- **Routes**: civetweb / mongoose / libonion all expose path strings explicitly in their routing API; libmicrohttpd does not (single-callback dispatch on `url`). For libmicrohttpd, only the entrypoint is captured — per-route URLs would need to be regexed out of `if (strcmp(url, "/x") == 0)` patterns inside the answer-callback.
- **HTTP method on routes**: the C web frameworks covered here don't statically declare HTTP methods at registration time (handlers branch on method internally), so all routes are emitted with method `ANY`.
- **OpenSSL EVP / RAND** signals are confidence 0.8 — they're broad indicators of crypto usage but not strong defensive signals on their own.
- **Authorization / Bearer / api_key keyword matches** are tier-0.6 (low confidence). They're useful as supporting evidence for an auth posture, not as load-bearing.
- **Hardcoded `#define JWT_SECRET "abc..."` macros** are not extracted — too noisy. `getenv("JWT_SECRET")` is the canonical pattern we rely on.

## License

MIT
