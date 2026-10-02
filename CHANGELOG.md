# Changelog

All notable changes to `attackmap-analyzer-c` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a local `rglob` + `SKIP_DIRS` walk (mlaify/AttackMap#253).
- The analyzer is now opt-in while experimental (`enabled_by_default=False`): run it with `attackmap analyze <repo> -m c` (mlaify/AttackMap#221).

### Fixed

- `.h` headers in C++ repos are no longer analyzed as C. Ownership is decided per repo by the rule shared with attackmap-analyzer-cpp: any C++ source/header or a C++-enabled `CMakeLists.txt` makes `.h` C++'s, otherwise it is C's. Drogon controllers declared in `.h` stop being labelled language `c` (#2).
- `detect()` requires at least one `.c` file. A lone `.h`, such as an ObjC/Swift bridging header or a Python C-extension header, no longer triggers the C analyzer (#2).
- `detect()` makes one walk. The quadratic nested `rglob("*.c")` per `CMakeLists.txt`/`Makefile` was already removed by the `attackmap.sdk` walker migration above; a regression test now asserts a single `os.walk` and no `rglob` (#2).
- A repo checked out under a directory named like a skip dir (e.g. `/build/...`, `.../out/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo are no longer followed and analyzed.
- cp1252/latin-1 encoded sources are analyzed instead of silently dropped, and an unreadable file no longer raises out of `analyze()`.
- `files_scanned` no longer counts files that could not be read.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. C ecosystem analyzer plugin for AttackMap (libmicrohttpd, civetweb, mongoose; libcurl; OpenSSL/mbedTLS/libsodium; sqlite3/libpq/mysql/hiredis/mongoc).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-c/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-c/releases/tag/v0.1.0
