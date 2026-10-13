# Changelog

All notable changes to `attackmap-analyzer-c` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Memory-safety and command-exec sinks (mlaify/AttackMap#189).** A new `native_sinks.py` pass emits `CodeWeakness` records for:
  - `unbounded_copy`: `gets`, unbounded `scanf` `%s`, and `strcpy`/`strcat`/`sprintf` from traced input;
  - `format_string`: non-constant printf-family formats;
  - `native_command_exec`: `system`/`popen`/`exec*`;
  - `tainted_copy_length`: input-controlled `memcpy` lengths;
  - `alloc_size_overflow`: unchecked `malloc(n * size)`.

  Sources are traced inside each function: civetweb, mongoose and libmicrohttpd request accessors, socket reads, stdin, argv, getenv and file reads. Severity and confidence follow the source: remote input high, local input medium, untraced low. Example code is capped at low and test/fuzz code is skipped. Validated on civetweb, mongoose, cpp-httplib, drogon, Crow, restbed and oat++ example-crud. Requires an AttackMap core that exports `CodeWeakness` (mlaify/AttackMap#333).

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
