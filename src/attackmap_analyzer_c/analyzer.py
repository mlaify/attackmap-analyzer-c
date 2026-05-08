"""C ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: civetweb (mg_set_request_handler routes), libmicrohttpd
  (MHD_start_daemon entrypoint), mongoose (mg_http_listen entrypoint +
  mg_http_match_uri pseudo-routes), libonion (onion_url_add routes)
- HTTP clients (external calls): libcurl (CURLOPT_URL string literals)
- Databases: sqlite3 (sqlite3_open*), libpq (PQconnectdb*), MySQL/MariaDB C
  client (mysql_real_connect), hiredis (redisConnect*), MongoDB C driver
  (mongoc_client_new)
- Auth/crypto: OpenSSL (broad framework hint via EVP_/SSL_/RSA_), mbedTLS,
  libsodium (crypto_pwhash, crypto_secretbox), Argon2 reference impl,
  bcrypt-c, scrypt
- Secrets: getenv / secure_getenv / getenv_s with secret-shaped names
- Service hints: project name from CMakeLists.txt

C is more fragmented than other ecosystems — there's no single dominant
HTTP framework, and routing patterns vary widely. We capture what regex
can reach reliably and conservatively confidence-tag pattern hits.
"""

from __future__ import annotations

import re
from pathlib import Path

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".c", ".h"}
SKIP_DIRS = {
    "build",
    ".git",
    "_deps",
    "third_party",
    "vendor",
    "external",
    ".cache",
    "out",
    "node_modules",
}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# civetweb: mg_set_request_handler(ctx, "/path", handler, NULL)
CIVETWEB_ROUTE_PATTERN = re.compile(
    r'\bmg_set_request_handler\s*\(\s*\w+\s*,\s*"([^"]+)"',
)

# mongoose: mg_http_match_uri(hm, "/path") inside an event handler — pseudo-routes
MONGOOSE_MATCH_URI_PATTERN = re.compile(
    r'\bmg_http_match_uri\s*\(\s*\w+\s*,\s*"([^"]+)"',
)

# libonion: onion_url_add(url, "^/path/?$", handler, ...)
ONION_ROUTE_PATTERN = re.compile(
    r'\bonion_url_add(?:_static|_with_data)?\s*\(\s*\w+\s*,\s*"([^"]+)"',
)

# libcurl: curl_easy_setopt(handle, CURLOPT_URL, "https://...")
LIBCURL_URL_PATTERN = re.compile(
    r'\bcurl_easy_setopt\s*\(\s*\w+\s*,\s*CURLOPT_URL\s*,\s*"(https?://[^"]+)"',
)

# DBs
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bsqlite3_open(?:_v2)?\s*\('), "sqlite"),
    (re.compile(r'\bPQconnectdb(?:Params)?\s*\(|\bPQsetdbLogin\s*\('), "postgresql"),
    (re.compile(r'\bmysql_real_connect\s*\(|\bmariadb_real_connect\s*\('), "mysql"),
    (re.compile(r'\bredisConnect(?:WithTimeout)?\s*\('), "redis"),
    (re.compile(r'\bmongoc_client_new\s*\(|\bmongoc_uri_new\s*\('), "mongodb"),
]

# Auth / crypto
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'\bcrypto_pwhash(?:_argon2(?:i|id))?\s*\(|\bcrypto_pwhash_str\s*\('), "argon2", 0.9),
    (re.compile(r'\bargon2(?:i|d|id)?_hash\w*\s*\('), "argon2", 0.9),
    (re.compile(r'\bbcrypt(?:_hashpw|_checkpw|_gensalt)?\s*\('), "bcrypt", 0.9),
    (re.compile(r'\bscrypt(?:_kdf)?\s*\('), "scrypt", 0.9),
    (re.compile(r'\bcrypto_secretbox\w*\s*\(|\bcrypto_aead_(?:chacha20poly1305|aes256gcm)\w*\s*\('), "libsodium_aead", 0.85),
    (re.compile(r'\bSSL_CTX_new\s*\(|\bSSL_new\s*\(|\bTLS_method\s*\(|\bTLS_(?:client|server)_method\s*\('), "openssl_tls", 0.85),
    (re.compile(r'\bEVP_PKEY_new\s*\(|\bEVP_(?:Encrypt|Decrypt)Init\w*\s*\('), "openssl_evp", 0.8),
    (re.compile(r'\bRAND_bytes\s*\(|\bRAND_priv_bytes\s*\('), "openssl_rand", 0.8),
    (re.compile(r'\bmbedtls_(?:ssl|x509)_\w+\s*\('), "mbedtls", 0.85),
    (re.compile(r'\bjwt_(?:encode|decode|new|verify)\s*\('), "jwt", 0.85),
    (re.compile(r'\bAuthorization\b'), "authorization_header", 0.6),
    (re.compile(r'\bBearer\b'), "bearer_token", 0.6),
    (re.compile(r'\bapi[_-]?key\b', re.IGNORECASE), "api_key", 0.6),
]

FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bMHD_start_daemon\s*\(|\bMHD_create_response\w*\s*\(|#\s*include\s+["<]microhttpd\.h'), "libmicrohttpd"),
    (re.compile(r'\bmg_start\s*\(|\bmg_set_request_handler\s*\(|#\s*include\s+["<]civetweb\.h'), "civetweb"),
    (re.compile(r'\bmg_mgr_init\s*\(|\bmg_http_listen\s*\(|#\s*include\s+["<]mongoose\.h'), "mongoose"),
    (re.compile(r'\bonion_new\s*\(|\bonion_listen\s*\(|#\s*include\s+["<]onion/onion\.h'), "libonion"),
    (re.compile(r'#\s*include\s+["<]openssl/'), "openssl"),
    (re.compile(r'#\s*include\s+["<]mbedtls/'), "mbedtls"),
    (re.compile(r'#\s*include\s+["<]sodium\.h'), "libsodium"),
    (re.compile(r'#\s*include\s+["<]curl/curl\.h'), "libcurl"),
    (re.compile(r'#\s*include\s+["<]sqlite3\.h'), "sqlite3"),
    (re.compile(r'#\s*include\s+["<]libpq-fe\.h'), "libpq"),
    (re.compile(r'#\s*include\s+["<]hiredis/hiredis\.h'), "hiredis"),
    (re.compile(r'#\s*include\s+["<]mongoc/mongoc\.h|#\s*include\s+["<]mongoc\.h'), "mongoc"),
]

ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bMHD_start_daemon\s*\('), "mhd_start_daemon"),
    (re.compile(r'\bmg_start\s*\('), "civetweb_start"),
    (re.compile(r'\bmg_http_listen\s*\('), "mongoose_http_listen"),
    (re.compile(r'\bonion_listen\s*\('), "onion_listen"),
    (re.compile(r'\baccept\s*\(\s*\w+\s*,\s*\(struct\s+sockaddr\s*\*\)'), "raw_socket_accept"),
]

# Secrets via getenv / secure_getenv / getenv_s
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\b(?:secure_)?getenv\s*\(\s*"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
    re.compile(
        r'\bgetenv_s\s*\([^,]*,\s*[^,]*,\s*"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
]


def _line_of(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _project_name_from_cmake(cmake_path: Path) -> str | None:
    if not cmake_path.exists():
        return None
    try:
        text = cmake_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    match = re.search(r"\bproject\s*\(\s*([A-Za-z0-9_\-]+)", text)
    if match:
        return match.group(1)
    return None


class CAnalyzer:
    metadata = AnalyzerMetadata(
        name="c",
        display_name="C Analyzer",
        version="0.1.0",
        description="C ecosystem analyzer covering libmicrohttpd, civetweb, mongoose, libonion, libcurl, OpenSSL, libsodium, sqlite3, libpq, mysql, hiredis, mongoc.",
        scope="C source trees and CMake/Make projects. Detects HTTP server entrypoints, libcurl outbound calls, common DB and crypto libraries.",
        targets=["c", "civetweb", "libmicrohttpd", "mongoose"],
        languages=["c"],
        priority=20,
        experimental=True,  # C ecosystem coverage is heuristic and partial; mark experimental.
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix in CODE_SUFFIXES:
                return True
            if path.name in {"CMakeLists.txt", "Makefile"}:
                # Disambiguate: a CMake project may be C++ rather than C. Only return True
                # when there's at least one .c file alongside it; otherwise let the C++
                # analyzer claim the repo.
                for sibling in path.parent.rglob("*.c"):
                    if any(part in SKIP_DIRS for part in sibling.parts):
                        continue
                    return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        for cmake in root.rglob("CMakeLists.txt"):
            if any(part in SKIP_DIRS for part in cmake.parts):
                continue
            project = _project_name_from_cmake(cmake)
            if project:
                self._append_unique_service(result, f"project:{project}", str(cmake.relative_to(root)))

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            if file_path.suffix not in CODE_SUFFIXES:
                continue

            result.files_scanned += 1
            if "c" not in result.languages:
                result.languages.append("c")

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        for match in CIVETWEB_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))
        for match in MONGOOSE_MATCH_URI_PATTERN.finditer(content):
            path = match.group(1)
            self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))
        for match in ONION_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1)
                self._append_unique_secret(
                    result, name, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for match in LIBCURL_URL_PATTERN.finditer(content):
            target = match.group(1)
            self._append_unique_external(
                result, target, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int | None) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["CAnalyzer"]
