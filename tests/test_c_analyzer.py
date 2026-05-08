"""Tests for the CAnalyzer plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap_analyzer_c import CAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_c_file(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    assert CAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_header_file(tmp_path: Path) -> None:
    (tmp_path / "api.h").write_text("#pragma once\nint foo(void);\n", encoding="utf-8")
    assert CAnalyzer().detect(tmp_path) is True


def test_detect_skips_build_dir(tmp_path: Path) -> None:
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "stale.c").write_text("int main() { return 0; }\n", encoding="utf-8")
    assert CAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_for_empty(tmp_path: Path) -> None:
    assert CAnalyzer().detect(tmp_path) is False


def test_detect_cmake_only_without_c_files_does_not_claim(tmp_path: Path) -> None:
    """A CMakeLists.txt next to .cpp files belongs to the C++ analyzer, not C."""
    (tmp_path / "CMakeLists.txt").write_text("project(demo)\n", encoding="utf-8")
    (tmp_path / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
    assert CAnalyzer().detect(tmp_path) is False


# ---------- Routes ----------


def test_civetweb_set_request_handler(tmp_path: Path) -> None:
    (tmp_path / "app.c").write_text(
        '#include <civetweb.h>\n'
        '\n'
        'int main(void) {\n'
        '    struct mg_context *ctx = mg_start(NULL, NULL, NULL);\n'
        '    mg_set_request_handler(ctx, "/api/users", users_handler, NULL);\n'
        '    mg_set_request_handler(ctx, "/health", health_handler, NULL);\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "/api/users" in paths
    assert "/health" in paths

    users = next(r for r in result.routes if r.path == "/api/users")
    assert users.line == 5


def test_mongoose_match_uri_emits_pseudo_routes(tmp_path: Path) -> None:
    (tmp_path / "handler.c").write_text(
        '#include <mongoose.h>\n'
        '\n'
        'static void handler(struct mg_connection *c, int ev, void *ev_data) {\n'
        '    if (ev == MG_EV_HTTP_MSG) {\n'
        '        struct mg_http_message *hm = (struct mg_http_message *)ev_data;\n'
        '        if (mg_http_match_uri(hm, "/api/login")) {\n'
        '            login(c, hm);\n'
        '        } else if (mg_http_match_uri(hm, "/admin/*")) {\n'
        '            admin(c, hm);\n'
        '        }\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "/api/login" in paths
    assert "/admin/*" in paths


def test_libonion_url_add(tmp_path: Path) -> None:
    (tmp_path / "app.c").write_text(
        '#include <onion/onion.h>\n'
        '\n'
        'void setup(onion_url *url) {\n'
        '    onion_url_add(url, "^/users/?$", users_handler);\n'
        '    onion_url_add_static(url, "^/static/", "./public", 0);\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "^/users/?$" in paths
    assert "^/static/" in paths


# ---------- HTTP clients ----------


def test_libcurl_url_extracted(tmp_path: Path) -> None:
    (tmp_path / "client.c").write_text(
        '#include <curl/curl.h>\n'
        '\n'
        'int fetch(void) {\n'
        '    CURL *curl = curl_easy_init();\n'
        '    curl_easy_setopt(curl, CURLOPT_URL, "https://api.stripe.com/v1/charges");\n'
        '    return curl_easy_perform(curl);\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


def test_curlopt_url_with_non_url_string_skipped(tmp_path: Path) -> None:
    (tmp_path / "client.c").write_text(
        'curl_easy_setopt(curl, CURLOPT_URL, "/local/path");\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert result.external_calls == []


# ---------- Databases ----------


def test_sqlite_open(tmp_path: Path) -> None:
    (tmp_path / "db.c").write_text(
        '#include <sqlite3.h>\n'
        '\n'
        'sqlite3 *open_db(void) {\n'
        '    sqlite3 *db;\n'
        '    sqlite3_open("data.db", &db);\n'
        '    return db;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert any(d.kind == "sqlite" for d in result.databases)


def test_libpq_connect(tmp_path: Path) -> None:
    (tmp_path / "pg.c").write_text(
        '#include <libpq-fe.h>\n'
        'PGconn *connect_db(void) {\n'
        '    return PQconnectdb("host=localhost dbname=app");\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


def test_mysql_and_redis_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "mysql.c").write_text(
        'MYSQL *m = mysql_init(NULL);\n'
        'mysql_real_connect(m, "host", "user", "pass", "db", 3306, NULL, 0);\n',
        encoding="utf-8",
    )
    (tmp_path / "redis.c").write_text(
        '#include <hiredis/hiredis.h>\n'
        'redisContext *c = redisConnect("127.0.0.1", 6379);\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "mysql" in kinds
    assert "redis" in kinds


def test_mongoc_emits_mongodb(tmp_path: Path) -> None:
    (tmp_path / "mongo.c").write_text(
        '#include <mongoc/mongoc.h>\n'
        'int main(void) {\n'
        '    mongoc_client_t *client = mongoc_client_new("mongodb://x");\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert any(d.kind == "mongodb" for d in result.databases)


# ---------- Auth / crypto ----------


def test_libsodium_pwhash_emits_argon2_hint(tmp_path: Path) -> None:
    (tmp_path / "auth.c").write_text(
        '#include <sodium.h>\n'
        'int hash(const char *pw, char *out) {\n'
        '    return crypto_pwhash_str(out, pw, strlen(pw),\n'
        '        crypto_pwhash_OPSLIMIT_INTERACTIVE,\n'
        '        crypto_pwhash_MEMLIMIT_INTERACTIVE);\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "argon2" in by_hint
    assert by_hint["argon2"].confidence == 0.9


def test_argon2_reference_impl_emits_hint(tmp_path: Path) -> None:
    (tmp_path / "auth.c").write_text(
        '#include "argon2.h"\n'
        'int verify(const char *pw, const char *encoded) {\n'
        '    return argon2id_hash_encoded(2, 1<<16, 1, pw, strlen(pw), salt, 16, 32, encoded, sizeof(encoded));\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert any(h.hint == "argon2" for h in result.auth_hints)


def test_openssl_tls_setup_emits_hint(tmp_path: Path) -> None:
    (tmp_path / "tls.c").write_text(
        '#include <openssl/ssl.h>\n'
        'SSL_CTX *create(void) {\n'
        '    return SSL_CTX_new(TLS_server_method());\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert any(h.hint == "openssl_tls" for h in result.auth_hints)


# ---------- Secrets ----------


def test_getenv_secrets(tmp_path: Path) -> None:
    (tmp_path / "config.c").write_text(
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    const char *jwt = getenv("JWT_SECRET");\n'
        '    const char *db = getenv("DATABASE_PASSWORD");\n'
        '    const char *api = secure_getenv("STRIPE_API_KEY");\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names
    assert "STRIPE_API_KEY" in names

    jwt = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt.line == 3


def test_getenv_with_non_secret_name_skipped(tmp_path: Path) -> None:
    (tmp_path / "config.c").write_text(
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    const char *home = getenv("HOME");\n'
        '    const char *path = getenv("PATH");\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    assert result.secret_hints == []


# ---------- Frameworks + entrypoints ----------


def test_libmicrohttpd_framework_and_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text(
        '#include <microhttpd.h>\n'
        '\n'
        'int main(void) {\n'
        '    struct MHD_Daemon *d = MHD_start_daemon(\n'
        '        MHD_USE_THREAD_PER_CONNECTION, 8888, NULL, NULL, &handler, NULL,\n'
        '        MHD_OPTION_END);\n'
        '    return d ? 0 : 1;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "libmicrohttpd" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "mhd_start_daemon" in ep


def test_civetweb_framework_and_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text(
        '#include <civetweb.h>\n'
        'int main(void) {\n'
        '    struct mg_context *ctx = mg_start(NULL, NULL, NULL);\n'
        '    return ctx ? 0 : 1;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "civetweb" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "civetweb_start" in ep


def test_mongoose_framework_and_listen(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text(
        '#include <mongoose.h>\n'
        'int main(void) {\n'
        '    struct mg_mgr mgr;\n'
        '    mg_mgr_init(&mgr);\n'
        '    mg_http_listen(&mgr, "http://0.0.0.0:8080", handler, NULL);\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "mongoose" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "mongoose_http_listen" in ep


# ---------- CMake → service hint ----------


def test_cmake_project_name_picked_up(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.10)\n'
        'project(billing-api LANGUAGES C)\n'
        'add_executable(billing src/main.c)\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    result = CAnalyzer().analyze(tmp_path)
    assert any(h.hint == "project:billing-api" for h in result.service_hints)


# ---------- End-to-end ----------


def test_full_civetweb_service_signal_set(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        'project(demo-svc LANGUAGES C)\nadd_executable(demo src/main.c)\n',
        encoding="utf-8",
    )
    src = tmp_path / "src" / "main.c"
    src.parent.mkdir()
    src.write_text(
        '#include <civetweb.h>\n'
        '#include <curl/curl.h>\n'
        '#include <sqlite3.h>\n'
        '#include <openssl/ssl.h>\n'
        '#include <stdlib.h>\n'
        '\n'
        'int main(void) {\n'
        '    const char *jwt = getenv("JWT_SECRET");\n'
        '    sqlite3 *db; sqlite3_open("data.db", &db);\n'
        '    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());\n'
        '    CURL *curl = curl_easy_init();\n'
        '    curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com/data");\n'
        '\n'
        '    struct mg_context *srv = mg_start(NULL, NULL, NULL);\n'
        '    mg_set_request_handler(srv, "/login", login_handler, NULL);\n'
        '    mg_set_request_handler(srv, "/admin", admin_handler, NULL);\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )

    result = CAnalyzer().analyze(tmp_path)

    paths = {r.path for r in result.routes}
    assert "/login" in paths
    assert "/admin" in paths

    assert any(d.kind == "sqlite" for d in result.databases)
    assert any(h.hint == "openssl_tls" for h in result.auth_hints)
    assert any(s.name == "JWT_SECRET" for s in result.secret_hints)
    assert any(e.target == "https://api.example.com/data" for e in result.external_calls)
    assert any(f.hint == "civetweb" for f in result.framework_hints)
    assert any(e.hint == "civetweb_start" for e in result.entrypoint_hints)
    assert any(h.hint == "project:demo-svc" for h in result.service_hints)
