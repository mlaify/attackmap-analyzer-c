"""Native memory-safety and command-exec sinks (AttackMap#189).

``native_sinks.py`` and this file are mirrored in attackmap-analyzer-cpp;
the C++ copy adds C++ framework cases. Each detector has positive and
negative cases; severity follows the source traced in the same function.
"""

from __future__ import annotations

import random
import re
import time
from pathlib import Path

import pytest

from attackmap_analyzer_c import CAnalyzer
from attackmap_analyzer_c.native_sinks import find_native_weaknesses, is_test_path, mask_source

FIXTURES = Path(__file__).parent / "fixtures" / "native"


def _hits(code: str, path: str = "src/server.c") -> list[tuple[int, str, str, str | None]]:
    """(line, kind, severity, source_kind) per weakness."""
    return [(w.line, w.kind, w.severity, w.source_kind) for w in find_native_weaknesses(code, path)]


def _kinds(code: str, path: str = "src/server.c") -> list[str]:
    return [k for _, k, _, _ in _hits(code, path)]


def _fn(body: str, params: str = "struct mg_connection *conn, void *cbdata") -> str:
    return f"int handler({params}) {{\n{body}\n}}\n"


CIVET_SOURCE = (
    "    char name[64];\n"
    "    const struct mg_request_info *ri = mg_get_request_info(conn);\n"
    '    const char *q = ri->query_string;\n'
)


# ---------- unbounded_copy ----------


def test_strcpy_from_request_is_high() -> None:
    code = _fn(CIVET_SOURCE + "    char buf[16];\n    strcpy(buf, q);")
    assert _hits(code) == [(6, "unbounded_copy", "high", "request")]


def test_strcpy_from_argv_is_medium() -> None:
    code = "int main(int argc, char **argv) {\n    char small[16];\n    strcpy(small, argv[1]);\n}\n"
    assert _hits(code) == [(3, "unbounded_copy", "medium", "argv")]


@pytest.mark.parametrize(
    "body",
    [
        '    strcpy(buf, "literal");',  # literal source
        "    strcpy(buf, other);",  # untraced source: not reported
        "    if (strlen(q) < sizeof(buf)) strcpy(buf, q);",  # length-checked
        "    size_t n = strlen(q);\n    if (n >= sizeof buf) return 0;\n    strcpy(buf, q);",  # via a length alias
        '    snprintf(buf, sizeof buf, "%s", q);',  # sized
        "    char *p = malloc(strlen(q) + 1);\n    strcpy(p, q);",  # sized allocation
        "    strncpy(buf, q, sizeof buf - 1);",  # bounded copy, constant length
    ],
)
def test_strcpy_negatives(body: str) -> None:
    assert _kinds(_fn(CIVET_SOURCE + "    char buf[16];\n" + body)) == []


def test_sprintf_with_request_string_is_flagged() -> None:
    code = _fn(CIVET_SOURCE + '    char path[256];\n    sprintf(path, "./%s", ri->local_uri);')
    assert _hits(code) == [(6, "unbounded_copy", "high", "request")]


@pytest.mark.parametrize(
    "call",
    [
        'sprintf(path, "%.200s", q);',  # precision bounds the %s
        'sprintf(path, "%d", atoi(q));',  # numeric conversion
        'sprintf(path, "%s", "x");',
    ],
)
def test_sprintf_negatives(call: str) -> None:
    assert _kinds(_fn(CIVET_SOURCE + "    char path[256];\n    " + call)) == []


def test_gets_and_unbounded_scanf() -> None:
    code = (
        "void f(void) {\n    char line[100];\n    gets(line);\n"
        '    scanf("%s", line);\n    scanf("%99s", line);\n    scanf("%ms", &p);\n    scanf("%d", &n);\n}\n'
    )
    assert _hits(code) == [(3, "unbounded_copy", "medium", "stdin"), (4, "unbounded_copy", "medium", "stdin")]


def test_bounded_read_only_overflows_a_smaller_array() -> None:
    code = (
        "void f(void) {\n    char line[1024], small[16], big[2048];\n"
        "    fgets(line, sizeof line, stdin);\n    strcpy(big, line);\n    strcpy(small, line);\n}\n"
    )
    assert _hits(code) == [(5, "unbounded_copy", "medium", "stdin")]


def test_width_limited_sscanf_fields_are_bounded() -> None:
    code = _fn(
        "    char u[256], d[256];\n    char *out = mg_malloc(2048);\n"
        '    sscanf(q, "%255[^:]:%255s", u, d);\n    sprintf(out, "%s:%s", u, d);',
        "const char *q",
    )
    assert _kinds(code) == []


# ---------- format_string ----------


def test_non_literal_format_untraced_is_low() -> None:
    code = "void log_it(const char *msg) {\n    printf(msg);\n}\n"
    assert _hits(code) == [(2, "format_string", "low", None)]


def test_format_from_request_is_high() -> None:
    code = _fn(CIVET_SOURCE + "    mg_printf(conn, q);")
    assert _hits(code) == [(5, "format_string", "high", "request")]


@pytest.mark.parametrize(
    "code",
    [
        'void f(char *x) { printf("%s", x); }',
        'void f(int n) { printf(n ? "yes\\n" : "no\\n"); }',
        '#define FMT "%d\\n"\nvoid f(int n) { printf(FMT, n); fprintf(stderr, MSG); }',
        'static const char *usage = "usage: %s\\n";\nvoid f(char *a) { printf(usage, a); }',
        'void f(int n) { char fmt[]{"%04x"}; fmt[2] = (char)(48 + n); printf(fmt, n); }',
        'void f(void) { printf(_("translated %d\\n"), 3); }',
        "void f(int n) { snprintf(buf, sizeof buf, format_for(n), n); }",  # call result, untraced
        "void logf(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); }",
        "void vlog(const char *fmt, va_list ap) { vsnprintf(buf, sizeof buf, fmt, ap); }",
        "void dbg(int level, const char *fmt, ...) { if (level > 2) fprintf(stderr, fmt, level); }",
        'void f(void) { const char *fmt = "%d"; printf(fmt, 1); }',
    ],
)
def test_format_negatives(code: str) -> None:
    assert _kinds(code) == []


def test_literal_buffer_written_later_is_not_constant() -> None:
    code = 'void exec_tag(char *tag) {\n    char cmd[1024] = "";\n    sscanf(tag, " \\"%1023[^\\"]\\"", cmd);\n    popen(cmd, "r");\n}\n'
    assert _hits(code) == [(4, "native_command_exec", "low", None)]


# ---------- native_command_exec ----------


def test_system_on_request_built_command_is_high() -> None:
    code = _fn(CIVET_SOURCE + '    char cmd[256];\n    snprintf(cmd, sizeof cmd, "ping %s", q);\n    system(cmd);')
    assert _hits(code) == [(7, "native_command_exec", "high", "request")]


@pytest.mark.parametrize(
    "call",
    [
        'system("ls -l");',
        "system(NULL);",
        'popen(SCRIPT_PATH, "r");',
        'execl("/bin/ls", "ls", "-l", (char *)NULL);',
        'execl("/bin/sh", "sh", "-c", "uptime", (char *)NULL);',
        "execv(path, args);",  # untraced exec without a shell: not reported
    ],
)
def test_command_negatives(call: str) -> None:
    assert _kinds(_fn("    " + call, "const char *path, char **args")) == []


def test_exec_with_input_and_untraced_sh_c() -> None:
    code = (
        "int main(int argc, char **argv) {\n"
        '    execlp("convert", "convert", argv[1], "out.png", (char *)NULL);\n}\n'
        'void run(const char *cmd) {\n    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);\n}\n'
    )
    assert _hits(code) == [(2, "native_command_exec", "medium", "argv"), (5, "native_command_exec", "low", None)]


def test_getenv_command_is_medium_env() -> None:
    code = 'void f(void) {\n    char *editor = getenv("EDITOR");\n    system(editor);\n}\n'
    assert _hits(code) == [(3, "native_command_exec", "medium", "env")]


# ---------- tainted_copy_length ----------


NET = "void on_packet(int sock) {\n    unsigned char pkt[512];\n    char out[64];\n    recv(sock, pkt, sizeof pkt, 0);\n    unsigned short len = ntohs(*(unsigned short *)pkt);\n"


def test_memcpy_with_packet_length_is_high() -> None:
    assert _hits(NET + "    memcpy(out, pkt + 2, len);\n}\n") == [(6, "tainted_copy_length", "high", "network")]


@pytest.mark.parametrize(
    "tail",
    [
        "    if (len > sizeof out) return;\n    memcpy(out, pkt + 2, len);",
        "    size_t m = MIN(len, sizeof out);\n    memcpy(out, pkt + 2, m);",
        "    memcpy(out, pkt + 2, sizeof out);",
        "    char *copy = malloc(len + 1);\n    memcpy(copy, pkt + 2, len);",
        "    assert(len <= sizeof out);\n    memcpy(out, pkt + 2, len);",
        "    int n = recv(sock, pkt, sizeof pkt, 0);\n    memcpy(out, pkt, n);",  # read count, not data
    ],
)
def test_memcpy_negatives(tail: str) -> None:
    assert _kinds(NET + tail + "\n}\n") == []


def test_mongoose_body_length() -> None:
    code = (
        "static void fn(struct mg_connection *c, int ev, void *ev_data) {\n"
        "    if (ev == MG_EV_HTTP_MSG) {\n"
        "        struct mg_http_message *hm = (struct mg_http_message *) ev_data;\n"
        "        char buf[100];\n"
        "        memcpy(buf, hm->body.buf, hm->body.len);\n"
        "    }\n}\n"
    )
    assert _hits(code) == [(5, "tainted_copy_length", "high", "request")]


def test_taint_does_not_flow_through_unknown_calls() -> None:
    code = (
        "int main(int argc, char **argv) {\n    struct hostent *server = gethostbyname(argv[1]);\n"
        "    memcpy(dst, src, server->h_length);\n}\n"
    )
    assert _kinds(code) == []


def test_clamp_inside_the_call_is_a_bound() -> None:
    assert _kinds(NET + "    memcpy(out, pkt + 2, len > sizeof out ? sizeof out : len);\n}\n") == []


@pytest.mark.parametrize(
    "check",
    [
        "    if (len < 0) return;",  # a sign check is not an upper bound
        "    if (len == 0) return;",
        "    if (strlen((char *)pkt) > 0) puts(\"x\");",
        "    assert(len != 0);",
    ],
)
def test_non_bounding_checks_do_not_silence(check: str) -> None:
    assert _kinds(NET + check + "\n    memcpy(out, pkt + 2, len);\n}\n") == ["tainted_copy_length"]


def test_upper_bound_assert_call_is_a_bound() -> None:
    assert _kinds(NET + "    ck_assert_int_lt(len, sizeof(out));\n    memcpy(out, pkt + 2, len);\n}\n") == []


# ---------- alloc_size_overflow ----------


def test_malloc_of_input_product() -> None:
    code = NET + "    char *items = malloc(len * 24);\n    int *v = realloc(v0, sizeof(int) * len);\n}\n"
    assert _hits(code) == [(6, "alloc_size_overflow", "high", "network"), (7, "alloc_size_overflow", "high", "network")]


@pytest.mark.parametrize(
    "tail",
    [
        "    char *p = calloc(len, 24);",  # calloc checks the product
        "    char *p = malloc(len + 24);",  # no product
        "    char *p = malloc(count * 24);",  # untraced factor
        "    if (len > 1000) return;\n    char *p = malloc(len * 24);",
        "    if (len > SIZE_MAX / 24) return;\n    char *p = malloc(len * 24);",
        "    char *p = malloc(*sizes + 4);",  # a dereference, not a product
    ],
)
def test_alloc_negatives(tail: str) -> None:
    assert _kinds(NET + tail + "\n}\n") == []


# ---------- sources ----------


def test_reassignment_to_a_literal_clears_taint() -> None:
    code = (
        "int main(int argc, char **argv) {\n    const char *u = argv[1];\n"
        '    if (bad(u)) u = "default";\n    char b[8];\n    strcpy(b, u);\n    system(u);\n}\n'
    )
    # The input no longer reaches either call; `system(u)` is still a
    # non-constant command (low, untraced).
    assert _hits(code) == [(6, "native_command_exec", "low", None)]


def test_copy_into_an_array_at_least_as_large_cannot_overflow() -> None:
    code = (
        "void f(int sock) {\n    char pkt[64], out[64], small[8];\n    recv(sock, pkt, sizeof pkt, 0);\n"
        "    strcpy(out, pkt);\n    strcpy(small, pkt);\n}\n"
    )
    assert _hits(code) == [(5, "unbounded_copy", "high", "network")]


def test_unbounded_input_held_in_a_smaller_array_cannot_overflow_a_larger_one() -> None:
    code = "void f(void) {\n    char line[32], out[64], tiny[8];\n    gets(line);\n    strcpy(out, line);\n    strcpy(tiny, line);\n}\n"
    assert _hits(code) == [(3, "unbounded_copy", "medium", "stdin"), (5, "unbounded_copy", "medium", "stdin")]


def test_struct_request_is_not_a_web_request() -> None:
    code = "void handle(struct Request *r) {\n    char b[8];\n    strcpy(b, r->path);\n    system(r->cmd);\n}\n"
    assert _hits(code) == [(4, "native_command_exec", "low", None)]





def test_libmicrohttpd_handler_params_are_request_input() -> None:
    code = (
        "static enum MHD_Result answer(void *cls, struct MHD_Connection *connection, const char *url,\n"
        "        const char *method, const char *version, const char *upload_data,\n"
        "        size_t *upload_data_size, void **con_cls) {\n"
        "    char path[128];\n    strcpy(path, url);\n"
        '    const char *v = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "q");\n'
        "    printf(v);\n    return MHD_YES;\n}\n"
    )
    assert _hits(code) == [(5, "unbounded_copy", "high", "request"), (7, "format_string", "high", "request")]


def test_civetweb_out_parameter_sources() -> None:
    code = _fn(
        "    char v[32], body[512];\n"
        '    mg_get_var(q, strlen(q), "n", v, sizeof v);\n'
        "    mg_read(conn, body, sizeof body);\n"
        "    syslog(LOG_INFO, v);\n"
        "    system(body);",
        "struct mg_connection *conn, const char *q",
    )
    assert _hits(code) == [(5, "format_string", "high", "request"), (6, "native_command_exec", "high", "request")]


def test_argv_only_counts_in_a_function_that_takes_it() -> None:
    code = 'void run(const char *p) {\n    char *argv[] = {"ls", (char *)p, NULL};\n    char b[8];\n    strcpy(b, argv[1]);\n}\n'
    assert _kinds(code) == []


def test_stdin_and_env_are_local() -> None:
    code = (
        "void f(void) {\n    char buf[256];\n    fgets(buf, sizeof buf, stdin);\n    printf(buf);\n"
        '    char *home = getenv("HOME");\n    char p[16];\n    strcpy(p, home);\n}\n'
    )
    assert _hits(code) == [(4, "format_string", "medium", "stdin"), (7, "unbounded_copy", "medium", "env")]


def test_taint_is_scoped_to_the_function() -> None:
    code = (
        "int main(int argc, char **argv) {\n    char *x = argv[1];\n    return 0;\n}\n"
        "void other(char *x) {\n    char b[8];\n    strcpy(b, x);\n}\n"
    )
    assert _kinds(code) == []


# ---------- masking, definitions, paths ----------


def test_comments_strings_and_disabled_code_are_ignored() -> None:
    code = (
        "/* strcpy(buf, argv[1]); */\n"
        "int main(int argc, char **argv) {\n"
        '    puts("system(argv[1]);");\n'
        "    // gets(buf);\n"
        "#if 0\n    gets(buf);\n#endif\n"
        "#define COPY(d, s) strcpy(d, s)\n"
        "    return 0;\n}\n"
    )
    assert _kinds(code) == []


def test_declarations_are_not_calls() -> None:
    code = "int printf(const char *fmt, ...);\nstatic int system(const char *cmd) {\n    return 0;\n}\n"
    assert _kinds(code) == []


def test_mask_keeps_offsets_and_quotes() -> None:
    src = 'a = "x\\"y"; /* c */ b = \'"\'; // z\n#define Q "q"\nR"(raw)";'
    masked = mask_source(src)
    assert len(masked) == len(src)
    assert masked.count("\n") == src.count("\n")
    assert '"    "' in masked and "'" in masked and "c" not in masked.split(";")[1]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_server.c", True),
        ("unittest/public_server.c", True),
        ("fuzztest/fuzzmain.c", True),
        ("src/parser_test.c", True),
        ("src/server.c", False),
        ("examples/hello/hello.c", False),
    ],
)
def test_test_paths(path: str, expected: bool) -> None:
    assert is_test_path(path) is expected


def test_test_code_skipped_unless_opted_in(monkeypatch: pytest.MonkeyPatch) -> None:
    code = "void f(void) {\n    char b[8];\n    gets(b);\n}\n"
    assert _kinds(code, "test/unit.c") == []
    monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
    assert _kinds(code, "test/unit.c") == ["unbounded_copy"]


def test_examples_are_capped_at_low() -> None:
    code = _fn(CIVET_SOURCE + "    char buf[16];\n    strcpy(buf, q);")
    (weakness,) = find_native_weaknesses(code, "examples/rest/rest.c")
    assert (weakness.severity, weakness.confidence, weakness.source_kind) == ("low", "low", "request")


def test_record_fields() -> None:
    code = _fn(CIVET_SOURCE + "    char buf[16];\n    strcpy(buf, q);")
    (w,) = find_native_weaknesses(code, "src/server.c")
    assert w.file == "src/server.c" and w.evidence_text == "strcpy(buf, q);"
    assert w.confidence == "high" and w.source_line == 3  # `ri = mg_get_request_info(conn)`


# ---------- real-repo validation fixtures ----------
#
# Patterns found while validating on civetweb, mongoose, cpp-httplib, drogon,
# Crow, restbed and oat++ example-crud (written for these tests, not copied).


def test_validation_fixture_expectations() -> None:
    found = {}
    for path in sorted(FIXTURES.glob("*.c")):
        for w in find_native_weaknesses(path.read_text(encoding="utf-8"), f"src/{path.name}"):
            found.setdefault(path.name, []).append((w.line, w.kind, w.severity))
    assert found == {
        # civetweb unittest/public_server.c: request URI sprintf'd into a 4 KiB path.
        "civetweb_store_body.c": [(9, "unbounded_copy", "high")],
        # civetweb src/civetweb.c: SSI #exec runs a command read from the page.
        "civetweb_ssi_exec.c": [(8, "native_command_exec", "low")],
    }


# ---------- robustness ----------


def test_fuzz_never_raises() -> None:
    rng = random.Random(189)
    alphabet = 'abcxyz_09 \n\t(){}[];,."\'\\/*#<>=-+&|!?:%sprintf strcpy memcpy malloc system argv recv '
    seeds = [p.read_text(encoding="utf-8") for p in FIXTURES.glob("*.c")] + [NET + "memcpy(out, pkt, len);\n}\n"]
    for _ in range(300):
        if rng.random() < 0.5:
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 600)))
        else:
            seed = rng.choice(seeds)
            cut = rng.randint(0, len(seed))
            text = seed[:cut] if rng.random() < 0.5 else seed[cut:]
        find_native_weaknesses(text, "src/x.c")


def test_pathological_input_is_fast() -> None:
    cases = [
        "void f(void) {" + "(" * 20000 + "}",
        "void f(void) {" + "strcpy(" * 5000 + "}",
        '"' + "\\" * 20000,
        "void f(void) { x = " + "a * " * 20000 + "b; }",
        "/*" + "*" * 50000,
        "R\"abc(" + ")" * 30000,
        "void f(int a) {" * 3000 + "}" * 3000,
    ]
    start = time.perf_counter()
    for text in cases:
        find_native_weaknesses(text, "src/x.c")
    assert time.perf_counter() - start < 10


def _timed(text: str, path: str = "src/x.cpp") -> float:
    start = time.perf_counter()
    find_native_weaknesses(text, path)
    return time.perf_counter() - start


def test_large_function_with_many_sinks_is_linear() -> None:
    def fn(n: int) -> str:
        lines = [f"    unsigned short n{i} = ntohs(pkt[{i}]); if (n{i} > sizeof out) return; memcpy(out, pkt, n{i});" for i in range(n)]
        return "void f(int sock) {\n    char out[64]; unsigned short pkt[512]; recv(sock, pkt, sizeof pkt, 0);\n" + "\n".join(lines) + "\n}\n"
    small, large = _timed(fn(500)), _timed(fn(2000))
    assert large < 3
    assert large < small * 8 + 0.5  # ~4x the input, not ~16x


def test_unterminated_constructs_are_linear() -> None:
    assert _timed("#if 0\nint x;\n" * 5000) < 2
    assert _timed('R"abc(' * 20000) < 2
    assert _timed("/*" * 50000) < 2
    assert _timed('"' + "\\" * 50000) < 2


def test_nested_lambdas_are_not_rescanned() -> None:
    text = "void f() {" + "auto l = [&](const httplib::Request &req) { memcpy(a, b, req.body.size());" * 500 + "}" * 1000
    assert _timed(text) < 3



def test_hostile_identifiers_are_linear() -> None:
    # Round-2 review: `"ls" aaaa…!` made the literal-only check split the
    # identifier 2^n ways; long identifiers before `.resize(`/`=` were
    # quadratic.
    ident = "a" * 5000
    assert _timed(f'void f() {{ system("ls" {"a" * 60}!); printf("x" {"b" * 60}!); }}') < 1
    assert _timed(f"void f() {{ {ident}!.resize(1); {ident}! = malloc(n); char {ident}!; }}") < 1
    assert _timed("void f() { char b[4]; if (n > " + " " * 20000 + "1) return; memcpy(b, s, n); }") < 1


_HOSTILE = (
    "a{0}!", '"ls" a{0}!', "x = a{0}!", "char a{0}!", "#define a{0}!", "(a.){0}", "(a->){0}", "(a::){0}", " {0}!",
    "({0}", "[{0}", "<{0}", "%{0}", '"a{0}', "(a ){0}!", "(a*){0}", "(a=){0}", "(a,){0}", "(a[1]){0}",
    '("x" ){0}!', "1{0}!", '("x" a ){0}!', "(a\t){0}", "(<a){0}", "(a<){0}",
)


def _hostile(n: int) -> list[str]:
    out = []
    for shape in _HOSTILE:
        if shape.startswith("(") and "){0}" in shape:
            unit = shape[1 : shape.index("){0}")]
            out.append(unit * n + shape[shape.index("){0}") + 4 :])
        else:
            head, tail = shape.split("{0}")
            out.append(head[:-1] + head[-1] * n + tail)
    return out


def test_every_module_regex_is_linear_on_hostile_text() -> None:
    from attackmap_analyzer_c import native_sinks

    patterns = {name: value for name, value in vars(native_sinks).items() if isinstance(value, re.Pattern)}
    # Only ever matched against operands of at most _TRIVIAL_BOUND_MAX chars.
    patterns.pop("_TRIVIAL_BOUND_RE")
    assert len(patterns) > 40
    slow = []
    for name, pattern in patterns.items():
        for text in (*_hostile(24), *_hostile(4000)):
            start = time.perf_counter()
            list(pattern.finditer(text))
            pattern.match(text)
            if time.perf_counter() - start > 0.05:
                slow.append((name, text[:20]))
    assert slow == []
    assert native_sinks._is_trivial_bound(" " * 20000 + "1") is False


# ---------- analyzer integration ----------


def test_analyze_emits_code_weaknesses(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text(
        "int main(int argc, char **argv) {\n    char b[8];\n    strcpy(b, argv[1]);\n    return 0;\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.c").write_text("void t(void) { char b[4]; gets(b); }\n", encoding="utf-8")
    result = CAnalyzer().analyze(tmp_path)
    assert [(w.file, w.kind, w.severity) for w in result.code_weaknesses] == [("src/main.c", "unbounded_copy", "medium")]


def test_headers_owned_by_cpp_are_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "a.c").write_text("int x;\n", encoding="utf-8")
    (tmp_path / "b.cpp").write_text("int y;\n", encoding="utf-8")
    (tmp_path / "h.h").write_text("static void f(void) { char b[4]; gets(b); }\n", encoding="utf-8")
    assert CAnalyzer().analyze(tmp_path).code_weaknesses == []
