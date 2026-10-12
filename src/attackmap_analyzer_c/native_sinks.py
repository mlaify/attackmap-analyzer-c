"""Native (C/C++) memory-safety and command-exec sinks (AttackMap#189).

Emits ``CodeWeakness`` records for five kinds, decided inside one function:

- ``unbounded_copy``: ``gets``, ``scanf``-family ``%s``/``%[`` without a field
  width, and ``strcpy``/``strcat``/``sprintf`` whose source (or ``%s``
  argument) is traced to an input in the same function.
- ``format_string``: a printf-family call whose format is not a constant.
- ``native_command_exec``: ``system``/``popen`` with a non-constant command,
  ``exec*`` with an input-derived argument or a non-constant ``sh -c`` line.
- ``tainted_copy_length``: ``memcpy``/``memmove``/``strncpy``/``strncat``
  whose length is traced to an input and not bounds-checked first.
- ``alloc_size_overflow``: ``malloc``/``realloc``/``alloca``/``new T[]`` of a
  product with an input-derived factor and no overflow check.

Sources (per function): request accessors of the supported web frameworks
(civetweb, mongoose, libmicrohttpd, cpp-httplib, Crow, Drogon, Pistache,
Boost.Beast, oat++, restbed) and parameters of their request types; socket
reads (``recv``, ``SSL_read``, ...); stdin (``fgets(..., stdin)``,
``std::cin``); ``argv``/``optarg`` in a function that takes ``argv``;
``getenv``; and file reads. Taint follows assignments, out-parameters and
copy functions in textual order; it is never cleared. A comparison
(``<``/``>``) on the value, a ``MIN``/``std::min`` clamp, or an allocation
sized from the same value counts as a bound.

Severity and confidence come from the traced source: request/network input
-> high/high, local input (stdin, argv, env, file) -> medium/medium, nothing
traced -> low/low (reported only for non-constant formats and commands).
Code under example/demo/sample directories is capped at low/low. Test and
fuzz code is skipped (``ATTACKMAP_INCLUDE_TESTS`` opts back in).

This module is mirrored verbatim in attackmap-analyzer-c and
attackmap-analyzer-cpp. Change both together.

Every scanner here is linear or bounded: comments/strings are masked with one
regex pass, brace and paren matching are capped, and all patterns are
module-level with no nested quantifiers.
"""

from __future__ import annotations

import bisect
import os
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from attackmap.sdk import line_of

try:  # attackmap >= the release that exports CodeWeakness (AttackMap#189)
    from attackmap.sdk import CodeWeakness
except ImportError:  # older core: the plugin still loads, emits no weaknesses
    CodeWeakness = None  # type: ignore[assignment,misc]

_SNIPPET_MAX_CHARS = 160
# Bounds for the hand-written scanners. A call or parameter list longer than
# this is treated as unparseable rather than scanned further.
_MAX_ARGS_SPAN = 4000
_MAX_PARAMS_SPAN = 2000
_MAX_RHS_SPAN = 1500
_COMPARE_WINDOW = 120
_MAX_OWNER_WALK = 2000

# ---------- Masking ----------

# One pass over the source: comments, preprocessor directives (with
# continuation lines), ``#if 0`` blocks and string/char literals. Comments and
# directives become spaces; literals keep their quotes and lose their
# contents. Newlines are preserved so offsets and line numbers don't move.
_MASK_RE = re.compile(
    r"^[ \t]*\#[ \t]*if[ \t]+0\b[\s\S]*?^[ \t]*\#[ \t]*(?:endif|else|elif)\b[^\n]*"
    r"|^[ \t]*\#(?:[^\n\\]|\\[\s\S])*"
    r"|//[^\n]*"
    r"|/\*[\s\S]*?(?:\*/|\Z)"
    r"|(?<![\w])(?:u8|[uUL])?R\"(?P<delim>[^()\\\s\"]{0,16})\((?:[^)]|\)(?!(?P=delim)\"))*\)(?P=delim)\""
    r"|\"(?:[^\"\\\n]|\\[\s\S])*\"?"
    r"|'(?:[^'\\\n]|\\[\s\S]){0,8}'",
    re.MULTILINE,
)


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _mask_match(match: re.Match[str]) -> str:
    text = match.group(0)
    if text.startswith(("#", "/", " ", "\t")):
        return _blank(text)
    quote = 0 if text.startswith("'") else text.find('"')
    if quote < 0:
        return _blank(text)
    head, body = text[: quote + 1], text[quote + 1 :]
    if len(body) >= 1 and body[-1] in "\"'":
        return head + _blank(body[:-1]) + body[-1]
    return head + _blank(body)


def mask_source(text: str) -> str:
    """Same-length copy of ``text`` with comments, directives and literal
    contents blanked (quotes kept, newlines kept)."""
    return _MASK_RE.sub(_mask_match, text)


# ---------- Calls, functions, arguments ----------

_CONTROL_WORDS = frozenset(
    {
        "if", "for", "while", "switch", "catch", "return", "sizeof", "alignof", "decltype",
        "else", "do", "case", "typeof", "__typeof__", "defined", "_Generic", "static_assert",
    }
)
_TRAILING_QUALIFIERS = frozenset({"const", "noexcept", "override", "final", "mutable", "volatile", "throw"})
_BRACE_RE = re.compile(r"[{}]")
_WORD_BEFORE_RE = re.compile(r"([A-Za-z_]\w*)\s*$")
_TRAILING_RETURN_RE = re.compile(r"->\s*[\w:<>,\s*&]{1,80}$")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_SIZEOF_RE = re.compile(r"\bsizeof\s*(?:\([^()]{0,200}\)|[A-Za-z_]\w*)")


@dataclass
class _Scope:
    start: int  # offset of the opening brace
    end: int  # offset of the closing brace
    name: str
    params: str  # masked parameter text
    params_orig: str
    param_names: set[str] = field(default_factory=set)


def _skip_ws_back(text: str, i: int) -> int:
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    return i


def _match_open_paren_back(text: str, close: int, limit: int) -> int:
    """Index of the ``(`` matching the ``)`` at ``close``, or -1."""
    depth = 0
    lo = max(-1, close - limit)
    i = close
    while i > lo:
        c = text[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                return i
        elif c in "{};":
            return -1
        i -= 1
    return -1


def _function_header(masked: str, brace: int) -> tuple[str, int, int] | None:
    """If the ``{`` at ``brace`` opens a function or lambda body, return
    ``(name, params_open, params_close)``."""
    i = _skip_ws_back(masked, brace - 1)
    # Trailing qualifiers / trailing return type.
    for _ in range(4):
        if i < 0:
            return None
        if masked[i] == ")":
            break
        tail = masked[max(0, i - 100) : i + 1]
        arrow = _TRAILING_RETURN_RE.search(tail)
        if arrow is not None:
            i = _skip_ws_back(masked, i - (len(tail) - arrow.start()))
            continue
        word = _WORD_BEFORE_RE.search(tail)
        if word is None or word.group(1) not in _TRAILING_QUALIFIERS:
            return None
        i = _skip_ws_back(masked, i - len(word.group(0)))
    if i < 0 or masked[i] != ")":
        return None
    open_paren = _match_open_paren_back(masked, i, _MAX_PARAMS_SPAN)
    if open_paren < 0:
        return None
    j = _skip_ws_back(masked, open_paren - 1)
    if j < 0:
        return None
    if masked[j] == "]":
        return "<lambda>", open_paren, i
    word = _WORD_BEFORE_RE.search(masked[max(0, j - 80) : j + 1])
    if word is None or word.group(1) in _CONTROL_WORDS:
        return None
    return word.group(1), open_paren, i


def _scopes(masked: str, orig: str) -> list[_Scope]:
    scopes: list[_Scope] = []
    stack: list[int] = []
    for match in _BRACE_RE.finditer(masked):
        if match.group(0) == "{":
            stack.append(match.start())
            continue
        if not stack:
            continue
        start = stack.pop()
        header = _function_header(masked, start)
        if header is None:
            continue
        name, p_open, p_close = header
        params = masked[p_open + 1 : p_close]
        scopes.append(
            _Scope(
                start=start,
                end=match.start(),
                name=name,
                params=params,
                params_orig=orig[p_open + 1 : p_close],
                param_names=_param_names(params),
            )
        )
    scopes.sort(key=lambda s: s.start)
    return scopes


def _param_names(params: str) -> set[str]:
    names: set[str] = set()
    for piece in _split_top(params, 0, len(params)):
        text = params[piece[0] : piece[1]].split("=", 1)[0]
        text = re.sub(r"\[[^\]]*\]", "", text)
        idents = _IDENT_RE.findall(text)
        if idents:
            names.add(idents[-1])
    return names


def _split_top(text: str, lo: int, hi: int) -> list[tuple[int, int]]:
    """Top-level comma-separated spans of ``text[lo:hi]``."""
    spans: list[tuple[int, int]] = []
    depth = 0
    start = lo
    for i in range(lo, hi):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
    if hi > start or spans:
        spans.append((start, hi))
    return spans


def _call_args(masked: str, open_paren: int) -> tuple[list[tuple[int, int]], int] | None:
    """Argument spans of the call whose ``(`` is at ``open_paren`` and the
    index of its ``)``; None when unbalanced within the bound."""
    depth = 0
    hi = min(len(masked), open_paren + _MAX_ARGS_SPAN)
    for i in range(open_paren, hi):
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if c != ")":
                    return None
                if i == open_paren + 1 or not masked[open_paren + 1 : i].strip():
                    return [], i
                return _split_top(masked, open_paren + 1, i), i
        elif c == ";" and depth == 1:
            return None
    return None


# ---------- Catalogs ----------

# Sinks, by family. Values are argument indexes.
_UNBOUNDED_COPY = {"strcpy": (0, 1), "strcat": (0, 1), "wcscpy": (0, 1), "wcscat": (0, 1), "stpcpy": (0, 1),
                   "lstrcpy": (0, 1), "lstrcat": (0, 1), "lstrcpyA": (0, 1), "lstrcatA": (0, 1)}
_SPRINTF = {"sprintf": 1, "vsprintf": 1}
# Format argument index for printf-family calls.
_FORMAT_FUNCS = {
    "printf": 0, "vprintf": 0, "wprintf": 0, "vwprintf": 0,
    "fprintf": 1, "vfprintf": 1, "fwprintf": 1,
    "sprintf": 1, "vsprintf": 1, "asprintf": 1, "vasprintf": 1,
    "snprintf": 2, "vsnprintf": 2, "swprintf": 2,
    "syslog": 1, "vsyslog": 1,
    # civetweb / mongoose response writers take a printf format.
    "mg_printf": 1, "mg_http_reply": 3,
}
_VA_FORMAT_FUNCS = frozenset(n for n in _FORMAT_FUNCS if n.startswith("v"))
_SCANF = {"scanf": 0, "fscanf": 1, "sscanf": 1, "wscanf": 0, "fwscanf": 1, "swscanf": 1}
_SHELL_COMMAND = {"system": 0, "popen": 0, "_popen": 0, "_wsystem": 0, "_wpopen": 0}
_EXEC = frozenset({"execl", "execlp", "execle", "execv", "execvp", "execvpe", "execve", "posix_spawn", "posix_spawnp"})
# (dst, src, length) for bounded copies whose length is the risk.
_LENGTH_COPY = {"memcpy": (0, 1, 2), "memmove": (0, 1, 2), "strncpy": (0, 1, 2), "strncat": (0, 1, 2),
                "wmemcpy": (0, 1, 2), "wmemmove": (0, 1, 2), "bcopy": (1, 0, 2), "CopyMemory": (0, 1, 2),
                "RtlCopyMemory": (0, 1, 2)}
_ALLOC = {"malloc": 0, "alloca": 0, "_alloca": 0, "realloc": 1, "xmalloc": 0, "xrealloc": 1}

# Out-parameter sources: function -> (dst arg index, source kind or a
# resolver keyword). "stream:<n>" means the kind follows the stream at
# argument n (stdin vs file); "fd:<n>" the descriptor at argument n.
_OUT_PARAM_SOURCES: dict[str, tuple[int, str]] = {
    "recv": (1, "network"), "recvfrom": (1, "network"), "SSL_read": (1, "network"),
    "SSL_read_ex": (1, "network"), "BIO_read": (1, "network"), "mbedtls_ssl_read": (1, "network"),
    "gnutls_record_recv": (1, "network"), "WSARecv": (1, "network"),
    "read": (1, "fd:0"), "pread": (1, "fd:0"),
    "fgets": (0, "stream:2"), "fgetws": (0, "stream:2"), "fread": (0, "stream:3"),
    "getline": (0, "stream:2"), "getdelim": (0, "stream:3"), "gets": (0, "stdin"),
    # civetweb
    "mg_read": (1, "request"), "mg_get_var": (3, "request"), "mg_get_var2": (3, "request"),
    "mg_get_cookie": (2, "request"), "mg_get_form_value": (2, "request"),
    # mongoose
    "mg_http_get_var": (2, "request"),
}
# Calls that copy taint from source argument(s) to a destination argument.
# Value: (dst index, first source index, all-following?)
_PROPAGATORS: dict[str, tuple[int, int, bool]] = {
    "strcpy": (0, 1, False), "strncpy": (0, 1, False), "strcat": (0, 1, False), "strncat": (0, 1, False),
    "stpcpy": (0, 1, False), "strlcpy": (0, 1, False), "strlcat": (0, 1, False),
    "wcscpy": (0, 1, False), "wcscat": (0, 1, False),
    "memcpy": (0, 1, False), "memmove": (0, 1, False),
    "sprintf": (0, 1, True), "vsprintf": (0, 1, True), "snprintf": (0, 2, True), "vsnprintf": (0, 2, True),
    "mg_url_decode": (2, 0, False), "mg_snprintf": (2, 3, True),
}

# Expressions that are a source wherever they appear (masked text).
_DIRECT_SOURCES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env", re.compile(r"(?<![\w.>])(?:std::)?(?:secure_getenv|getenv|_wgetenv)\s*\(")),
    # civetweb / mongoose / libmicrohttpd request accessors
    ("request", re.compile(r"\bmg_get_(?:header|request_info|request_link)\s*\(")),
    ("request", re.compile(r"\bmg_http_(?:get_header|get_header_var|var)\s*\(")),
    ("request", re.compile(r"\bMHD_lookup_connection_value(?:_n)?\s*\(")),
    # cpp-httplib / Crow / Drogon / Pistache / restbed accessors
    ("request", re.compile(r"\.\s*get_(?:param|header|file)_value\s*\(")),
    ("request", re.compile(r"\.\s*url_params\b")),
    ("request", re.compile(r"->\s*get(?:Parameter|Parameters|Header|Headers|Body|JsonObject|Cookie|Cookies|Path|Query)\s*\(")),
    ("request", re.compile(r"->\s*get_(?:query|path)_parameters?\s*\(")),
    ("request", re.compile(r"->\s*get_request\s*\(")),
)
# Parameter (or local declaration) types whose variable is request data.
_REQUEST_TYPE_RE = re.compile(
    r"(?:\bstruct\s+(?:mg_http_message|mg_request_info)\b"
    r"|\b(?:httplib::)?Request\b"
    r"|\bcrow::request\b"
    r"|\bHttpRequestPtr\b"
    r"|\b(?:Pistache::)?(?:Rest|Http)::Request\b"
    r"|\b(?:\w+::)*request\s*<"
    r"|\bshared_ptr\s*<\s*(?:const\s+)?(?:restbed::)?(?:Session|Request)\s*>"
    r")"
)
_MG_LOCAL_DECL_RE = re.compile(r"\bstruct\s+(?:mg_http_message|mg_request_info)\s*\*\s*(?:const\s+)?([A-Za-z_]\w*)")
# libmicrohttpd access-handler parameters that carry the request.
_MHD_HANDLER_RE = re.compile(r"\bstruct\s+MHD_Connection\b")
_MHD_REQUEST_PARAMS = frozenset({"url", "method", "version", "upload_data", "upload_data_size"})
# oat++ ENDPOINT parameter macros.
_OATPP_PARAM_RE = re.compile(r"\b(?:QUERY|PATH|HEADER|BODY_STRING|BODY_DTO)\s*\(\s*[^,()]{1,120},\s*([A-Za-z_]\w*)")
_ARGV_PARAM_RE = re.compile(r"\bargv\b")
_ARGV_USE_RE = re.compile(r"\bargv\s*\[|\boptarg\b")
# `std::string t(req.target());` / `std::string s{buf};`: direct-initialized
# strings take their argument's data like an assignment.
_STRING_CTOR_DECL_RE = re.compile(
    r"\b(?:std::)?(?:string|wstring|string_view|basic_string\s*<[^<>;\n]{0,40}>)\s+([A-Za-z_]\w*)\s*[({]"
)
_CIN_RE = re.compile(r"\b(?:std::)?(?:cin|wcin)\s*>>\s*([A-Za-z_]\w*)")
_GETLINE_CIN_RE = re.compile(r"\b(?:std::)?getline\s*\(\s*(?:std::)?(?:cin|wcin)\s*,\s*([A-Za-z_]\w*)")

_STDIN_ARG_RE = re.compile(r"^\s*(?:stdin|0|STDIN_FILENO|std::cin)\s*$")
_SOCKET_NAME_RE = re.compile(r"(?i)sock|conn|client|peer|remote|accept")

# Conversions that make a value numeric (taint kept, string-ness dropped).
_NUMERIC_RHS_RE = re.compile(
    r"^\s*(?:\(\s*(?:unsigned\s+|signed\s+)?[A-Za-z_][\w:]*\s*\)\s*)?"
    r"(?:(?:std::)?(?:atoi|atol|atoll|atof|strtol|strtoul|strtoll|strtoull|strtoumax|strtoimax|strtod|"
    r"stoi|stol|stoul|stoll|stoull|stod)|ntohs|ntohl|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|"
    r"strlen|wcslen|strnlen)\s*\("
)
_INT_DECL_RE = re.compile(
    r"\b(?:(?:unsigned|signed|long|short|int|size_t|ssize_t|off_t|u?int(?:8|16|32|64)_t|DWORD|uint|ulong|"
    r"std::size_t|socklen_t)\s+)+(?:const\s+)?([A-Za-z_]\w*)\s*[=;,\[)]"
)
_CLAMP_RE = re.compile(r"\b(?:MIN|min|std::min|MG_MIN|g_min|qMin)\s*[(<]")
_ALLOC_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*)\s*(?:\[[^\]\n]{0,80}\])?\s*=\s*(?:\([^()\n]{1,60}\)\s*)?"
    r"(?:(?:std::)?(?:malloc|calloc|realloc|alloca|_alloca|xmalloc|xcalloc|xrealloc|mg_malloc|mg_calloc|"
    r"mg_realloc|mg_malloc_ctx|mg_calloc_ctx|g_malloc|g_malloc0|OPENSSL_malloc)\s*\("
    r"|new\s+[\w:]+(?:\s*<[^<>;\n]{0,60}>)?\s*\[)"
)
_RESIZE_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\.|->)\s*(?:resize|reserve|assign)\s*\(")
_ASSIGN_RE = re.compile(
    r"(?<![\w.>])([A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*){0,4})\s*(?:\[[^\]\n]{0,80}\])?\s*"
    r"(?:[+\-*/|&^%]|<<|>>)?=(?!=)"
)
_DECL_STRING_LITERAL_RE = re.compile(
    r"\b(?:const\s+)?(?:char|wchar_t|TCHAR|std::string|string)\s*(?:const\s*)?\*?\s*(?:const\s+)?"
    r"([A-Za-z_]\w*)\s*(?:\[\s*\w*\s*\])?\s*(?:=\s*\{?|\{)\s*(?:u8|[uUL])?\""
)
# `char buf[256], small[16];`: declared byte/char arrays with a literal size.
_ARRAY_DECL_START_RE = re.compile(r"\b(?:char|wchar_t|TCHAR|u?int8_t|BYTE|uchar)\s+(?=[*\s]*[A-Za-z_])")
_ARRAY_DECLARATOR_RE = re.compile(r"(?:^|,)\s*\**\s*([A-Za-z_]\w*)\s*\[\s*(\d{1,9})\s*\]")
# `x.c_str()` / `p->data()`: a call that only exposes a variable's data.
_DATA_CALL_RE = re.compile(r"(?:\.|->)\s*(?:c_str|data|get|str|toStdString|constData|toUtf8)\s*\(\s*\)\s*$")
# A call to a free function (not a method): `f(`, `ns::f(`, `f<T>(`.
_FREE_CALL_RE = re.compile(r"(?<![\w.>:])((?:[A-Za-z_]\w*::){0,4}[A-Za-z_]\w*)\s*(?:<[^<>;()\n]{0,60}>\s*)?\(")
# Free functions whose result still carries their argument's data: sources,
# string views/copies/searches, numeric conversions and casts.
_PASSTHROUGH_CALLS = frozenset(
    {
        "getenv", "secure_getenv", "_wgetenv", "mg_get_header", "mg_get_request_info", "mg_get_request_link",
        "mg_http_get_header", "mg_http_get_header_var", "mg_http_var", "MHD_lookup_connection_value",
        "MHD_lookup_connection_value_n",
        "strdup", "strndup", "_strdup", "wcsdup", "mg_strdup", "mg_strndup", "mg_strdup_ctx", "mg_strndup_ctx",
        "strchr", "strrchr", "strstr", "strcasestr", "strpbrk", "strtok", "strtok_r", "strsep", "memchr",
        "mg_str", "mg_str_n", "mg_strdup", "basename", "dirname", "realpath",
        "string", "string_view", "basic_string", "move", "forward", "data", "c_str",
        "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull", "strtoumax", "strtoimax",
        "strtod", "stoi", "stol", "stoul", "stoll", "stoull", "stod", "ntohs", "ntohl", "htons", "htonl",
        "be16toh", "be32toh", "be64toh", "le16toh", "le32toh", "le64toh", "strlen", "wcslen", "strnlen",
        "static_cast", "reinterpret_cast", "const_cast", "size_t", "int", "long", "unsigned",
    }
)
_LEADING_CAST_RE = re.compile(r"^\(\s*(?:unsigned\s+|signed\s+|const\s+)?[A-Za-z_][\w:]*\s*\**\s*\)\s*")
_INDEXED_IDENT_RE = re.compile(r"([A-Za-z_]\w*)\s*\[[^\]]{0,60}\]")
# Copies that bound the destination (its content stays input, its length
# doesn't grow past the destination).
_BOUNDED_PROPAGATORS = frozenset(
    {"strncpy", "strlcpy", "strlcat", "strncat", "snprintf", "vsnprintf", "memcpy", "memmove", "mg_url_decode",
     "mg_snprintf"}
)
_DEFINE_STRING_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+(?:u8|[uUL])?\"", re.MULTILINE)
# assert(), ck_assert_int_lt(), ASSERT(), CHECK(), REQUIRE(), EXPECT_LT()...
_CHECK_CALL_RE = re.compile(
    r"\b(?:assert|static_assert|[A-Za-z_]\w*_assert\w*|ck_assert\w*|ASSERT\w*|CHECK\w*|REQUIRE\w*|"
    r"EXPECT_\w+|BOOST_ASSERT\w*|g_return_\w+)\s*\("
)
_COMPARE_OP_RE = re.compile(r"(?<![-<>=!])(?:<=|>=|<|>)(?![<>=])")
_OVERFLOW_GUARD_RE = re.compile(r"\b(?:SIZE_MAX|INT_MAX|UINT_MAX|LONG_MAX|SSIZE_MAX|PTRDIFF_MAX|__builtin_mul_overflow|"
                                r"ckd_mul|std::numeric_limits)\b")
# A binary multiplication or left shift (an operand before it, so `*p` and
# `(char *)` casts don't count).
_MUL_RE = re.compile(r"[\w)\]]\s*(?:\*(?![*/=)])|<<(?!=))")
_GETTEXT_RE = re.compile(r"^\s*(?:_|N_|gettext|dgettext|_T|TEXT|L|tr|QObject::tr)\s*\(")
_ALL_CAPS_RE = re.compile(r"^\s*[A-Z][A-Z0-9_]*\s*$")
_LITERAL_START_RE = re.compile(r"^\s*(?:u8|[uUL])?\"")
_CONVERSION_RE = re.compile(
    r"%(?:%|(?P<flags>[-+ #0']*)(?P<width>\*|\d+)?(?:\.(?P<prec>\*|\d+))?"
    r"(?P<len>hh|h|ll|l|L|q|j|z|Z|t|I64|I32)?(?P<conv>[diouxXeEfFgGaAcspnCS]|\[))"
)
_SCANF_CONVERSION_RE = re.compile(
    r"%(?:%|(?P<suppress>\*)?(?P<width>\d+)?(?P<alloc>m)?(?P<len>hh|h|ll|l|L|q|j|z|t)?"
    r"(?P<conv>[diouxXeEfFgGaAcspn]|\[\^?\]?[^\]]{0,64}\]))"
)
_SH_C_RE = re.compile(r"^\s*\"-c\"\s*$")

_ALL_CALLS = sorted(
    set(_UNBOUNDED_COPY) | set(_FORMAT_FUNCS) | set(_SCANF) | set(_SHELL_COMMAND) | _EXEC
    | set(_LENGTH_COPY) | set(_ALLOC) | set(_OUT_PARAM_SOURCES) | set(_PROPAGATORS) | {"gets", "getline"},
    key=lambda n: (-len(n), n),
)
_CALL_RE = re.compile(r"(?<![\w.>:$])(?:(?:std)?::)?(" + "|".join(_ALL_CALLS) + r")\s*\(")
_NEW_ARRAY_RE = re.compile(r"\bnew\s+(?:[\w:]+(?:\s*<[^<>;\n]{0,60}>)?)\s*\[")

_REMOTE = frozenset({"request", "network"})
_DOWNRANK_SEGMENTS = frozenset({"example", "examples", "sample", "samples", "demo", "demos", "contrib", "doc", "docs",
                                "tutorial", "tutorials"})
_TEST_SEGMENTS = frozenset({"test", "tests", "testing", "unittest", "unittests", "unit_test", "unit_tests", "fuzz",
                            "fuzztest", "fuzzing", "fuzzer", "fuzzers", "bench", "benchmark", "benchmarks", "mock",
                            "mocks", "spec", "specs", "__tests__", "fixtures", "gtest", "googletest"})
_TEST_FILE_RE = re.compile(r"(?i)(?:^test_|_test\.|_tests\.|_unittest\.|_fuzzer\.|^fuzz_|\.test\.)")


def is_test_path(relative: str) -> bool:
    """Test, fuzz and benchmark code: skipped (``ATTACKMAP_INCLUDE_TESTS`` opts in)."""
    if os.environ.get("ATTACKMAP_INCLUDE_TESTS"):
        return False
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if any(p.lower() in _TEST_SEGMENTS for p in parts[:-1]):
        return True
    return bool(parts) and _TEST_FILE_RE.search(parts[-1]) is not None


def _is_downranked(relative: str) -> bool:
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    return any(p.lower() in _DOWNRANK_SEGMENTS for p in parts[:-1])


# ---------- Taint state ----------


@dataclass(frozen=True)
class _Taint:
    kind: str
    line: int
    numeric: bool = False
    # A string whose length is capped (a sized read, a width-limited %s);
    # `max_len` is the cap when known (the destination array's size).
    bounded: bool = False
    max_len: int | None = None


@dataclass
class _State:
    tainted: dict[str, list[tuple[int, _Taint]]] = field(default_factory=dict)
    constant_assigned: dict[str, bool] = field(default_factory=dict)
    allocs: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    resized: dict[str, list[int]] = field(default_factory=dict)
    # `n = strlen(s)` / `n = s.size()`: n measures s, so checking n bounds s.
    length_of: dict[str, set[str]] = field(default_factory=dict)
    # Offsets where a call wrote into a variable (out-parameter, copy).
    written: dict[str, list[int]] = field(default_factory=dict)

    def write(self, name: str, pos: int) -> None:
        self.written.setdefault(name, []).append(pos)

    def written_before(self, name: str, pos: int) -> bool:
        return any(p < pos for p in self.written.get(name, ()))

    def add(self, name: str, pos: int, taint: _Taint) -> None:
        self.tainted.setdefault(name, []).append((pos, taint))

    def get(self, name: str, before: int, *, want_string: bool) -> _Taint | None:
        best: _Taint | None = None
        for pos, taint in self.tainted.get(name, ()):
            if pos >= before:
                continue
            if want_string and taint.numeric:
                continue
            if best is None or _rank(taint) > _rank(best):
                best = taint
        return best


def _rank(taint: _Taint) -> int:
    """Remote input beats local; an unbounded string beats a bounded one."""
    return (4 if taint.kind in _REMOTE else 2) + (0 if taint.bounded else 1)


def _better(a: _Taint | None, b: _Taint | None) -> _Taint | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if _rank(a) >= _rank(b) else b


def _base_ident(expr: str) -> str | None:
    """The variable an lvalue/argument expression names: ``&buf[2]`` ->
    ``buf``, ``(char *) p + 1`` -> ``p``, ``s.data()`` -> ``s``."""
    text = expr.strip()
    text = re.sub(r"^\(\s*[^()]{0,60}\)\s*", "", text)  # leading cast
    text = text.lstrip("&*( ")
    match = _IDENT_RE.match(text)
    if match is None:
        return None
    name = match.group(0)
    if name in ("std", "static_cast", "reinterpret_cast", "const_cast"):
        inner = re.search(r"\(\s*&?\s*([A-Za-z_]\w*)", text)
        return inner.group(1) if inner else None
    return name


@dataclass
class _Ctx:
    masked: str
    orig: str
    scope: _Scope
    state: _State
    request_vars: dict[str, int]  # name -> line where it enters the function
    argv_scope: bool
    int_vars: set[str]
    constants: set[str]
    int_decl_positions: dict[str, int]
    array_sizes: dict[str, int] = field(default_factory=dict)


def _opaque_calls_blanked(text: str) -> str:
    """``text`` with the arguments of calls to unknown free functions blanked:
    ``gethostbyname(argv[1])`` or ``sanitize(name)`` returns something else,
    so its argument's taint doesn't carry over. Method calls, sources and the
    known pass-through functions (``strdup``, ``strchr``, ``atoi``, casts...)
    keep theirs."""
    if "(" not in text:
        return text
    out = list(text)
    for match in _FREE_CALL_RE.finditer(text):
        name = match.group(1).rsplit("::", 1)[-1]
        if name in _PASSTHROUGH_CALLS or name in _CONTROL_WORDS:
            continue
        depth = 0
        for i in range(match.end() - 1, min(len(text), match.end() - 1 + _MAX_ARGS_SPAN)):
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    for j in range(match.end(), i):
                        if out[j] != "\n":
                            out[j] = " "
                    break
    return "".join(out)


def _expr_taint(ctx: _Ctx, lo: int, hi: int, *, want_string: bool) -> _Taint | None:
    """Taint of the expression ``masked[lo:hi]`` as of offset ``lo``."""
    text = _opaque_calls_blanked(ctx.masked[lo:hi])
    if not text.strip():
        return None
    found: _Taint | None = None
    line = line_of(ctx.orig, lo)
    for kind, pattern in _DIRECT_SOURCES:
        if pattern.search(text):
            found = _better(found, _Taint(kind, line))
    if ctx.argv_scope and _ARGV_USE_RE.search(text):
        found = _better(found, _Taint("argv", line))
    stripped = _SIZEOF_RE.sub(" ", text)
    for match in _IDENT_RE.finditer(stripped):
        start = match.start()
        before = stripped[max(0, start - 2) : start]
        if before.endswith(".") or before == "->":
            continue
        name = match.group(0)
        if name in ctx.request_vars:
            found = _better(found, _Taint("request", ctx.request_vars[name]))
            continue
        taint = ctx.state.get(name, lo, want_string=want_string)
        if taint is not None:
            found = _better(found, taint)
    return found


def _is_numeric_expr(ctx: _Ctx, text: str) -> bool:
    if _NUMERIC_RHS_RE.match(text):
        return True
    stripped = text.strip()
    return stripped.endswith((".size()", ".length()", ".len", "->len", "_len", ".size", "->size"))


def _is_constant_expr(ctx: _Ctx, lo: int, hi: int, depth: int = 0) -> bool:
    """A string literal (possibly concatenated with macros), an ALL_CAPS macro,
    a gettext-wrapped literal, a literal ternary, or a variable that is only
    ever assigned constants."""
    text = ctx.masked[lo:hi].strip()
    if not text or depth > 3:
        return False
    if _LITERAL_START_RE.match(text) or _ALL_CAPS_RE.match(text):
        return True
    if text.startswith("(") and text.endswith(")"):
        inner_lo = ctx.masked.index("(", lo) + 1
        inner_hi = ctx.masked.rindex(")", lo, hi)
        if _is_constant_expr(ctx, inner_lo, inner_hi, depth + 1):
            return True
    gettext = _GETTEXT_RE.match(text)
    if gettext is not None and text.endswith(")"):
        inner_lo = lo + ctx.masked[lo:hi].index("(") + 1
        inner_hi = ctx.masked.rindex(")", lo, hi)
        return _is_constant_expr(ctx, inner_lo, inner_hi, depth + 1)
    question = _top_level_index(text, "?")
    if question >= 0:
        colon = _top_level_index(text, ":", question + 1)
        if colon > question:
            offset = lo + (len(ctx.masked[lo:hi]) - len(ctx.masked[lo:hi].lstrip()))
            return _is_constant_expr(ctx, offset + question + 1, offset + colon, depth + 1) and _is_constant_expr(
                ctx, offset + colon + 1, offset + len(text), depth + 1
            )
    ident = _IDENT_RE.fullmatch(text) or _INDEXED_IDENT_RE.fullmatch(text)
    if ident is not None:
        name = ident.group(1) if ident.re is _INDEXED_IDENT_RE else ident.group(0)
        if ctx.state.written_before(name, lo):
            return False  # `char cmd[64] = ""; sscanf(tag, "%63s", cmd);`
        if ctx.state.constant_assigned.get(name) is not None:
            return ctx.state.constant_assigned[name]
        return name in ctx.constants
    return False


def _top_level_index(text: str, char: str, start: int = 0) -> int:
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == char and depth == 0:
            if char == ":" and (text[i - 1 : i] == ":" or text[i + 1 : i + 2] == ":"):
                continue
            return i
    return -1


def _compared_before(ctx: _Ctx, names: set[str], before: int) -> bool:
    """A ``<``/``>`` comparison or an assert-style check involving any of
    ``names`` in the scope before ``before`` (a length or bounds check)."""
    if not names:
        return False
    names = names | {alias for alias, measured in ctx.state.length_of.items() if measured & names}
    body = ctx.masked
    for match in _CHECK_CALL_RE.finditer(body, ctx.scope.start, before):
        parsed = _call_args(body, match.end() - 1)
        if parsed is not None and set(_IDENT_RE.findall(body[match.end() : parsed[1]])) & names:
            return True
    for match in _COMPARE_OP_RE.finditer(body, ctx.scope.start, before):
        left = body[max(ctx.scope.start, match.start() - _COMPARE_WINDOW) : match.start()]
        right = body[match.end() : min(before, match.end() + _COMPARE_WINDOW)]
        left = re.split(r"&&|\|\||[;{}?]|\breturn\b", left)[-1]
        right = re.split(r"&&|\|\||[;{}?]", right)[0]
        idents = set(_IDENT_RE.findall(left)) | set(_IDENT_RE.findall(right))
        if idents & names:
            return True
    return False


def _clamped(ctx: _Ctx, names: set[str], before: int) -> bool:
    """A ``x = MIN(...)``-style clamp of any of ``names`` before ``before``."""
    for name in names:
        for match in re.finditer(r"\b" + re.escape(name) + r"\s*=(?!=)", ctx.masked[ctx.scope.start : before]):
            rhs_lo = ctx.scope.start + match.end()
            rhs = ctx.masked[rhs_lo : min(before, rhs_lo + 200)].split(";", 1)[0]
            if _CLAMP_RE.search(rhs):
                return True
    return False


def _expr_names(ctx: _Ctx, lo: int, hi: int) -> set[str]:
    stripped = _SIZEOF_RE.sub(" ", ctx.masked[lo:hi])
    out: set[str] = set()
    for match in _IDENT_RE.finditer(stripped):
        before = stripped[max(0, match.start() - 2) : match.start()]
        if before.endswith(".") or before == "->":
            continue
        out.add(match.group(0))
    return out


def _sized_by(ctx: _Ctx, dst: str | None, names: set[str], before: int) -> bool:
    """``dst`` was allocated or resized from one of ``names`` before
    ``before`` (``p = malloc(len + 1); memcpy(p, s, len)``)."""
    if dst is None:
        return False
    measured = set(names)
    for alias, of in ctx.state.length_of.items():
        if of & names:
            measured.add(alias)
    for pos, expr in ctx.state.allocs.get(dst, ()):
        if pos < before and (_names_in(expr) & measured or "strlen" in expr):
            return True
    return any(pos < before for pos in ctx.state.resized.get(dst, ()))


def _names_in(text: str) -> set[str]:
    return set(_IDENT_RE.findall(_SIZEOF_RE.sub(" ", text)))


# ---------- Scope analysis ----------


@dataclass
class _Hit:
    kind: str
    pos: int
    taint: _Taint | None
    traced_direct: bool = False


def _scope_hits(masked: str, orig: str, scope: _Scope, file_constants: set[str]) -> list[_Hit]:
    body_lo, body_hi = scope.start, scope.end
    state = _State()
    request_vars: set[str] = set()
    for piece in _split_top(scope.params, 0, len(scope.params)):
        decl = scope.params[piece[0] : piece[1]]
        if _REQUEST_TYPE_RE.search(decl):
            names = _IDENT_RE.findall(re.sub(r"<[^<>]*>", " ", decl.split("=", 1)[0]))
            if names:
                request_vars.add(names[-1])
    if _MHD_HANDLER_RE.search(scope.params):
        request_vars |= scope.param_names & _MHD_REQUEST_PARAMS
    if scope.name == "ENDPOINT":
        request_vars |= set(_OATPP_PARAM_RE.findall(scope.params_orig))
    header_line = line_of(orig, scope.start)
    request_lines = {name: header_line for name in request_vars}
    for match in _MG_LOCAL_DECL_RE.finditer(masked, body_lo, body_hi):
        request_lines.setdefault(match.group(1), line_of(orig, match.start()))

    int_vars: set[str] = set()
    int_decl_positions: dict[str, int] = {}
    for match in _INT_DECL_RE.finditer(scope.params):
        int_vars.add(match.group(1))
    for match in _INT_DECL_RE.finditer(masked, body_lo, body_hi):
        int_vars.add(match.group(1))
        int_decl_positions.setdefault(match.group(1), match.start())

    constants = set(file_constants)
    for match in _DECL_STRING_LITERAL_RE.finditer(masked, body_lo, body_hi):
        constants.add(match.group(1))
    array_sizes: dict[str, int] = {}
    for match in _ARRAY_DECL_START_RE.finditer(masked, body_lo, body_hi):
        end = masked.find(";", match.end(), min(body_hi, match.end() + 400))
        if end > 0:
            for decl in _ARRAY_DECLARATOR_RE.finditer(masked[match.end() : end]):
                array_sizes.setdefault(decl.group(1), int(decl.group(2)))

    ctx = _Ctx(
        masked=masked,
        orig=orig,
        scope=scope,
        state=state,
        request_vars=request_lines,
        argv_scope="argv" in scope.param_names or bool(_ARGV_PARAM_RE.search(scope.params)),
        int_vars=int_vars,
        constants=constants,
        int_decl_positions=int_decl_positions,
        array_sizes=array_sizes,
    )

    events: list[tuple[int, int, re.Match[str]]] = []
    for match in _ASSIGN_RE.finditer(masked, body_lo, body_hi):
        events.append((match.end() - 1, 0, match))
    for match in _CALL_RE.finditer(masked, body_lo, body_hi):
        events.append((match.start(), 1, match))
    for match in _CIN_RE.finditer(masked, body_lo, body_hi):
        events.append((match.start(), 2, match))
    for match in _GETLINE_CIN_RE.finditer(masked, body_lo, body_hi):
        events.append((match.start(), 2, match))
    for match in _NEW_ARRAY_RE.finditer(masked, body_lo, body_hi):
        events.append((match.start(), 3, match))
    for match in _STRING_CTOR_DECL_RE.finditer(masked, body_lo, body_hi):
        events.append((match.end() - 1, 4, match))
    for match in _RESIZE_RE.finditer(masked, body_lo, body_hi):
        state.resized.setdefault(match.group(1), []).append(match.start())
    events.sort(key=lambda e: (e[0], e[1]))

    hits: list[_Hit] = []
    for pos, etype, match in events:
        if etype == 0:
            _on_assign(ctx, match)
        elif etype == 1:
            hits.extend(_on_call(ctx, match))
        elif etype == 2:
            state.add(match.group(1), match.end(), _Taint("stdin", line_of(orig, match.start())))
        elif etype == 4:
            _on_string_ctor(ctx, match)
        else:
            hit = _on_new_array(ctx, match)
            if hit is not None:
                hits.append(hit)
    return hits


def _rhs_span(masked: str, lo: int, hi_limit: int) -> int:
    depth = 0
    end = min(hi_limit, lo + _MAX_RHS_SPAN)
    for i in range(lo, end):
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif c in ",;" and depth == 0:
            return i
    return end


def _on_assign(ctx: _Ctx, match: re.Match[str]) -> None:
    lhs = match.group(1)
    name = _IDENT_RE.match(lhs).group(0)  # type: ignore[union-attr]
    if name in _CONTROL_WORDS or name in ("operator",):
        return
    rhs_lo = match.end()
    rhs_hi = _rhs_span(ctx.masked, rhs_lo, ctx.scope.end)
    rhs = ctx.masked[rhs_lo:rhs_hi]
    stripped = rhs.strip()
    # Constant-only assignment tracking (for format / command arguments). An
    # element write (`fmt[2] = '0' + n`) doesn't make a literal non-constant.
    indexed = "[" in ctx.masked[match.end(1) : match.end()]
    if stripped and not indexed:
        is_const = _is_constant_expr(ctx, rhs_lo, rhs_hi)
        previous = ctx.state.constant_assigned.get(name)
        ctx.state.constant_assigned[name] = is_const if previous is None else (previous and is_const)
    alloc = _ALLOC_ASSIGN_RE.match(ctx.masked, match.start())
    if alloc is not None:
        ctx.state.allocs.setdefault(name, []).append((match.end(), rhs))
    # The return value of a read is a byte count bounded by the caller's
    # buffer, not attacker data (the buffer itself is tainted by the call).
    call = _CALL_RE.match(_LEADING_CAST_RE.sub("", stripped, count=1))
    if call is not None and call.group(1) in _OUT_PARAM_SOURCES and call.group(1) not in ("gets",):
        return
    if _CLAMP_RE.search(rhs):
        return
    numeric_rhs = _is_numeric_expr(ctx, rhs)
    if numeric_rhs:
        measured = _expr_names(ctx, rhs_lo, rhs_hi) - {name}
        if measured:
            ctx.state.length_of.setdefault(name, set()).update(measured)
    taint = _expr_taint(ctx, rhs_lo, rhs_hi, want_string=False)
    if taint is None:
        return
    numeric = taint.numeric or name in ctx.int_vars or numeric_rhs
    ctx.state.add(name, rhs_lo, _Taint(taint.kind, taint.line, numeric, taint.bounded, taint.max_len))


def _on_string_ctor(ctx: _Ctx, match: re.Match[str]) -> None:
    open_index = match.end() - 1
    close_char = ")" if ctx.masked[open_index] == "(" else "}"
    depth = 0
    for i in range(open_index, min(len(ctx.masked), open_index + _MAX_RHS_SPAN)):
        c = ctx.masked[i]
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
            if depth == 0:
                if c != close_char:
                    return
                taint = _expr_taint(ctx, open_index + 1, i, want_string=True)
                if taint is not None:
                    ctx.state.add(match.group(1), i, taint)
                return


def _resolve_kind(spec: str, ctx: _Ctx, args: list[tuple[int, int]]) -> str | None:
    if ":" not in spec:
        return spec
    resolver, index_text = spec.split(":", 1)
    index = int(index_text)
    if index >= len(args):
        return None
    arg = ctx.masked[args[index][0] : args[index][1]]
    if _STDIN_ARG_RE.match(arg):
        return "stdin"
    if resolver == "fd" and _SOCKET_NAME_RE.search(arg):
        return "network"
    return "file"


def _on_call(ctx: _Ctx, match: re.Match[str]) -> list[_Hit]:
    name = match.group(1)
    if _is_definition(ctx.masked, match.start()):
        return []
    parsed = _call_args(ctx.masked, match.end() - 1)
    if parsed is None:
        return []
    args, _close = parsed
    pos = match.start()
    hits: list[_Hit] = []

    if name == "gets" and len(args) == 1:
        hits.append(_Hit("unbounded_copy", pos, _Taint("stdin", line_of(ctx.orig, pos)), traced_direct=True))
    if name in _UNBOUNDED_COPY and len(args) == 2:
        hit = _check_strcpy(ctx, args, pos)
        if hit is not None:
            hits.append(hit)
    if name in _SPRINTF:
        hit = _check_sprintf(ctx, args, _SPRINTF[name], pos)
        if hit is not None:
            hits.append(hit)
    if name in _SCANF:
        hit = _check_scanf(ctx, name, args, pos)
        if hit is not None:
            hits.append(hit)
    if name in _FORMAT_FUNCS:
        hit = _check_format(ctx, name, args, pos)
        if hit is not None:
            hits.append(hit)
    if name in _SHELL_COMMAND:
        hit = _check_shell(ctx, args, _SHELL_COMMAND[name], pos)
        if hit is not None:
            hits.append(hit)
    if name in _EXEC:
        hit = _check_exec(ctx, name, args, pos)
        if hit is not None:
            hits.append(hit)
    if name in _LENGTH_COPY:
        hit = _check_length_copy(ctx, args, _LENGTH_COPY[name], pos)
        if hit is not None:
            hits.append(hit)
    if name in _ALLOC:
        index = _ALLOC[name]
        if index < len(args):
            hit = _check_alloc(ctx, args[index], pos)
            if hit is not None:
                hits.append(hit)

    # Taint effects of the call, visible after it.
    after = match.end()
    if name in _OUT_PARAM_SOURCES:
        dst_index, spec = _OUT_PARAM_SOURCES[name]
        if dst_index < len(args):
            kind = _resolve_kind(spec, ctx, args)
            dst = _base_ident(ctx.masked[args[dst_index][0] : args[dst_index][1]])
            if dst is not None:
                ctx.state.write(dst, after)
            if kind is not None and dst is not None:
                # Every read here but `gets` takes a size: the result is
                # bounded by the destination.
                bounded = name != "gets"
                ctx.state.add(dst, after, _Taint(kind, line_of(ctx.orig, pos), False, bounded, ctx.array_sizes.get(dst)))
    if name in _PROPAGATORS:
        dst_index, src_index, rest = _PROPAGATORS[name]
        if dst_index < len(args) and src_index < len(args):
            src_spans = args[src_index:] if rest else [args[src_index]]
            taint: _Taint | None = None
            for lo, hi in src_spans:
                taint = _better(taint, _expr_taint(ctx, lo, hi, want_string=True))
            dst = _base_ident(ctx.masked[args[dst_index][0] : args[dst_index][1]])
            if dst is not None:
                ctx.state.write(dst, after)
            if taint is not None and dst is not None:
                if name in _BOUNDED_PROPAGATORS:
                    ctx.state.add(dst, after, _Taint(taint.kind, taint.line, False, True, ctx.array_sizes.get(dst)))
                else:
                    ctx.state.add(dst, after, _Taint(taint.kind, taint.line, False, taint.bounded, taint.max_len))
    if name in _SCANF and len(args) > _SCANF[name] + 1:
        for lo, hi in args[_SCANF[name] + 1 :]:
            dst = _base_ident(ctx.masked[lo:hi])
            if dst is not None:
                ctx.state.write(dst, after)
        if name in ("sscanf", "swscanf"):
            source = _expr_taint(ctx, args[0][0], args[0][1], want_string=True)
        else:
            kind = "stdin" if name in ("scanf", "wscanf") else _resolve_kind("stream:0", ctx, args)
            source = _Taint(kind, line_of(ctx.orig, pos)) if kind is not None else None
        if source is not None:
            _taint_scanf_outputs(ctx, args, _SCANF[name], source, after)
    return hits


def _taint_scanf_outputs(ctx: _Ctx, args: list[tuple[int, int]], fmt_index: int, source: _Taint, after: int) -> None:
    """Taint each scanf destination with the source, numeric for numeric
    conversions and bounded for a width-limited ``%s``/``%[``."""
    fmt = _format_literal(ctx, args[fmt_index])
    convs = [c for c in _SCANF_CONVERSION_RE.finditer(fmt) if c.group(0) != "%%" and not c.group("suppress")] if fmt else []
    for i, (lo, hi) in enumerate(args[fmt_index + 1 :]):
        dst = _base_ident(ctx.masked[lo:hi])
        if dst is None:
            continue
        conv = convs[i] if i < len(convs) else None
        if conv is None:
            taint = _Taint(source.kind, source.line, dst in ctx.int_vars, source.bounded, source.max_len)
        elif conv.group("conv") == "s" or conv.group("conv").startswith("["):
            width = conv.group("width")
            taint = _Taint(source.kind, source.line, False, width is not None or source.bounded,
                           int(width) + 1 if width else source.max_len)
        else:
            taint = _Taint(source.kind, source.line, True)
        ctx.state.add(dst, after, taint)


def _is_definition(masked: str, start: int) -> bool:
    """``int printf(const char *fmt, ...)``: a declaration, not a call."""
    i = _skip_ws_back(masked, start - 1)
    if i < 0:
        return False
    c = masked[i]
    if c == "*" or c == "&":
        j = _skip_ws_back(masked, i - 1)
        return j >= 0 and (masked[j].isalnum() or masked[j] == "_")
    if c.isalnum() or c == "_":
        word = _WORD_BEFORE_RE.search(masked[max(0, i - 40) : i + 1])
        return word is not None and word.group(1) not in _CONTROL_WORDS and word.group(1) not in ("else", "new", "delete", "co_await", "co_return", "throw")
    return False


def _string_taint(ctx: _Ctx, span: tuple[int, int]) -> _Taint | None:
    return _expr_taint(ctx, span[0], span[1], want_string=True)


def _direct(ctx: _Ctx, span: tuple[int, int]) -> bool:
    text = ctx.masked[span[0] : span[1]]
    return any(p.search(text) for _, p in _DIRECT_SOURCES) or (ctx.argv_scope and bool(_ARGV_USE_RE.search(text)))


def _check_strcpy(ctx: _Ctx, args: list[tuple[int, int]], pos: int) -> _Hit | None:
    if _is_constant_expr(ctx, *args[1]):
        return None
    taint = _string_taint(ctx, args[1])
    if taint is None:
        return None
    src_names = _expr_names(ctx, *args[1])
    dst = _base_ident(ctx.masked[args[0][0] : args[0][1]])
    if not _overflows(ctx, taint, dst):
        return None
    if _compared_before(ctx, src_names, pos) or _sized_by(ctx, dst, src_names, pos):
        return None
    return _Hit("unbounded_copy", pos, taint, _direct(ctx, args[1]))


def _overflows(ctx: _Ctx, taint: _Taint, dst: str | None) -> bool:
    """Can a copy of ``taint`` overflow ``dst``? An unbounded string can; a
    bounded one only into a declared array smaller than its cap."""
    if not taint.bounded:
        return True
    size = ctx.array_sizes.get(dst) if dst else None
    return size is not None and taint.max_len is not None and size < taint.max_len


def _format_literal(ctx: _Ctx, span: tuple[int, int]) -> str | None:
    """The concatenated literal text of a constant format argument; macro
    pieces between literals (``"%" PRIu64``) become an integer conversion."""
    masked = ctx.masked[span[0] : span[1]]
    if not _LITERAL_START_RE.match(masked):
        return None
    pieces: list[str] = []
    i = 0
    text = ctx.orig[span[0] : span[1]]
    while i < len(masked):
        if masked[i] == '"':
            j = masked.find('"', i + 1)
            if j < 0:
                return None
            pieces.append(text[i + 1 : j])
            i = j + 1
        elif masked[i].isalpha() or masked[i] == "_":
            ident = _IDENT_RE.match(masked, i)
            if ident is None:
                break
            if ident.group(0) not in ("u8", "u", "U", "L"):
                pieces.append("d")
            i = ident.end()
        else:
            i += 1
    return "".join(pieces)


def _check_sprintf(ctx: _Ctx, args: list[tuple[int, int]], fmt_index: int, pos: int) -> _Hit | None:
    if fmt_index >= len(args):
        return None
    fmt = _format_literal(ctx, args[fmt_index])
    if fmt is None:
        return None  # non-constant format: reported by the format-string check
    dst = _base_ident(ctx.masked[args[0][0] : args[0][1]])
    arg_index = fmt_index + 1
    best: _Hit | None = None
    for conv in _CONVERSION_RE.finditer(fmt):
        if conv.group(0) == "%%":
            continue
        if conv.group("width") == "*":
            arg_index += 1
        if conv.group("prec") == "*":
            arg_index += 1
        if conv.group("conv") in ("s", "S") and conv.group("prec") is None and arg_index < len(args):
            span = args[arg_index]
            taint = _string_taint(ctx, span)
            names = _expr_names(ctx, *span)
            if (
                taint is not None
                and _overflows(ctx, taint, dst)
                and not _compared_before(ctx, names, pos)
                and not _sized_by(ctx, dst, names, pos)
                and (best is None or _rank(taint) > _rank(best.taint))  # type: ignore[arg-type]
            ):
                best = _Hit("unbounded_copy", pos, taint, _direct(ctx, span))
        arg_index += 1
    return best


def _check_scanf(ctx: _Ctx, name: str, args: list[tuple[int, int]], pos: int) -> _Hit | None:
    fmt_index = _SCANF[name]
    if fmt_index >= len(args):
        return None
    fmt = _format_literal(ctx, args[fmt_index])
    if fmt is None:
        return None
    unbounded = any(
        c.group(0) != "%%"
        and not c.group("suppress")
        and not c.group("width")
        and not c.group("alloc")
        and (c.group("conv") == "s" or c.group("conv").startswith("["))
        for c in _SCANF_CONVERSION_RE.finditer(fmt)
    )
    if not unbounded:
        return None
    line = line_of(ctx.orig, pos)
    if name in ("scanf", "wscanf"):
        return _Hit("unbounded_copy", pos, _Taint("stdin", line), True)
    if name in ("fscanf", "fwscanf"):
        kind = _resolve_kind("stream:0", ctx, args) or "file"
        return _Hit("unbounded_copy", pos, _Taint(kind, line), True)
    taint = _string_taint(ctx, args[0])
    if taint is None:
        return None
    return _Hit("unbounded_copy", pos, taint, _direct(ctx, args[0]))


def _check_format(ctx: _Ctx, name: str, args: list[tuple[int, int]], pos: int) -> _Hit | None:
    index = _FORMAT_FUNCS[name]
    if index >= len(args):
        return None
    span = args[index]
    if _is_constant_expr(ctx, *span):
        return None
    base = _base_ident(ctx.masked[span[0] : span[1]])
    variadic = "..." in ctx.scope.params or "va_list" in ctx.scope.params
    if base is not None and base in ctx.scope.param_names and (variadic or name in _VA_FORMAT_FUNCS):
        return None  # a format wrapper forwarding its caller's format
    if name in _VA_FORMAT_FUNCS and variadic:
        return None
    taint = _string_taint(ctx, span)
    if taint is None and _is_call_result(ctx, span):
        return None  # e.g. a function returning a constant format
    return _Hit("format_string", pos, taint, taint is not None and _direct(ctx, span))


def _is_call_result(ctx: _Ctx, span: tuple[int, int]) -> bool:
    text = ctx.masked[span[0] : span[1]].strip()
    return text.endswith(")") and not text.startswith("(") and _DATA_CALL_RE.search(text) is None


def _check_shell(ctx: _Ctx, args: list[tuple[int, int]], index: int, pos: int) -> _Hit | None:
    if index >= len(args) or _is_constant_expr(ctx, *args[index]):
        return None
    if not ctx.masked[args[index][0] : args[index][1]].strip():
        return None
    taint = _string_taint(ctx, args[index])
    if taint is None and _is_call_result(ctx, args[index]):
        return None
    return _Hit("native_command_exec", pos, taint, taint is not None and _direct(ctx, args[index]))


def _check_exec(ctx: _Ctx, name: str, args: list[tuple[int, int]], pos: int) -> _Hit | None:
    taint: _Taint | None = None
    direct = False
    for span in args:
        t = _string_taint(ctx, span)
        if t is not None and _better(taint, t) is t:
            taint, direct = t, _direct(ctx, span)
    if taint is not None:
        return _Hit("native_command_exec", pos, taint, direct)
    # An untraced but non-constant `sh -c <cmd>` line.
    if name.startswith("execl"):
        for i, span in enumerate(args[:-1]):
            if _SH_C_RE.match(ctx.orig[span[0] : span[1]]):
                cmd = args[i + 1]
                if not _is_constant_expr(ctx, *cmd) and ctx.masked[cmd[0] : cmd[1]].strip() not in ("NULL", "0", "nullptr"):
                    return _Hit("native_command_exec", pos, None)
    return None


def _check_length_copy(ctx: _Ctx, args: list[tuple[int, int]], spec: tuple[int, int, int], pos: int) -> _Hit | None:
    dst_index, _src_index, len_index = spec
    if len_index >= len(args):
        return None
    span = args[len_index]
    text = ctx.masked[span[0] : span[1]]
    if _CLAMP_RE.search(text):
        return None
    taint = _expr_taint(ctx, span[0], span[1], want_string=False)
    if taint is None:
        return None
    names = _expr_names(ctx, *span)
    dst = _base_ident(ctx.masked[args[dst_index][0] : args[dst_index][1]])
    if _compared_before(ctx, names, pos) or _clamped(ctx, names, pos) or _sized_by(ctx, dst, names, pos):
        return None
    return _Hit("tainted_copy_length", pos, taint, _direct(ctx, span))


def _product_terms(masked: str, lo: int, hi: int) -> list[tuple[int, int]]:
    """Top-level ``+``/``-`` terms of ``masked[lo:hi]`` that multiply or shift."""
    terms: list[tuple[int, int]] = []
    depth = 0
    start = lo
    for i in range(lo, hi + 1):
        c = masked[i] if i < hi else "+"
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c in "+-" and masked[i + 1 : i + 2] not in ("+", "-", ">", "=") and masked[i - 1 : i] not in ("+", "-"):
            if _MUL_RE.search(masked, start, i):
                terms.append((start, i))
            start = i + 1
    return terms


def _check_alloc(ctx: _Ctx, span: tuple[int, int], pos: int) -> _Hit | None:
    terms = _product_terms(ctx.masked, span[0], span[1])
    if not terms:
        return None
    if _OVERFLOW_GUARD_RE.search(ctx.masked, ctx.scope.start, pos):
        return None
    taint: _Taint | None = None
    names: set[str] = set()
    direct = False
    for lo, hi in terms:
        t = _expr_taint(ctx, lo, hi, want_string=False)
        if t is not None:
            if _better(taint, t) is t:
                direct = _direct(ctx, (lo, hi))
            taint = _better(taint, t)
            names |= _expr_names(ctx, lo, hi)
    if taint is None:
        return None
    if _compared_before(ctx, names, pos) or _clamped(ctx, names, pos):
        return None
    return _Hit("alloc_size_overflow", pos, taint, direct)


def _on_new_array(ctx: _Ctx, match: re.Match[str]) -> _Hit | None:
    open_bracket = match.end() - 1
    depth = 0
    hi = min(len(ctx.masked), open_bracket + 400)
    for i in range(open_bracket, hi):
        c = ctx.masked[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return _check_alloc(ctx, (open_bracket + 1, i), match.start())
    return None


# ---------- Public entry point ----------


def _severity(taint: _Taint | None, downranked: bool) -> tuple[str, str]:
    if downranked:
        return "low", "low"
    if taint is None:
        return "low", "low"
    if taint.kind in _REMOTE:
        return "high", "high"
    return "medium", "medium"


def _snippet(content: str, offset: int) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > _SNIPPET_MAX_CHARS:
        line = line[: _SNIPPET_MAX_CHARS - 1] + "…"
    return line


def find_native_weaknesses(content: str, relative: str) -> list[CodeWeakness]:
    """C/C++ memory-safety and command-exec weaknesses in one file."""
    if CodeWeakness is None or is_test_path(relative):
        return []
    masked = mask_source(content)
    if _CALL_RE.search(masked) is None and _NEW_ARRAY_RE.search(masked) is None:
        return []
    file_constants = set(_DEFINE_STRING_RE.findall(content))
    for match in _DECL_STRING_LITERAL_RE.finditer(masked):
        file_constants.add(match.group(1))
    downranked = _is_downranked(relative)
    scopes = _scopes(masked, content)
    starts = [s.start for s in scopes]
    # Each sink belongs to its innermost enclosing function or lambda.
    owner: dict[int, _Scope] = {}
    for match in _CALL_RE.finditer(masked):
        _assign_owner(owner, scopes, starts, match.start())
    for match in _NEW_ARRAY_RE.finditer(masked):
        _assign_owner(owner, scopes, starts, match.start())
    out: list[CodeWeakness] = []
    seen: set[tuple[str, int]] = set()
    for scope in {id(s): s for s in owner.values()}.values():
        for hit in _scope_hits(masked, content, scope, file_constants):
            if owner.get(hit.pos) is not scope:
                continue  # found while scanning an enclosing scope
            line = line_of(content, hit.pos)
            key = (hit.kind, line)
            if key in seen:
                continue
            seen.add(key)
            severity, confidence = _severity(hit.taint, downranked)
            out.append(
                CodeWeakness(
                    kind=hit.kind,  # type: ignore[arg-type]
                    file=relative,
                    line=line,
                    evidence_text=_snippet(content, hit.pos),
                    severity=severity,  # type: ignore[arg-type]
                    confidence=confidence,  # type: ignore[arg-type]
                    source_kind=hit.taint.kind if hit.taint else None,
                    source_line=hit.taint.line if hit.taint else None,
                )
            )
    out.sort(key=lambda w: (w.line or 0, w.kind))
    return out


def _assign_owner(owner: dict[int, _Scope], scopes: list[_Scope], starts: list[int], pos: int) -> None:
    """The innermost scope containing ``pos``: walking back from the last
    scope that starts before it, the first one still open at ``pos``."""
    i = bisect.bisect_left(starts, pos) - 1
    for _ in range(_MAX_OWNER_WALK):
        if i < 0:
            return
        if scopes[i].end > pos:
            owner[pos] = scopes[i]
            return
        i -= 1


__all__ = ["find_native_weaknesses", "is_test_path", "mask_source"]
