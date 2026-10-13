"""Hostile inputs for regexes fixed in review round 3 (must stay linear)."""

import time

from attackmap_analyzer_c import native_sinks as ns


def _fast(fn, limit: float = 1.0) -> None:
    start = time.perf_counter()
    fn()
    assert time.perf_counter() - start < limit


def test_literal_only_is_not_exponential_on_prefixed_literals() -> None:
    _fast(lambda: ns._LITERAL_ONLY_RE.match('""' + 'u8""' * 40 + " + p"))
    assert ns._LITERAL_ONLY_RE.match('"%" PRIu64 "\\n"')
    assert ns._LITERAL_ONLY_RE.match('u8"a" L"b"')
    assert not ns._LITERAL_ONLY_RE.match('"ping " + host')


def test_int_declaration_scan_is_linear_on_keyword_runs() -> None:
    _fast(lambda: list(ns._INT_DECL_RE.finditer("int " * 250_000 + "!")))
    found = [m.group(1) for m in ns._INT_DECL_RE.finditer("unsigned long long int n = 3; const size_t len; int x;")]
    assert found == ["n", "len", "x"]
