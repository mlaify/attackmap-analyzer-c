"""Hostile inputs for regexes fixed in review round 3 (must stay linear)."""

import time

from attackmap_analyzer_c import native_deps as nd


def test_conan_section_scan_is_linear_on_blank_lines() -> None:
    start = time.perf_counter()
    list(nd._CONAN_SECTION_RE.finditer("[requires]\nzlib/1.2.13\n" + "\n" * 1_000_000))
    assert time.perf_counter() - start < 1.0
    found = [m.group(1) for m in nd._CONAN_SECTION_RE.finditer("[requires]\nzlib/1\n  [tool_requires] \ncmake/3\n")]
    assert found == ["requires", "tool_requires"]
