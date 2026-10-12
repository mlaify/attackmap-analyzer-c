"""CMake / Conan / vcpkg dependency inventory (AttackMap#191).

``native_deps.py`` and this file are mirrored verbatim in the C and C++
analyzer plugins (only the import line differs)."""

from __future__ import annotations

import random
from pathlib import Path

from attackmap_analyzer_c.native_deps import (
    native_dependencies,
    parse_cmake,
    parse_conan_lock,
    parse_conanfile_py,
    parse_conanfile_txt,
    parse_vcpkg_json,
)


def _deps(hints) -> list[tuple[str, str, bool]]:
    return [(d.name, d.version, d.dev) for d in hints]


# ---------- vcpkg ----------


def test_vcpkg_manifest() -> None:
    text = """{
  "name": "app",
  "dependencies": [
    "openssl",
    {"name": "fmt", "version>=": "10.1.0"},
    {"name": "spdlog"},
    {"name": "vcpkg-cmake", "host": true}
  ],
  "overrides": [{"name": "spdlog", "version": "1.12.0"}],
  "builtin-baseline": "9e593bb18ea69cc5095e012465dcd675a822ed0d"
}"""
    hints = parse_vcpkg_json(text, "vcpkg.json")
    assert _deps(hints) == [
        ("openssl", "", False),
        ("fmt", ">=10.1.0", False),
        ("spdlog", "1.12.0", False),
        ("vcpkg-cmake", "", True),
    ]
    assert [h.resolved for h in hints] == [False, False, True, False]
    assert {h.ecosystem for h in hints} == {"vcpkg"}
    assert "builtin-baseline 9e593bb" in hints[0].evidence_text and hints[1].line == 5


# ---------- Conan ----------


def test_conanfile_txt_sections() -> None:
    text = (
        "[requires]\njsoncpp/1.9.4\nzlib/1.2.13#a1b2c3\n#libpq/13.2\nboost/[>=1.80 <2.0]\n"
        "poco/1.12.4@user/stable\n\n[tool_requires]\ncmake/3.27.0\n[generators]\nCMakeDeps\n[options]\nzlib/*:shared=True\n"
    )
    hints = parse_conanfile_txt(text, "conanfile.txt")
    assert _deps(hints) == [
        ("jsoncpp", "1.9.4", False),
        ("zlib", "1.2.13", False),
        ("boost", "[>=1.80 <2.0]", False),
        ("poco", "1.12.4", False),
        ("cmake", "3.27.0", True),
    ]
    assert [h.line for h in hints] == [2, 3, 5, 6, 9]
    assert {h.ecosystem for h in hints} == {"conan"}


def test_conanfile_py_is_read_not_run() -> None:
    text = (
        "from conan import ConanFile\n"
        "class App(ConanFile):\n"
        '    requires = ("openssl/3.1.4",\n                "zlib/1.3")\n'
        '    tool_requires = "ninja/1.11.1"\n'
        "    def requirements(self):\n"
        '        self.requires("fmt/10.1.1")\n'
        '        self.test_requires("gtest/1.14.0")\n'
        '        self.requires(f"boost/{self.version}")\n'
    )
    assert _deps(parse_conanfile_py(text, "conanfile.py")) == [
        ("openssl", "3.1.4", False),
        ("zlib", "1.3", False),
        ("ninja", "1.11.1", True),
        ("fmt", "10.1.1", False),
        ("gtest", "1.14.0", True),
    ]


def test_conan_lock_is_resolved() -> None:
    text = '{"version": "0.5", "requires": ["zlib/1.3#b3b71bfe8dd07abc7b82ff2bd0eac021%1695128467.123"], "build_requires": ["cmake/3.27.0"]}'
    hints = parse_conan_lock(text, "conan.lock")
    assert _deps(hints) == [("zlib", "1.3", False), ("cmake", "3.27.0", True)]
    assert all(h.resolved for h in hints)


# ---------- CMake ----------


def _cmake(text: str, path: str = "CMakeLists.txt"):
    deps, issues = parse_cmake(text, path)
    return _deps(deps), [(i.package, i.severity) for i in issues]


def test_fetchcontent_git_refs() -> None:
    text = (
        "include(FetchContent)\n"
        "FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3)\n"
        "FetchContent_Declare(\n  fmt\n  GIT_REPOSITORY https://github.com/fmtlib/fmt\n  GIT_TAG master\n)\n"
        "FetchContent_Declare(spdlog GIT_REPOSITORY https://github.com/gabime/spdlog)\n"
        "FetchContent_Declare(pinned GIT_REPOSITORY https://github.com/a/b GIT_TAG 0123456789abcdef0123456789abcdef01234567)\n"
        "FetchContent_Declare(var GIT_REPOSITORY https://github.com/a/c GIT_TAG ${C_TAG})\n"
    )
    deps, issues = _cmake(text)
    assert deps == [
        ("json", "v3.11.3", False),
        ("fmt", "master", False),
        ("spdlog", "", False),
        ("pinned", "0123456789abcdef0123456789abcdef01234567", False),
        ("var", "", False),
    ]
    assert issues == [("json", "low"), ("fmt", "medium"), ("spdlog", "medium")]


def test_url_downloads_need_a_hash() -> None:
    text = (
        "FetchContent_Declare(gtest URL https://github.com/google/googletest/archive/main.tar.gz)\n"
        'ExternalProject_Add(lua URL "http://www.lua.org/ftp/lua-5.4.6.tar.gz" URL_MD5 ${LUA_MD5})\n'
        "FetchContent_Declare(zlib URL https://zlib.net/zlib-1.3.1.tar.gz URL_HASH SHA256=abc)\n"
        'ExternalProject_Add(lxml URL "https://github.com/n1tehawk/LuaXML/archive/v1.8.0.zip" PREFIX x)\n'
    )
    deps, issues = _cmake(text)
    assert deps == [("gtest", "", True), ("lua", "5.4.6", False), ("zlib", "1.3.1", False), ("lxml", "1.8.0", False)]
    assert issues == [("gtest", "medium"), ("lxml", "medium")]
    _, flagged = parse_cmake(text, "CMakeLists.txt")
    assert "of a branch" in flagged[0].evidence_text and flagged[0].ecosystem == "cmake" and flagged[0].line == 1


def test_cpm_forms() -> None:
    text = (
        'CPMAddPackage("gh:fmtlib/fmt#10.1.1")\n'
        'CPMAddPackage("gh:catchorg/Catch2@3.4.0")\n'
        "CPMAddPackage(NAME cmake-sbom GITHUB_REPOSITORY DEMCON/cmake-sbom GIT_TAG v1.5.0 DOWNLOAD_ONLY YES)\n"
        "CPMAddPackage(NAME cxxopts GITHUB_REPOSITORY jarro2783/cxxopts VERSION 3.1.1)\n"
    )
    deps, issues = _cmake(text)
    assert deps == [("fmt", "10.1.1", False), ("Catch2", "3.4.0", True), ("cmake-sbom", "v1.5.0", False), ("cxxopts", "v3.1.1", False)]
    assert [s for _, s in issues] == ["low", "low", "low", "low"]


def test_find_package() -> None:
    text = (
        "find_package(Threads REQUIRED)\nfind_package(PkgConfig)\n"
        "find_package(Boost 1.61.0 REQUIRED COMPONENTS system)\n"
        "find_package(OpenSSL 3.0 EXACT REQUIRED)\nfind_package(ZLIB REQUIRED)\n"
        "find_package(${PROJECT_NAME}Deps)\nfind_package(GTest)\n"
        "# find_package(Commented 1.0)\n#[[ find_package(Bracketed) ]]\n"
        'message("# find_package(InString)")\n'
    )
    deps, issues = _cmake(text)
    assert deps == [("Boost", ">=1.61.0", False), ("OpenSSL", "==3.0", False), ("ZLIB", "", False), ("GTest", "", True)]
    assert issues == []


def test_manifests_under_tests_and_examples_are_dev() -> None:
    deps, _ = _cmake("find_package(CURL REQUIRED)\n", "test/CMakeLists.txt")
    assert deps == [("CURL", "", True)]


# ---------- walk + robustness ----------


def test_walk_finds_every_manifest_and_skips_vendored(tmp_path: Path) -> None:
    (tmp_path / "vcpkg.json").write_text('{"dependencies": ["zlib"]}', encoding="utf-8")
    (tmp_path / "conanfile.txt").write_text("[requires]\nfmt/10.1.1\n", encoding="utf-8")
    (tmp_path / "cmake").mkdir()
    (tmp_path / "cmake" / "deps.cmake").write_text("FetchContent_Declare(x GIT_REPOSITORY https://g/x GIT_TAG main)\n", encoding="utf-8")
    (tmp_path / "third_party").mkdir()
    (tmp_path / "third_party" / "CMakeLists.txt").write_text("find_package(Vendored 1.0)\n", encoding="utf-8")
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "vcpkg.json").write_text("{not json", encoding="utf-8")
    deps, issues = native_dependencies(tmp_path, {"third_party"})
    assert sorted((d.ecosystem, d.name) for d in deps) == [("cmake", "x"), ("conan", "fmt"), ("vcpkg", "zlib")]
    assert [(i.package, i.severity, i.file) for i in issues] == [("x", "medium", "cmake/deps.cmake")]


def test_fuzz_never_raises() -> None:
    rng = random.Random(191)
    pieces = ["FetchContent_Declare(", "find_package(", "CPMAddPackage(", "GIT_TAG", "URL", '"', "(", ")", "#",
              "#[[", "]]", "${X}", "main", "a/1.0", "[requires]", "\n", " ", "{", "}", '"dependencies"', ":", "[", "]"]
    for _ in range(400):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 60)))
        parse_cmake(text, "CMakeLists.txt")
        parse_conanfile_txt(text, "conanfile.txt")
        parse_conanfile_py(text, "conanfile.py")
        for parser in (parse_vcpkg_json, parse_conan_lock):
            try:
                parser(text, "x.json")
            except (ValueError, TypeError, KeyError, AttributeError):
                pass  # native_dependencies() skips malformed JSON
    parse_cmake("FetchContent_Declare(" + "(" * 50000, "CMakeLists.txt")


# ---------- analyzer integration ----------


def test_analyzer_emits_dependencies_and_issues(tmp_path: Path) -> None:
    from attackmap_analyzer_c import CAnalyzer

    (tmp_path / "main.c").write_text("int main() { return 0; }\n", encoding="utf-8")
    (tmp_path / "CMakeLists.txt").write_text(
        "project(app)\nfind_package(ZLIB 1.2)\n"
        "FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt GIT_TAG master)\n",
        encoding="utf-8",
    )
    (tmp_path / "vcpkg.json").write_text('{"dependencies": ["zlib"]}', encoding="utf-8")
    result = CAnalyzer().analyze(tmp_path)
    assert sorted((d.ecosystem, d.name, d.version) for d in result.dependencies) == [
        ("cmake", "ZLIB", ">=1.2"),
        ("cmake", "fmt", "master"),
        ("vcpkg", "zlib", ""),
    ]
    assert [(i.kind, i.package, i.severity) for i in result.supply_chain_issues] == [("mutable_vcs_dependency", "fmt", "medium")]
    assert "project:app" in {h.hint for h in result.service_hints}
