"""Native dependency inventory: CMake, Conan and vcpkg (AttackMap#191).

Emits ``DependencyHint`` records so ``--cve`` reaches native dependencies,
plus ``SupplyChainIssue`` records for CMake downloads that aren't pinned.

- **vcpkg** (``vcpkg.json``): ``dependencies`` (strings or objects with
  ``version>=``), ``overrides`` (exact pins, ``resolved=True``) and the
  ``builtin-baseline`` (recorded in the evidence). ``host`` dependencies are
  build tools (``dev=True``). Ecosystem ``vcpkg``.
- **Conan** (``conanfile.txt``, ``conanfile.py``, ``conan.lock``): ``[requires]``
  / ``requires = ...`` / ``self.requires("zlib/1.3")``; tool, build and test
  requirements are ``dev``. ``conan.lock`` entries are exact
  (``resolved=True``). ``conanfile.py`` is read as text and never executed.
  Ecosystem ``conan``.
- **CMake** (``CMakeLists.txt``, ``*.cmake``): ``FetchContent_Declare``,
  ``ExternalProject_Add``, ``CPMAddPackage`` and ``find_package``. Ecosystem
  ``cmake`` (inventory only: no OSV database). A git download whose
  ``GIT_TAG`` is missing or names a branch, or an archive ``URL`` with no
  ``URL_HASH``/``URL_MD5``, is a ``mutable_vcs_dependency`` (medium). A tag
  or short SHA is low. A full 40-hex commit SHA isn't flagged.

Arguments that are CMake variables (``${X}``) are unresolved and never flagged.

This module is mirrored verbatim in attackmap-analyzer-c and
attackmap-analyzer-cpp; both may run on a mixed repo, and core's merge
dedupes identical records.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path, PurePosixPath

from attackmap.sdk import iter_repo_files, line_of, read_source, rel

try:  # attackmap >= the release with the `cmake` ecosystem and SupplyChainIssue (AttackMap#191)
    from attackmap.sdk import DEPENDENCY_ECOSYSTEMS, DependencyHint, SupplyChainIssue
except ImportError:  # older core: no native SBOM
    DependencyHint = SupplyChainIssue = None  # type: ignore[assignment,misc]
    DEPENDENCY_ECOSYSTEMS = ()

_MANIFEST_NAMES = {"CMakeLists.txt", "vcpkg.json", "conanfile.txt", "conanfile.py", "conan.lock"}
_MAX_ARGS_SPAN = 8000
_MAX_FILE_CHARS = 2_000_000

_CMAKE_QUOTED_BODY_RE = re.compile(r"(?:[^\"\\]|\\[\s\S])*")
_PAREN_RE = re.compile(r"[()]")
_CMAKE_COMMAND_RE = re.compile(
    r"\b(FetchContent_Declare|ExternalProject_Add|CPMAddPackage|CPMFindPackage|find_package)\s*\(", re.IGNORECASE
)
_CMAKE_TOKEN_RE = re.compile(r"\"((?:[^\"\\]|\\[\s\S])*)\"|([^\s\"()]+)")
_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{7,39}$")
_BRANCH_REFS = frozenset({"main", "master", "develop", "dev", "devel", "trunk", "head", "latest", "stable", "nightly"})
_URL_VERSION_RE = re.compile(r"(?:^|[/_-])v?(\d+(?:[._]\d+){1,3})(?=[^/]*$|/)")
_URL_BRANCH_RE = re.compile(r"/(?:archive|zip|tarball|zipball)/(?:refs/heads/)?(?:main|master|develop|trunk|HEAD)\b"
                            r"|/refs/heads/|/(?:main|master)\.(?:zip|tar\.gz|tgz)$", re.IGNORECASE)
_VERSION_TOKEN_RE = re.compile(r"^\d+(?:\.\d+){0,3}$")
# CMake >= 3.19 version range: `1.2...2.0` (inclusive) / `1.2...<2.0`.
_VERSION_RANGE_RE = re.compile(r"^(\d+(?:\.\d+){0,3})\.\.\.(<?)(\d+(?:\.\d+){0,3})$")
_CPM_SHORTHAND_RE = re.compile(r"^(?:(gh|gl|bb):)?([^@#\s]+?)(?:@([^#\s]+))?(?:#(\S+))?$")
# CMake modules and build tools found with find_package that aren't
# third-party code shipped with the project.
_FIND_PACKAGE_TOOLING = frozenset(
    {"threads", "pkgconfig", "git", "doxygen", "python", "python2", "python3", "pythoninterp", "pythonlibs",
     "perl", "sphinx", "bison", "flex", "swig", "java", "jni", "cuda", "openmp", "zephyr", "librt", "winsock",
     "cmakeparsearguments", "packagehandlestandardargs"}
)
_TEST_DEPS = frozenset({"gtest", "googletest", "gmock", "catch2", "catch", "doctest", "benchmark", "boost.test", "cppunit",
                        "check", "cmocka", "unity"})
_TEST_SEGMENTS = frozenset({"test", "tests", "testing", "unittest", "unittests", "unit_test", "fuzz", "fuzztest",
                            "bench", "benchmark", "benchmarks", "example", "examples", "sample", "samples", "demo"})

# Conan
_CONAN_REF_RE = re.compile(r"\b([A-Za-z0-9_][A-Za-z0-9_.+-]{0,100})/(\[[^\]\n]{1,80}\]|[A-Za-z0-9_.+~-]{1,64})"
                           r"(?:@[\w.+-]{1,64}/[\w.+-]{1,64})?(?:#[0-9a-f]{1,64})?")
_CONAN_SECTION_RE = re.compile(r"^\s*\[([a-z_]+)\]\s*$", re.MULTILINE)
_CONAN_REQUIRE_NAMES = frozenset({"requires", "tool_requires", "build_requires", "test_requires"})
_DEV_SECTIONS = frozenset({"tool_requires", "build_requires", "test_requires"})


MANIFEST_NAMES = frozenset(_MANIFEST_NAMES)
MANIFEST_SUFFIXES = frozenset({".cmake"})


def is_manifest(path: Path) -> bool:
    """A file ``manifest_records`` understands (for the analyzer's own walk)."""
    return path.name in MANIFEST_NAMES or path.suffix == ".cmake"


def manifest_records(path: Path, text: str, relative: str) -> tuple[list, list]:
    """``(DependencyHint list, SupplyChainIssue list)`` from one manifest.
    A malformed manifest yields nothing; it never raises."""
    if DependencyHint is None or "cmake" not in DEPENDENCY_ECOSYSTEMS or len(text) > _MAX_FILE_CHARS:
        return [], []
    name = path.name
    try:
        if name == "vcpkg.json":
            return parse_vcpkg_json(text, relative), []
        if name == "conanfile.txt":
            return parse_conanfile_txt(text, relative), []
        if name == "conanfile.py":
            return parse_conanfile_py(text, relative), []
        if name == "conan.lock":
            return parse_conan_lock(text, relative), []
        if name == "CMakeLists.txt" or path.suffix == ".cmake":
            return parse_cmake(text, relative)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, MemoryError):
        pass  # malformed or hostile (deeply nested JSON, unparsable Python)
    return [], []


def native_dependencies(root: Path, skip_dirs: set[str]) -> tuple[list, list]:
    """Walk ``root`` and collect every manifest's records (deduped)."""
    deps: list = []
    issues: list = []
    for path in iter_repo_files(root, suffixes=set(MANIFEST_SUFFIXES), names=set(MANIFEST_NAMES), skip_dirs=skip_dirs):
        text = read_source(path)
        if text is None:
            continue
        found, flagged = manifest_records(path, text, rel(path, root))
        deps.extend(found)
        issues.extend(flagged)
    return dedupe_dependencies(deps), issues


def dedupe_dependencies(deps: list) -> list:
    seen: set[tuple] = set()
    out = []
    for dep in deps:
        key = (dep.ecosystem, dep.name, dep.version, dep.file, dep.dev)
        if key not in seen:
            seen.add(key)
            out.append(dep)
    return out


def _is_test_manifest(relative: str) -> bool:
    return any(p.lower() in _TEST_SEGMENTS for p in PurePosixPath(relative).parts[:-1])


def _line(text: str, needle: str) -> int | None:
    index = text.find(needle)
    return line_of(text, index) if index >= 0 else None


# ---------- vcpkg ----------


def _list(value: object) -> list:
    """A JSON list field, or nothing (`"dependencies": "zlib"` is malformed)."""
    return value if isinstance(value, list) else []


def parse_vcpkg_json(text: str, relative: str) -> list:
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    baseline = data.get("builtin-baseline")
    overrides = {}
    for item in _list(data.get("overrides")):
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            version = item.get("version") or item.get("version-string") or item.get("version-semver") or item.get("version-date")
            if isinstance(version, str):
                overrides[item["name"]] = version
    dev_manifest = _is_test_manifest(relative)
    out = []
    for item in _list(data.get("dependencies")):
        if isinstance(item, str):
            name, minimum, host = item, None, False
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            name, minimum, host = item["name"], item.get("version>="), bool(item.get("host"))
        else:
            continue
        if name in overrides:
            version, resolved, how = overrides[name], True, "override"
        elif isinstance(minimum, str):
            version, resolved, how = f">={minimum}", False, "version>="
        else:
            version, resolved, how = "", False, "baseline"
        evidence = f"vcpkg {name} ({how}" + (f", builtin-baseline {baseline}" if isinstance(baseline, str) else "") + ")"
        out.append(DependencyHint(
            name=name, version=version, ecosystem="vcpkg", file=relative, line=_line(text, f'"{name}"'),
            dev=host or dev_manifest, resolved=resolved, evidence_text=evidence,
        ))
    return out


# ---------- Conan ----------


def _conan_hint(ref: re.Match[str], text: str, relative: str, dev: bool, offset: int, resolved: bool = False):
    version = ref.group(2)
    return DependencyHint(
        name=ref.group(1), version=version, ecosystem="conan", file=relative, line=line_of(text, offset),
        dev=dev, resolved=resolved and not version.startswith("["), evidence_text=ref.group(0),
    )


def parse_conanfile_txt(text: str, relative: str) -> list:
    out = []
    dev_manifest = _is_test_manifest(relative)
    sections = list(_CONAN_SECTION_RE.finditer(text))
    for i, section in enumerate(sections):
        kind = section.group(1)
        if kind not in ("requires", *_DEV_SECTIONS):
            continue
        end = sections[i + 1].start() if i + 1 < len(sections) else len(text)
        offset = section.end()
        for raw_line in text[section.end() : end].splitlines(keepends=True):
            line = raw_line.split("#", 1)[0]
            ref = _CONAN_REF_RE.search(line)
            if ref is not None:
                out.append(_conan_hint(ref, text, relative, kind in _DEV_SECTIONS or dev_manifest, offset + ref.start()))
            offset += len(raw_line)
    return out


def parse_conanfile_py(text: str, relative: str) -> list:
    """Requirements from a ``conanfile.py``, read with ``ast`` and never run:
    ``requires = "a/1.0"`` / a tuple or list (class or module level), and
    ``self.requires("x/1.0")`` and the tool/build/test forms. Comments and
    docstrings are not code, so they don't count."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    dev_manifest = _is_test_manifest(relative)
    out = []

    def literal_refs(node: ast.AST) -> list[ast.Constant]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [e for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return []

    def emit(kind: str, constants: list[ast.Constant]) -> None:
        for constant in constants:
            ref = _CONAN_REF_RE.fullmatch(constant.value)
            if ref is not None:
                offset = _offset_of(text, constant.lineno, constant.col_offset)
                out.append(_conan_hint(ref, text, relative, kind in _DEV_SECTIONS or dev_manifest, offset))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in _CONAN_REQUIRE_NAMES:
                emit(node.targets[0].id, literal_refs(node.value))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
            and node.func.attr in _CONAN_REQUIRE_NAMES
            and node.args
        ):
            emit(node.func.attr, literal_refs(node.args[0]))
    out.sort(key=lambda d: d.line or 0)
    return out


def _offset_of(text: str, lineno: int, col: int) -> int:
    offset = 0
    for _ in range(lineno - 1):
        newline = text.find("\n", offset)
        if newline == -1:
            return offset
        offset = newline + 1
    return offset + col


def parse_conan_lock(text: str, relative: str) -> list:
    """Conan 2 (``requires`` / ``build_requires`` lists) and Conan 1.x
    (``graph_lock.nodes``, build-context nodes are ``dev``) lockfiles."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    entries: list[tuple[str, bool]] = []
    for key, dev in (("requires", False), ("build_requires", True), ("python_requires", True)):
        entries.extend((entry, dev) for entry in _list(data.get(key)) if isinstance(entry, str))
    graph = data.get("graph_lock")
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if isinstance(nodes, dict):
        for node in nodes.values():
            if isinstance(node, dict) and isinstance(node.get("ref"), str):
                entries.append((node["ref"], node.get("context") == "build"))
    out = []
    for entry, dev in entries:
        ref = _CONAN_REF_RE.match(entry)
        if ref is not None:
            out.append(_conan_hint(ref, text, relative, dev, max(0, text.find(entry)), resolved=True))
    return out


# ---------- CMake ----------


_CMAKE_SPECIAL_RE = re.compile(r"#\[(=*)\[|#|\"|\[(=*)\[")


def _cmake_masks(text: str) -> tuple[str, str]:
    """``(clean, bare)`` in one linear pass. ``clean``: comments (``#`` and
    ``#[[ ]]``) and bracket arguments (``[[ ]]``, whose content is never a
    command or a dependency) blanked, quoted strings kept for argument
    values. ``bare``: quoted string contents blanked too, so a command inside
    ``message("find_package(x)")`` doesn't count. Unterminated constructs
    run to the end of the file."""
    clean: list[str] = []
    bare: list[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        match = _CMAKE_SPECIAL_RE.search(text, pos)
        if match is None:
            break
        start = match.start()
        clean.append(text[pos:start])
        bare.append(text[pos:start])
        token = match.group(0)
        if token.startswith("#[") or (token.startswith("[") and match.group(2) is not None):
            equals = match.group(1) if token.startswith("#") else match.group(2)
            close = text.find("]" + equals + "]", match.end())
            end = n if close == -1 else close + len(equals) + 2
            blank = _blank(text[start:end])
            clean.append(blank)
            bare.append(blank)
        elif token == "#":
            newline = text.find("\n", start)
            end = n if newline == -1 else newline
            blank = _blank(text[start:end])
            clean.append(blank)
            bare.append(blank)
        else:  # quoted argument
            body = _CMAKE_QUOTED_BODY_RE.match(text, match.end())
            end = body.end() if body else match.end()
            if end < n:
                end += 1  # closing quote
            clean.append(text[start:end])
            closed = end - start >= 2 and text[end - 1] == '"'
            inner_end = end - 1 if closed else end
            bare.append('"' + _blank(text[start + 1 : inner_end]) + ('"' if closed else ""))
        pos = end
    clean.append(text[pos:])
    bare.append(text[pos:])
    return "".join(clean), "".join(bare)


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _paren_pairs(bare: str) -> dict[int, int]:
    """Matching ``)`` for every ``(`` in one pass (strings already blanked)."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for match in _PAREN_RE.finditer(bare):
        if match.group(0) == "(":
            stack.append(match.start())
        elif stack:
            pairs[stack.pop()] = match.start()
    return pairs


def _cmake_args(clean: str, open_paren: int, pairs: dict[int, int]) -> list[str] | None:
    close = pairs.get(open_paren)
    if close is None or close - open_paren > _MAX_ARGS_SPAN:
        return None
    body = clean[open_paren + 1 : close]
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in _CMAKE_TOKEN_RE.finditer(body)]


def _keyword_values(args: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for i, token in enumerate(args[:-1]):
        if token.isupper() and token not in values:
            values[token] = args[i + 1]
    return values


def _ref_issue(name: str, ref: str | None, url: str, relative: str, line: int | None):
    if ref is not None and "${" in ref:
        return None
    if ref is None or ref.lower() in _BRANCH_REFS:
        severity = "medium"
        what = f"branch `{ref}`" if ref else "no GIT_TAG (the default branch)"
    elif _SHA40_RE.match(ref):
        return None
    else:
        severity = "low"
        what = f"`{ref}`, a tag or short SHA"
    return SupplyChainIssue(
        kind="mutable_vcs_dependency", file=relative, line=line, package=name, ecosystem="cmake", severity=severity,
        evidence_text=f"{name}: git dependency on {what}, not a commit SHA; the remote can change what is built: {url}",
    )


def _url_issue(name: str, url: str, values: dict[str, str], relative: str, line: int | None):
    if "${" in url or "URL_HASH" in values or "URL_MD5" in values:
        return None
    branch = _URL_BRANCH_RE.search(url) is not None
    return SupplyChainIssue(
        kind="mutable_vcs_dependency", file=relative, line=line, package=name, ecosystem="cmake", severity="medium",
        evidence_text=f"{name}: archive URL{' of a branch' if branch else ''} downloaded without URL_HASH: {url}",
    )


def _url_version(url: str) -> str:
    if "${" in url:
        return ""
    match = _URL_VERSION_RE.search(url)
    return match.group(1).replace("_", ".") if match else ""


def parse_cmake(text: str, relative: str) -> tuple[list, list]:
    clean, bare = _cmake_masks(text)
    pairs = _paren_pairs(bare)
    deps: list = []
    issues: list = []
    dev_manifest = _is_test_manifest(relative)
    for match in _CMAKE_COMMAND_RE.finditer(bare):
        command = match.group(1).lower()
        args = _cmake_args(clean, match.end() - 1, pairs)
        if not args:
            continue
        line = line_of(text, match.start())
        if command == "find_package":
            dep = _find_package(args, relative, line, dev_manifest)
            if dep is not None:
                deps.append(dep)
            continue
        if command in ("cpmaddpackage", "cpmfindpackage") and len(args) == 1:
            dep, issue = _cpm_shorthand(args[0], relative, line, dev_manifest)
        else:
            dep, issue = _download(command, args, relative, line, dev_manifest)
        if dep is not None:
            deps.append(dep)
        if issue is not None:
            issues.append(issue)
    return deps, issues


def _find_package(args: list[str], relative: str, line: int, dev_manifest: bool):
    name = args[0]
    if "${" in name or name.lower() in _FIND_PACKAGE_TOOLING:
        return None
    version = ""
    if len(args) > 1 and _VERSION_TOKEN_RE.match(args[1]):
        version = ("==" if "EXACT" in args[2:] else ">=") + args[1]
    elif len(args) > 1 and (version_range := _VERSION_RANGE_RE.match(args[1])):
        low, exclusive, high = version_range.groups()
        version = f">={low},{'<' if exclusive else '<='}{high}"
    return DependencyHint(
        name=name, version=version, ecosystem="cmake", file=relative, line=line,
        dev=dev_manifest or name.lower() in _TEST_DEPS, evidence_text=f"find_package({' '.join(args[:4])})",
    )


def _download(command: str, args: list[str], relative: str, line: int, dev_manifest: bool):
    cpm = command in ("cpmaddpackage", "cpmfindpackage")
    values = _keyword_values(args) if cpm else _keyword_values(args[1:])
    name = values.get("NAME") if cpm else args[0]
    if not name or "${" in name:
        return None, None
    repo = values.get("GIT_REPOSITORY") or (
        f"https://github.com/{values['GITHUB_REPOSITORY']}" if "GITHUB_REPOSITORY" in values else None
    )
    url = values.get("URL")
    ref = values.get("GIT_TAG")
    if repo is None and url is None:
        return None, None  # SOURCE_DIR / SVN / local: nothing to pin
    if cpm and ref is None and "VERSION" in values:
        ref = "v" + values["VERSION"]  # CPM's default tag for a VERSION
    dev = dev_manifest or name.lower() in _TEST_DEPS
    if repo is not None:
        version = values.get("VERSION") if cpm and "VERSION" in values else ref
        version = version if version and "${" not in version else ""
        dep = DependencyHint(name=name, version=version, ecosystem="cmake", file=relative, line=line, dev=dev,
                             evidence_text=repo)
        return dep, _ref_issue(name, ref, repo, relative, line)
    assert url is not None
    dep = DependencyHint(name=name, version=_url_version(url), ecosystem="cmake", file=relative, line=line, dev=dev,
                         evidence_text=url)
    return dep, _url_issue(name, url, values, relative, line)


def _cpm_shorthand(spec: str, relative: str, line: int, dev_manifest: bool):
    match = _CPM_SHORTHAND_RE.match(spec)
    if match is None or "${" in spec:
        return None, None
    host, path, version, tag = match.groups()
    base = {"gh": "https://github.com/", "gl": "https://gitlab.com/", "bb": "https://bitbucket.org/"}.get(host or "", "")
    repo = base + path if base else path
    name = path.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    ref = tag or (f"v{version}" if version else None)
    dep = DependencyHint(name=name, version=version or tag or "", ecosystem="cmake", file=relative, line=line,
                         dev=dev_manifest or name.lower() in _TEST_DEPS, evidence_text=repo)
    return dep, _ref_issue(name, ref, repo, relative, line)


__all__ = ["dedupe_dependencies", "is_manifest", "manifest_records", "native_dependencies", "parse_cmake", "parse_conan_lock", "parse_conanfile_py", "parse_conanfile_txt",
           "parse_vcpkg_json"]
