#!/usr/bin/env python3
"""Generate src/generated/ from a ForensicArtifacts checkout.

    tools/gen_catalog.py <path-to-artifacts-checkout> [--out src/generated] [--upstream origin/main]

Reads artifacts/data/*.yaml and writes one Rust module per YAML file, holding one
`pub(crate) const` per definition in upstream order, plus mod.rs with the definitions
sorted by name, the name/alias index, and the commits.

The checkout may carry local commits on top of upstream. Every definition they add or
change is marked as such in the generated code and listed in LOCAL_DEFINITIONS, as the
Apache-2.0 license asks of modified files (see NOTICE). Upstream is the merge base of
HEAD and --upstream.

The output is deterministic: rerunning it on the same commit gives the same bytes
(tools/check_generated.sh checks that). Anything the generator doesn't know how to
map (a new key, source type, attribute or OS) is an error, so an upstream change can
never be dropped silently.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

KB_REPO = "https://github.com/ForensicArtifacts/artifacts"

DEFINITION_KEYS = {"name", "doc", "sources", "supported_os", "urls", "aliases"}
# Keys we read past on purpose.
IGNORED_KEYS = {"labels"}
SOURCE_KEYS = {"type", "attributes", "supported_os"}
SOURCE_ATTRIBUTES = {
    "FILE": {"paths", "separator"},
    "PATH": {"paths", "separator"},
    "REGISTRY_KEY": {"keys"},
    "REGISTRY_VALUE": {"key_value_pairs"},
    "WMI": {"query", "base_object"},
    "COMMAND": {"cmd", "args"},
    "ARTIFACT_GROUP": {"names"},
}
OS = {
    "Windows": "Os::Windows",
    "Linux": "Os::Linux",
    "Darwin": "Os::Darwin",
    "ESXi": "Os::Esxi",
    "Android": "Os::Android",
    "iOS": "Os::Ios",
}
SEPARATORS = {"/": "Separator::Slash", "\\": "Separator::Backslash"}


class GenError(Exception):
    pass


def rust_str(s: str) -> str:
    """A Rust string literal for `s`: raw when it fits on one line, escaped otherwise."""
    if not isinstance(s, str):
        raise GenError(f"expected a string, got {type(s).__name__}: {s!r}")
    if "\n" in s or "\r" in s or any(ord(c) < 0x20 and c != "\t" for c in s):
        out = []
        for c in s:
            if c == "\\":
                out.append("\\\\")
            elif c == '"':
                out.append('\\"')
            elif c == "\n":
                out.append("\\n")
            elif c == "\r":
                out.append("\\r")
            elif c == "\t":
                out.append("\\t")
            elif ord(c) < 0x20:
                out.append(f"\\u{{{ord(c):x}}}")
            else:
                out.append(c)
        return '"' + "".join(out) + '"'
    hashes = 0
    while '"' + "#" * hashes in s:
        hashes += 1
    return "r" + "#" * hashes + '"' + s + '"' + "#" * hashes


def text(s: str) -> str:
    return f"B({rust_str(s)})"


def const_name(name: str) -> str:
    """`WindowsAMCacheHveFile` -> `WINDOWS_AM_CACHE_HVE_FILE`."""
    s = re.sub(r"[^0-9A-Za-z]+", "_", name)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    s = s.strip("_").upper()
    if not s or s[0].isdigit():
        s = "D_" + s
    return s


def str_list(values, what: str) -> list:
    if not isinstance(values, list):
        raise GenError(f"{what}: expected a list, got {values!r}")
    return values


def os_list(values, what: str) -> str:
    items = []
    for os_name in str_list(values, what):
        if os_name not in OS:
            raise GenError(f"{what}: unknown OS {os_name!r}")
        items.append(OS[os_name])
    return "B(&[" + ", ".join(items) + "])"


def text_slice(values, what: str, indent: str) -> str:
    values = str_list(values, what)
    if not values:
        return "B(&[])"
    if len(values) == 1:
        return f"B(&[{text(values[0])}])"
    inner = "".join(f"{indent}    {text(v)},\n" for v in values)
    return f"B(&[\n{inner}{indent}])"


def source_expr(src: dict, where: str, indent: str) -> tuple[str, set]:
    """Rust `ArtifactSource` expression for `src`, and the types it uses."""
    unknown = set(src) - SOURCE_KEYS
    if unknown:
        raise GenError(f"{where}: unknown source keys {sorted(unknown)}")
    kind = src.get("type")
    if kind not in SOURCE_ATTRIBUTES:
        raise GenError(f"{where}: unknown source type {kind!r}")
    attrs = src.get("attributes") or {}
    unknown = set(attrs) - SOURCE_ATTRIBUTES[kind]
    if unknown:
        raise GenError(f"{where}: unknown {kind} attributes {sorted(unknown)}")
    i = indent + "    "
    used = set()
    if kind in ("FILE", "PATH"):
        variant = "File" if kind == "FILE" else "Path"
        sep = attrs.get("separator", "/")
        if sep not in SEPARATORS:
            raise GenError(f"{where}: unknown separator {sep!r}")
        used.add("Separator")
        body = (f"ArtifactSource::{variant} {{\n"
                f"{i}paths: {text_slice(attrs.get('paths', []), where, i)},\n"
                f"{i}separator: {SEPARATORS[sep]},\n"
                f"{indent}}}")
    elif kind == "REGISTRY_KEY":
        body = (f"ArtifactSource::RegistryKey {{\n"
                f"{i}keys: {text_slice(attrs.get('keys', []), where, i)},\n"
                f"{indent}}}")
    elif kind == "REGISTRY_VALUE":
        used.add("RegistryValueRef")
        pairs = str_list(attrs.get("key_value_pairs", []), where)
        lines = []
        for pair in pairs:
            if not isinstance(pair, dict) or set(pair) != {"key", "value"}:
                raise GenError(f"{where}: bad key_value_pair {pair!r}")
            lines.append(f"{i}    RegistryValueRef {{ key: {text(pair['key'])}, value: {text(pair['value'])} }},\n")
        body = (f"ArtifactSource::RegistryValue {{\n"
                f"{i}pairs: B(&[\n{''.join(lines)}{i}]),\n"
                f"{indent}}}")
    elif kind == "WMI":
        base = attrs.get("base_object")
        base = "None" if base is None else f"Some({text(base)})"
        body = (f"ArtifactSource::Wmi {{\n"
                f"{i}query: {text(attrs.get('query', ''))},\n"
                f"{i}base_object: {base},\n"
                f"{indent}}}")
    elif kind == "COMMAND":
        body = (f"ArtifactSource::Command {{\n"
                f"{i}cmd: {text(attrs.get('cmd', ''))},\n"
                f"{i}args: {text_slice(attrs.get('args', []), where, i)},\n"
                f"{indent}}}")
    else:  # ARTIFACT_GROUP
        body = (f"ArtifactSource::Group {{\n"
                f"{i}names: {text_slice(attrs.get('names', []), where, i)},\n"
                f"{indent}}}")
    return body, used


def definition_const(d: dict, const: str, where: str, local: str) -> tuple[str, set]:
    used = set()
    sources = []
    for n, src in enumerate(str_list(d.get("sources", []), where)):
        swhere = f"{where} source {n}"
        expr, u = source_expr(src, swhere, "            ")
        used |= u
        src_os = os_list(src.get("supported_os", []), swhere)
        sources.append("        SourceEntry {\n"
                       f"            source: {expr},\n"
                       f"            supported_os: {src_os},\n"
                       "        },\n")
    body = (f"/// `{d['name']}`\n"
            f"{local}"
            f"pub(crate) const {const}: ArtifactDefinition = ArtifactDefinition {{\n"
            f"    name: {text(d['name'])},\n"
            f"    aliases: {text_slice(d.get('aliases', []), where, '    ')},\n"
            f"    doc: {text(d.get('doc', ''))},\n"
            f"    sources: B(&[\n{''.join(sources)}    ]),\n"
            f"    supported_os: {os_list(d.get('supported_os', []), where)},\n"
            f"    urls: {text_slice(d.get('urls', []), where, '    ')},\n"
            "};\n")
    return body, used


def kb_commit(checkout: Path) -> str:
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(checkout), "status", "--porcelain", "--", "artifacts/data"],
                           check=True, capture_output=True, text=True).stdout.strip()
    if dirty:
        print(f"warning: {checkout}/artifacts/data has local changes; KB_COMMIT will not describe them",
              file=sys.stderr)
    return commit


def git(checkout: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(checkout), *args], capture_output=True, text=True)


def upstream_commit(checkout: Path, upstream: str) -> str:
    """The last upstream commit the checkout has: the merge base of HEAD and `upstream`."""
    base = git(checkout, "merge-base", "HEAD", upstream)
    if base.returncode != 0:
        raise GenError(f"no merge base of HEAD and {upstream!r} in {checkout} "
                       "(pass --upstream with a ref of ForensicArtifacts/artifacts)")
    return base.stdout.strip()


def upstream_definitions(checkout: Path, base: str, path: Path) -> dict:
    """The definitions of `path`'s YAML file at `base`, by name. Empty when it didn't exist."""
    shown = git(checkout, "show", f"{base}:artifacts/data/{path.name}")
    if shown.returncode != 0:
        return {}
    return {d.get("name"): d for d in yaml.safe_load_all(shown.stdout) if d}


def header(commit: str, base: str) -> str:
    source = f"ForensicArtifacts/artifacts @ {commit}"
    if base != commit:
        source = f"ForensicArtifacts/artifacts @ {base} plus local commits up to {commit}"
    return (f"// @generated by tools/gen_catalog.py from {source}.\n"
            "// Do not edit: rerun the generator (see README.md).\n")


def local_notice(change: str, base: str) -> str:
    """The doc lines marking a definition the local commits added or changed."""
    if change == "added":
        return f"///\n/// Added by this project: not in upstream ForensicArtifacts @ {base[:7]}.\n"
    return f"///\n/// Changed by this project from upstream ForensicArtifacts @ {base[:7]}.\n"


def generate(checkout: Path, out: Path, upstream: str) -> None:
    commit = kb_commit(checkout)
    base = upstream_commit(checkout, upstream)
    data = checkout / "artifacts" / "data"
    files = sorted(data.glob("*.yaml"))
    if not files:
        raise GenError(f"no *.yaml under {data}")

    modules = {}      # module name -> (source text, used types, local changes)
    local = []        # (name, "added" | "changed")
    entries = []      # (name, module, const, aliases)
    names = {}
    consts = {}
    for path in files:
        module = re.sub(r"[^0-9a-z_]", "_", path.stem.lower())
        parts, used, changes = [], set(), 0
        with path.open(encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
        upstream_docs = upstream_definitions(checkout, base, path) if base != commit else {}
        for d in docs:
            where = f"{path.name}: {d.get('name', '?')}"
            unknown = set(d) - DEFINITION_KEYS - IGNORED_KEYS
            if unknown:
                raise GenError(f"{where}: unknown keys {sorted(unknown)}")
            name = d.get("name")
            if not isinstance(name, str) or not name:
                raise GenError(f"{path.name}: definition without a name")
            if name in names:
                raise GenError(f"{where}: name also defined in {names[name]}")
            names[name] = path.name
            const = const_name(name)
            if const in consts:
                raise GenError(f"{where}: const {const} clashes with {consts[const]}")
            consts[const] = name
            change = None
            if base != commit and upstream_docs.get(name) != d:
                change = "changed" if name in upstream_docs else "added"
                local.append((name, change))
                changes += 1
            notice = local_notice(change, base) if change else ""
            body, u = definition_const(d, const, where, notice)
            parts.append(body)
            used |= u
            entries.append((name, module, const, list(d.get("aliases", []))))
        modules[module] = (parts, used, changes)

    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.rs"):
        old.unlink()
    for module, (parts, _used, changes) in modules.items():
        body = "\n".join(parts)
        candidates = ["ArtifactDefinition", "ArtifactSource", "Os", "RegistryValueRef",
                      "Separator", "SourceEntry"]
        types = [t for t in candidates if re.search(rf"\b{t}\b", body)]
        modified = ""
        if changes:
            count = "1 definition" if changes == 1 else f"{changes} definitions"
            modified = (f"//!\n//! Modified by this project: {count} added or changed locally, "
                        "marked below.\n")
        text_out = (header(commit, base)
                    + f"//! Definitions from `artifacts/data/{module}.yaml`, in upstream order.\n"
                    + modified + "\n"
                    + f"use forensic_rs::catalog::{{{', '.join(types)}}};\n"
                    + "use std::borrow::Cow::Borrowed as B;\n\n"
                    + body)
        (out / f"{module}.rs").write_text(text_out, encoding="utf-8", newline="\n")

    entries.sort(key=lambda e: e[0])
    position = {e[0]: i for i, e in enumerate(entries)}
    index = []
    for name, _, _, aliases in entries:
        index.append((name, position[name]))
        index.extend((alias, position[name]) for alias in aliases)
    index.sort(key=lambda e: e[0])
    for (a, _), (b, _) in zip(index, index[1:]):
        if a == b:
            raise GenError(f"name or alias used twice: {a}")

    defs = "".join(f"    {module}::{const},\n" for _, module, const, _ in entries)
    idx = "".join(f"    CatalogIndexEntry {{ key: {text(k)}, def: {i} }},\n" for k, i in index)
    mods = "".join(f"mod {m};\n" for m in modules)
    local.sort()
    local_list = "".join(f"    {rust_str(name)},\n" for name, _ in local)
    mod_rs = (header(commit, base)
              + "//! The ForensicArtifacts definitions, one module per upstream YAML file.\n\n"
              + mods + "\n"
              + "use forensic_rs::catalog::{ArtifactDefinition, CatalogIndexEntry};\n"
              + "use std::borrow::Cow::Borrowed as B;\n\n"
              + "/// The upstream repository the definitions come from.\n"
              + f"pub const KB_REPO: &str = {rust_str(KB_REPO)};\n"
              + "/// The commit the definitions were generated from: [`KB_UPSTREAM_COMMIT`], or a local\n"
              + "/// commit on top of it when there are [`LOCAL_DEFINITIONS`].\n"
              + f"pub const KB_COMMIT: &str = {rust_str(commit)};\n"
              + "/// The last upstream commit [`KB_COMMIT`] is based on.\n"
              + f"pub const KB_UPSTREAM_COMMIT: &str = {rust_str(base)};\n"
              + "/// The definitions this project added or changed, not as in [`KB_UPSTREAM_COMMIT`], sorted.\n"
              + f"pub const LOCAL_DEFINITIONS: &[&str] = &[\n{local_list}];\n"
              + "/// How many definitions [`KB_COMMIT`] has.\n"
              + f"pub const DEFINITION_COUNT: usize = {len(entries)};\n\n"
              + "/// Every definition, sorted by name.\n"
              + f"pub(crate) static DEFINITIONS: [ArtifactDefinition; {len(entries)}] = [\n{defs}];\n\n"
              + "/// Every name and alias, sorted, with the position of its definition.\n"
              + f"pub(crate) static INDEX: [CatalogIndexEntry; {len(index)}] = [\n{idx}];\n")
    (out / "mod.rs").write_text(mod_rs, encoding="utf-8", newline="\n")
    print(f"{len(entries)} definitions, {len(index) - len(entries)} aliases, "
          f"{len(modules)} modules from {commit[:7]} "
          f"({len(local)} local on top of {base[:7]}) -> {out}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("checkout", type=Path, help="a ForensicArtifacts/artifacts checkout")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent / "src" / "generated")
    parser.add_argument("--upstream", default="origin/main",
                        help="a ref of upstream ForensicArtifacts/artifacts (default: origin/main)")
    args = parser.parse_args()
    try:
        generate(args.checkout, args.out, args.upstream)
    except GenError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
