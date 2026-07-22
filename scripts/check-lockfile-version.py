#!/usr/bin/env python3
# check-lockfile-version.py — CI gate (DIG-Network/dig_ecosystem#1469).
#
# Fails the build when any LOCAL package's version in Cargo.lock does not equal the version in
# that package's Cargo.toml. This catches the "stale-lock" trap: an author bumps Cargo.toml's
# version but never runs `cargo build`, so Cargo.lock's own-package entry keeps the OLD version.
# Ordinary PR checks silently resync the lock and stay green, but `cargo package/clippy --locked`
# at release/publish time re-resolves, sees a dirty lock, and the release FAILS post-merge.
# Gating it PRE-MERGE turns a red release into a red PR.
#
# The check is driven FROM Cargo.lock: every `[[package]]` entry with no `source` key is a LOCAL
# package — a workspace member OR an implicit path-dependency member — and is subject to `--locked`
# re-resolution. Registry crates (`source = "registry+..."`) and git deps (`source = "git+..."`)
# always carry a source and are ignored. For each local package we locate its Cargo.toml anywhere
# in the tree, resolve `version.workspace = true` inheritance, and compare. A local lock entry with
# no matching manifest FAILS (never silently passes) — a stale lock the gate can't verify is a
# release risk, not a green light (§1.9: a gate that green-lights a stale lock is worse than none).
#
# Zero third-party dependencies: python3.11+ stdlib `tomllib` (Cargo.toml and Cargo.lock are both
# TOML). Exit 0 = every local version matches; exit 1 = drift (with a fix hint).
# Usage: `python3 scripts/check-lockfile-version.py [repo_root]` (default: the script's repo root).

import sys
import tomllib
from pathlib import Path


def load_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def workspace_inherited_version(root):
    """The `[workspace.package].version` a member may inherit via `version.workspace = true`.

    Read from the repo-root manifest (the workspace root in every DIG repo). Falls back to any
    `[workspace.package].version` found in the tree so a non-root workspace layout still resolves.
    """
    try:
        v = load_toml(root / "Cargo.toml").get("workspace", {}).get("package", {}).get("version")
        if isinstance(v, str):
            return v
    except FileNotFoundError:
        pass
    for manifest in root.rglob("Cargo.toml"):
        if "target" in manifest.parts:
            continue
        try:
            v = load_toml(manifest).get("workspace", {}).get("package", {}).get("version")
        except Exception:
            continue
        if isinstance(v, str):
            return v
    return None


def manifest_versions(root):
    """Map package name -> LIST of (resolved version or None, path-relative-to-root) for every
    Cargo.toml in the tree that declares a `[package]`, honoring `version.workspace = true`
    inheritance. A list (not last-write-wins) so a duplicate `[package]` name — a test fixture, an
    examples/ copy, a vendored crate — cannot silently mask the real member: the caller fails closed
    on any name whose manifests disagree on the version (which also makes the result order-independent
    of the filesystem walk)."""
    ws_version = workspace_inherited_version(root)
    result = {}
    for manifest in root.rglob("Cargo.toml"):
        if "target" in manifest.parts:
            continue
        try:
            pkg = load_toml(manifest).get("package")
        except Exception:
            continue
        if not pkg or not pkg.get("name"):
            continue
        version = pkg.get("version")
        if isinstance(version, dict) and version.get("workspace") is True:
            version = ws_version
        elif not isinstance(version, str):
            version = None
        result.setdefault(pkg["name"], []).append((version, manifest.relative_to(root).as_posix()))
    return result


def local_lock_versions(lock_path):
    """Map name -> version for Cargo.lock entries with NO `source` (path/workspace members)."""
    data = load_toml(lock_path)
    local = {}
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if name and "source" not in pkg:  # registry + git deps carry a source; local packages do not
            local[name] = pkg.get("version")
    return local


def main():
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent

    lock_path = root / "Cargo.lock"
    if not lock_path.is_file():
        print(f"WARN: no Cargo.lock at {root} - nothing to check "
              "(a publishable crate SHOULD commit Cargo.lock).")
        return 0

    local = local_lock_versions(lock_path)
    manifests = manifest_versions(root)

    mismatches = []
    checked = []
    for name, lock_version in sorted(local.items()):
        entries = manifests.get(name)
        if not entries:
            mismatches.append(
                f"  {name}: present in Cargo.lock as a local package (version {lock_version}) "
                "but no matching [package] Cargo.toml was found in the tree")
            continue
        paths = ", ".join(rel for (_, rel) in entries)
        versions = {version for (version, _) in entries}
        if None in versions:
            mismatches.append(
                f"  {name} ({paths}): could not resolve a version from Cargo.toml "
                f"(Cargo.lock={lock_version})")
        elif len(versions) > 1:
            # Two+ manifests declare this package name at DIFFERENT versions. We cannot tell which is
            # the real workspace member, so a stray copy could mask a stale one -> fail closed (§1.9).
            found = ", ".join(sorted(v for v in versions if v is not None))
            mismatches.append(
                f"  {name} ({paths}): AMBIGUOUS - multiple Cargo.toml declare this name at "
                f"differing versions [{found}]; cannot verify Cargo.lock={lock_version}")
        else:
            toml_version = next(iter(versions))
            if toml_version != lock_version:
                mismatches.append(
                    f"  {name} ({paths}): Cargo.toml={toml_version} but Cargo.lock={lock_version}")
            else:
                checked.append(f"{name}@{toml_version}")

    if mismatches:
        print("Cargo.lock local-package version does NOT match Cargo.toml:")
        print("\n".join(mismatches))
        print("\nFix: run `cargo build` (or `cargo update -p <name>`) to resync Cargo.lock, "
              "then commit the updated Cargo.lock.")
        return 1

    if not checked:
        print("WARN: Cargo.lock has no local (source-less) packages to check.")
        return 0

    print(f"OK: Cargo.lock matches Cargo.toml for {len(checked)} local package(s): "
          + ", ".join(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())
