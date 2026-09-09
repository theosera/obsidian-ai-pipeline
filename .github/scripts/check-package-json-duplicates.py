#!/usr/bin/env python3
"""Fail CI when a package.json in the repo is malformed or auto-executing.

Two checks, both about manifests that survive review while changing what CI
does:

1. Duplicate keys. json.load accepts duplicates silently (last-wins), so
   malformed manifests can survive review — as happened with the duplicate
   `"private": true` that main accumulated during merge history. Rejected at
   any nesting level via object_pairs_hook.

2. Install-lifecycle scripts in our own manifests. .npmrc deliberately does
   not set `ignore-scripts` (it would break the approved better-sqlite3 native
   build) and only sets `enable-pre-post-scripts=false`, which governs implicit
   pre/post *wrappers* — not the root project's own install lifecycle. Measured
   with pnpm 10.33.0: a root `preinstall`/`postinstall`/`prepare` still runs on
   `pnpm install --frozen-lockfile`, i.e. inside the CI job that holds the vault
   deploy key and the Gmail refresh token. Nothing else in CI reads these keys,
   so they are rejected here.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


# pnpm/npm がインストール時に自動実行するスクリプト名。ここに載るキーは
# `pnpm install` だけで走るので、明示的な `pnpm run <name>` に移すこと。
INSTALL_LIFECYCLE_SCRIPTS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
)


def reject_duplicates(pairs):
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def install_lifecycle_scripts(manifest) -> list[str]:
    """Return the install-lifecycle script names declared by a manifest."""
    if not isinstance(manifest, dict):
        return []
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return []
    return [name for name in INSTALL_LIFECYCLE_SCRIPTS if name in scripts]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    targets = sorted(
        p for p in repo_root.glob("**/package.json")
        if "node_modules" not in p.parts
    )
    if not targets:
        print("No package.json files found.", file=sys.stderr)
        return 1

    failed = False
    for path in targets:
        rel = path.relative_to(repo_root)
        try:
            with path.open() as fh:
                manifest = json.load(fh, object_pairs_hook=reject_duplicates)
        except ValueError as exc:
            print(f"::error file={rel}::{exc}")
            failed = True
            continue
        lifecycle = install_lifecycle_scripts(manifest)
        if lifecycle:
            names = ", ".join(repr(n) for n in lifecycle)
            print(
                f"::error file={rel}::install-lifecycle script(s) {names} run "
                f"automatically on `pnpm install` (inside the CI job holding the "
                f"vault deploy key and Gmail refresh token). Move the logic to an "
                f"explicit `pnpm run` target."
            )
            failed = True
        else:
            print(f"OK {rel}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
