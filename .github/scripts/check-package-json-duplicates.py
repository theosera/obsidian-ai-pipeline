#!/usr/bin/env python3
"""Fail CI when any package.json in the repo contains duplicate keys.

json.load accepts duplicates silently (last-wins), so malformed manifests
can survive review — as happened with the duplicate `"private": true`
that main accumulated during merge history. This checker rejects
duplicates at any nesting level via object_pairs_hook.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def reject_duplicates(pairs):
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


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
                json.load(fh, object_pairs_hook=reject_duplicates)
        except ValueError as exc:
            print(f"::error file={rel}::{exc}")
            failed = True
        else:
            print(f"OK {rel}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
