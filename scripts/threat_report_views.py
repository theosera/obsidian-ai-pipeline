#!/usr/bin/env python3
"""Build Obsidian-readable copies of the weekly threat reports.

usage: threat_report_views.py <raw dir> [--write]

For each YYYY-MM-DD.md.txt in <raw dir>, makes YYYY-MM-DD-view.md next to it.
Without --write it only prints what it would do.

The weekly ingest workflow (.github/workflows/llm-sec-weekly.yml) runs this with
--write after the gate re-check and before the vault commit, so the reading copy
lands in the same commit as the report.

The .md.txt stays the source of truth and is never changed. The ingest route is not
touched: its migration matches only YYYY-MM-DD.md and its rebuild reads only *.md.txt.
A report body is untrusted input, so the copy holds the whole body in one code block
whose fence is longer than any backtick run in the body, and marks that another
plugin would act on are rewritten.
This file lives in the pipeline repo, not in the vault: a file that gets executed
must not sit where the ingest bot can write. Standard library only.
"""
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

SOURCE_NAME = re.compile(r'^(\d{4}-\d{2}-\d{2})\.md\.txt$')
BACKTICK_RUN = re.compile(r'`+')
NEUTRALIZED = (('<%', '< %'),)


@dataclass(frozen=True)
class Outcome:
    name: str
    status: str  # created | updated | unchanged | error
    detail: str = ''


def neutralize(body: str) -> str:
    for mark, harmless in NEUTRALIZED:
        body = body.replace(mark, harmless)
    return body


def fence_for(body: str) -> str:
    longest = max((len(run) for run in BACKTICK_RUN.findall(body)), default=0)
    return '`' * max(3, longest + 1)


def render(date: str, source_text: str) -> str:
    body = neutralize(source_text)
    if not body.endswith('\n'):
        body += '\n'
    fence = fence_for(body)
    return (f'# {date} 週報（読む用）\n\n'
            f'原文は `{date}.md.txt` です。これは読むための写しで、本文の一部の字を替えています。\n\n'
            f'{fence}\n{body}{fence}\n')


def is_regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def write_atomically(target: Path, text: str) -> None:
    # The raw dir is a vault checkout that the ingest bot can write, so a fixed temp
    # name could already be a symlink. mkstemp creates a fresh, randomly named file
    # with O_CREAT | O_EXCL (never follows an existing path), then we replace.
    fd, temp_name = tempfile.mkstemp(dir=target.parent, prefix=f'.{target.name}.', suffix='.tmp')
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            os.fchmod(handle.fileno(), 0o644)
        os.replace(temp, target)
    except BaseException:
        # A failed write must not leave a temp file for the vault commit to pick up.
        temp.unlink(missing_ok=True)
        raise


def build_one(source: Path, date: str, write: bool) -> Outcome:
    target = source.with_name(f'{date}-view.md')
    if not is_regular(source):
        return Outcome(source.name, 'error', 'source is not a regular file')
    if target.is_symlink() or (target.exists() and not target.is_file()):
        return Outcome(source.name, 'error', 'target is not a regular file')
    try:
        source_text = source.read_bytes().decode('utf-8')
    except UnicodeDecodeError:
        return Outcome(source.name, 'error', 'source is not UTF-8')
    if '\x00' in source_text:
        return Outcome(source.name, 'error', 'source holds a NUL')
    view = render(date, source_text)
    existed = target.exists()
    if existed and target.read_text(encoding='utf-8') == view:
        return Outcome(source.name, 'unchanged')
    if write:
        write_atomically(target, view)
    return Outcome(source.name, 'updated' if existed else 'created')


def build_all(raw_dir: Path, write: bool) -> list[Outcome]:
    outcomes = []
    for path in sorted(raw_dir.iterdir()):
        match = SOURCE_NAME.match(path.name)
        if match:
            outcomes.append(build_one(path, match[1], write))
    return outcomes


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != '--write']
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    raw_dir = Path(args[0])
    if raw_dir.is_symlink() or not raw_dir.is_dir():
        print(f'not a real directory: {raw_dir}', file=sys.stderr)
        return 2
    write = '--write' in argv
    outcomes = build_all(raw_dir, write)
    for outcome in outcomes:
        if outcome.status != 'unchanged':
            print(outcome.status, outcome.name, outcome.detail)
    counts = {s: sum(o.status == s for o in outcomes) for s in ('created', 'updated', 'unchanged', 'error')}
    print('written' if write else 'dry run (add --write to write)', counts)
    return 1 if counts['error'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
