# Issue #204: staged secret-file deletions

## Scope

The two staged filename checks in `block-secret-git.cjs` exclude Git-classified
`D` entries only when the proposed commit uses the inspected index. They retain
the existing selected Git/environment/cwd, parser, reader and later checks.
There is no early ALLOW for a deletion. The filename predicate is unchanged.

`git diff --cached --name-only --diff-filter=d -z` keeps additions,
modifications, type changes, and rename/copy destinations. Nonempty results must
be complete NUL-delimited records without empty names; malformed results and
reader exceptions stop explicitly as UNKNOWN in either staged check.

The denial advice distinguishes index-based operations from alternate-tree
selection and never recommends cancelling a verified untracking deletion.

## Pathspec and alternate-tree boundary

An index deletion is not proof of a deletion in `git commit -- subdirectory`:
Git can take a retained local secret from the working tree. Literal directory
pathspecs are particularly important because `ls-files` no longer lists the
untracked secret. Both checks therefore keep the original unfiltered filename
inspection when a pathspec is present.

`--only`, `-o` (including bundles and accepted long abbreviations), and
`--fixup=reword:<commit>` can also select a tree other than the current index
without a pathspec. `parseCommitArgs().only` records these selections; an
unresolved fixup value is conservatively included. A later negation does not
clear this conservative marker. These forms keep the unfiltered inspection.
Option values that merely contain `--only` or `-o` remain DATA.

This change does not introduce a general pathspec prohibition or claim to prove
every proposed tree. Existing refusal of unsupported pathspecs, automatic
staging, unknown context and active uninspected readers remains intact.

## Standalone acceptance block

From the repository root, with the complete patch applied:

```bash
set -e
node --test .claude/hooks/tests/staged-secret-deletions.test.cjs
node .claude/hooks/tests/staged-secret-deletions.test.cjs --reverse
```

Acceptance requires 45/45 normal tests and 2/2 reverse tests, with zero failures,
skips, cancellations or malformed Hook wires. The test fails if a trusted Git
with actual `--no-lazy-fetch` support and the fsmonitor version floor is absent.
No dependencies beyond Node.js and Git are required.

| Cases | Required observation |
| --- | --- |
| D01 | Separate `git rm --cached` followed by ordinary commit: both staged reads and all three direct Hook processes allow; a native dummy commit omits the path, leaves the local file, and retains the earlier-history control. |
| D02-D04 | Ordinary deletion, unusual NUL-delimited names and a public addition remain allowed. |
| N, M, NUL | Secret additions, modifications, rename/copy destinations, type changes, re-addition and mixed deletion/addition or deletion/modification remain FORBIDDEN. Non-deletions are also tested directly at the second check. |
| P, PDIR, PONLY, PDATA | Secret pathspecs, directories and alternate-tree selections stay refused; option-looking message DATA does not select an alternate tree. Directory and alternate-tree cases reach the second check through a clearly identified first-read seam. |
| U | Absent repository, corrupt index and a later uninspected fsmonitor reader remain UNKNOWN. |
| F | Timeout/error injection and malformed results at each of the two reads produce explicit UNKNOWN, with the intended read reached. |
| R1/R2 | Removing only one deletion filter in a disposable copy restores the corresponding staged filename FORBIDDEN; ordinary deletion and secret-addition controls stay unchanged. A crash or unrelated denial cannot pass. |

To bind the same tests to an unchanged source snapshot:

```bash
ISSUE204_HOOKS_DIR=/absolute/baseline/.claude/hooks \
  node --test .claude/hooks/tests/staged-secret-deletions.test.cjs
```

`ISSUE204_EVIDENCE=/absolute/output.json` optionally records exact proposed
commands, stdin, cwd, project/environment, source hashes, raw Hook wires,
native Git commands, and injected/reverse observations. Only owned DUMMY data
is used; no proposed command is evaluated as shell code. Native Git fixture
creation and the positive deletion commit are separate recorded actions.

The existing CI component-test discovery includes the new `.test.cjs` file.
The reverse invocation remains an explicit acceptance step.

## Evidence limits

Direct Hook processes are not actual Claude Code dispatch. Native dummy Git
confirms the resulting tree, not the real host's PreToolUse routing. Injected
ETIMEDOUT/EIO proves exception handling, not a wall-clock bound on the current
Git subprocess calls (the separate Issue #202 concern). An outer Hook crash or
host timeout is not recorded as UNKNOWN by this test harness.

This block does not certify complete repository CI, all 8,696 standalone guard
bank inputs, a different Git/OS profile, or a merge. Removing a file from the
new tree does not remove it from old history or complete secret remediation.

## References

- [Issue #204](https://github.com/theosera/obsidian-ai-pipeline/issues/204)
- [Git diff status filters and NUL output](https://git-scm.com/docs/git-diff)
- [Git commit pathspec, only and reword-fixup behavior](https://git-scm.com/docs/git-commit)
