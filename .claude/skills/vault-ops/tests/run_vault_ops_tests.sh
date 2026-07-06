#!/usr/bin/env bash
# run_vault_ops_tests.sh — deterministic acceptance tests for the vault-ops
# kit (pre-push hook / safe-vault-push-perm.sh / install-vault-ops.sh).
#
# Each case builds a fresh sandbox under mktemp -d: a bare `origin.git` plus
# two clones — `ci-clone` (simulates the weekly ingest CI / any other writer)
# and `mac-clone` (the human's vault clone the wrapper operates on). Local
# file transport only: no network, no pnpm/node, safe to run anywhere
# (wired into .github/workflows/ci.yml; also run on the Mac via
# `install-vault-ops.sh --self-test` — must therefore stay bash 3.2
# compatible: no mapfile / assoc arrays / ${var,,}).
#
# Output style follows the scan-threat-report python test runners:
# one PASS/FAIL line per case, summary line, non-zero exit on any failure.

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd -P)"
SKILL_DIR="$(cd "${TESTS_DIR}/.." && pwd -P)"
WRAPPER="${SKILL_DIR}/scripts/safe-vault-push-perm.sh"
HOOK_TPL="${SKILL_DIR}/scripts/vault-pre-push.hook"
INSTALLER="${SKILL_DIR}/scripts/install-vault-ops.sh"

PASS=0
FAIL=0
SANDBOXES=""
ZERO_SHA="0000000000000000000000000000000000000000"

cleanup() {
  # shellcheck disable=SC2086  # word-splitting the sandbox list is intended
  [ -n "${SANDBOXES}" ] && rm -rf ${SANDBOXES} || true
}
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

# Isolate from any global/system git config (identity, hooksPath, gpg...).
# GIT_CONFIG_GLOBAL/SYSTEM are honored by git >= 2.32; on older git the
# per-repo config set below still covers everything the tests rely on.
export GIT_CONFIG_NOSYSTEM=1

repo_cfg() {
  git -C "$1" config user.name "vault-ops-test"
  git -C "$1" config user.email "vault-ops-test@example.invalid"
  git -C "$1" config commit.gpgsign false
}

# new_sandbox: sets $SB, creates bare origin (branch: main) + ci/mac clones
# with one shared root commit already pushed and checked out everywhere.
new_sandbox() {
  SB="$(mktemp -d "${TMPDIR:-/tmp}/vault-ops-test.XXXXXX")"
  SANDBOXES="${SANDBOXES} ${SB}"
  export GIT_CONFIG_GLOBAL="${SB}/gitconfig-global"
  : > "${GIT_CONFIG_GLOBAL}"
  git init -q --bare "${SB}/origin.git"
  git -C "${SB}/origin.git" symbolic-ref HEAD refs/heads/main
  git clone -q "${SB}/origin.git" "${SB}/ci-clone" 2>/dev/null
  repo_cfg "${SB}/ci-clone"
  mkdir -p "${SB}/ci-clone/notes"
  printf 'base\n' > "${SB}/ci-clone/notes/base.md"
  git -C "${SB}/ci-clone" checkout -qB main
  git -C "${SB}/ci-clone" add notes/base.md
  git -C "${SB}/ci-clone" commit -qm "init"
  git -C "${SB}/ci-clone" push -q origin main
  git clone -q "${SB}/origin.git" "${SB}/mac-clone"
  repo_cfg "${SB}/mac-clone"
  git -C "${SB}/mac-clone" checkout -qB main origin/main
  mkdir -p "${SB}/backups"
}

install_hook() {
  mkdir -p "${SB}/mac-clone/.githooks"
  cp "${HOOK_TPL}" "${SB}/mac-clone/.githooks/pre-push"
  chmod +x "${SB}/mac-clone/.githooks/pre-push"
  git -C "${SB}/mac-clone" config core.hooksPath .githooks
}

ci_commit_push() { # <relpath> <content> [message]
  mkdir -p "${SB}/ci-clone/$(dirname "$1")"
  printf '%s\n' "$2" > "${SB}/ci-clone/$1"
  git -C "${SB}/ci-clone" add -f -- "$1"
  git -C "${SB}/ci-clone" commit -qm "${3:-ci: update $1}"
  git -C "${SB}/ci-clone" push -q origin main
}

origin_main_sha() { git -C "${SB}/origin.git" rev-parse refs/heads/main; }

origin_has_path() { # <relpath> -> exit 0 if present in origin main tree
  git -C "${SB}/origin.git" ls-tree -r --name-only refs/heads/main | grep -qxF "$1"
}

# run_wrapper: captures combined output in $out and exit code in $rc
run_wrapper() {
  set +e
  out="$(PERM_NOTE_PATH="${SB}/mac-clone" VAULT_OPS_BACKUP_DIR="${SB}/backups" \
         bash "${WRAPPER}" 2>&1)"
  rc=$?
  set -e
}

# run_mac: run a git command in mac-clone, capturing output/exit code
run_mac() {
  set +e
  out="$(git -C "${SB}/mac-clone" "$@" 2>&1)"
  rc=$?
  set -e
}

# ---------------------------------------------------------------------------
# H: pre-push hook
# ---------------------------------------------------------------------------

t_h1_ff_push_allowed() {
  new_sandbox; install_hook
  printf 'note\n' > "${SB}/mac-clone/notes/h1.md"
  git -C "${SB}/mac-clone" add notes/h1.md
  git -C "${SB}/mac-clone" commit -qm "h1"
  run_mac push origin main
  if [ "${rc}" -eq 0 ] && origin_has_path "notes/h1.md"; then
    pass "H-1 hook allows fast-forward push"
  else
    fail "H-1" "rc=${rc} out=${out}"
  fi
}

t_h2_nonff_rejected() {
  new_sandbox; install_hook
  ci_commit_push "notes/ci.md" "ci"
  printf 'local\n' > "${SB}/mac-clone/notes/h2.md"
  git -C "${SB}/mac-clone" add notes/h2.md
  git -C "${SB}/mac-clone" commit -qm "h2"
  run_mac push origin main
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "vault-push-perm"; then
    pass "H-2 hook rejects non-ff push with guidance"
  else
    fail "H-2" "rc=${rc} out=${out}"
  fi
}

t_h3_force_push_rejected() {
  new_sandbox; install_hook
  ci_commit_push "notes/ci.md" "ci"
  ci_sha="$(origin_main_sha)"
  printf 'local\n' > "${SB}/mac-clone/notes/h3.md"
  git -C "${SB}/mac-clone" add notes/h3.md
  git -C "${SB}/mac-clone" commit -qm "h3"
  run_mac push --force origin main
  if [ "${rc}" -ne 0 ] && [ "$(origin_main_sha)" = "${ci_sha}" ]; then
    pass "H-3 hook rejects force push (CI commits preserved)"
  else
    fail "H-3" "rc=${rc} origin_moved=$([ "$(origin_main_sha)" != "${ci_sha}" ] && echo yes || echo no)"
  fi
}

t_h4_feature_to_main_rejected() {
  new_sandbox; install_hook
  ci_commit_push "notes/ci.md" "ci"
  git -C "${SB}/mac-clone" checkout -qb feat
  printf 'feat\n' > "${SB}/mac-clone/notes/h4.md"
  git -C "${SB}/mac-clone" add notes/h4.md
  git -C "${SB}/mac-clone" commit -qm "h4"
  run_mac push origin feat:main
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "push 拒否"; then
    pass "H-4 hook keys on remote ref (feature:main rejected)"
  else
    fail "H-4" "rc=${rc} out=${out}"
  fi
}

t_h5_delete_skipped() {
  new_sandbox; install_hook
  head_sha="$(git -C "${SB}/mac-clone" rev-parse HEAD)"
  set +e
  out="$(cd "${SB}/mac-clone" && printf '(delete) %s refs/heads/main %s\n' "${ZERO_SHA}" "${head_sha}" \
        | ./.githooks/pre-push origin "${SB}/origin.git" 2>&1)"
  rc=$?
  set -e
  if [ "${rc}" -eq 0 ]; then
    pass "H-5 hook skips branch deletion (all-zero local sha)"
  else
    fail "H-5" "rc=${rc} out=${out}"
  fi
}

t_h6_tag_push_skipped() {
  new_sandbox; install_hook
  ci_commit_push "notes/ci.md" "ci"   # origin/main ahead: proves tags bypass the guard
  git -C "${SB}/mac-clone" tag v1
  run_mac push origin v1
  if [ "${rc}" -eq 0 ]; then
    pass "H-6 hook skips tag push even when origin/main is ahead"
  else
    fail "H-6" "rc=${rc} out=${out}"
  fi
}

t_h7_new_branch_allowed() {
  new_sandbox; install_hook
  head_sha="$(git -C "${SB}/mac-clone" rev-parse HEAD)"
  # Remote ref does not exist yet: git passes an all-zero remote sha.
  set +e
  out="$(cd "${SB}/mac-clone" && printf 'refs/heads/main %s refs/heads/main %s\n' "${head_sha}" "${ZERO_SHA}" \
        | ./.githooks/pre-push origin "${SB}/origin.git" 2>&1)"
  rc=$?
  set -e
  if [ "${rc}" -eq 0 ]; then
    pass "H-7 hook allows first push of the branch (all-zero remote sha)"
  else
    fail "H-7" "rc=${rc} out=${out}"
  fi
}

t_h8_remote_object_absent_rejected() {
  # regression for the production failure: a concurrent writer advanced origin,
  # the local clone never fetched it, and the old in-hook `git fetch` failed
  # open -> the non-ff push slipped through to the server. With git's own
  # remote sha the object is absent locally, `merge-base --is-ancestor` errors,
  # and the hook fails CLOSED (reject) — which is what must happen.
  new_sandbox; install_hook
  ci_commit_push "notes/ci.md" "ci"            # origin advances; mac never fetches
  remote_sha="$(origin_main_sha)"
  printf 'local\n' > "${SB}/mac-clone/notes/h8.md"
  git -C "${SB}/mac-clone" add notes/h8.md
  git -C "${SB}/mac-clone" commit -qm "h8"      # mac diverges from origin
  local_sha="$(git -C "${SB}/mac-clone" rev-parse HEAD)"
  set +e
  out="$(cd "${SB}/mac-clone" && printf 'refs/heads/main %s refs/heads/main %s\n' "${local_sha}" "${remote_sha}" \
        | ./.githooks/pre-push origin "${SB}/origin.git" 2>&1)"
  rc=$?
  set -e
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "push 拒否"; then
    pass "H-8 rejects when remote sha is unknown locally (fail-closed regression)"
  else
    fail "H-8" "rc=${rc} out=${out}"
  fi
}

# ---------------------------------------------------------------------------
# W: safe-vault-push-perm.sh wrapper
# ---------------------------------------------------------------------------

t_w1_e2e_happy_path() {
  new_sandbox
  printf 'new note\n' > "${SB}/mac-clone/notes/w1.md"
  run_wrapper
  if [ "${rc}" -eq 0 ] && origin_has_path "notes/w1.md" \
     && git -C "${SB}/origin.git" log -1 --format=%s refs/heads/main | grep -q "^vault: update "; then
    pass "W-1 wrapper end-to-end (stage/commit/push a new note)"
  else
    fail "W-1" "rc=${rc} out=${out}"
  fi
}

t_w2_json_quarantine() {
  new_sandbox
  ci_commit_push "10_Threat_Reports/.threat_reports.json" "ci-version"
  mkdir -p "${SB}/mac-clone/10_Threat_Reports"
  printf 'local-version\n' > "${SB}/mac-clone/10_Threat_Reports/.threat_reports.json"
  run_wrapper
  backup_file="$(find "${SB}/backups" -name '*threat_reports*' -type f 2>/dev/null | head -1 || true)"
  worktree_content="$(cat "${SB}/mac-clone/10_Threat_Reports/.threat_reports.json")"
  if [ "${rc}" -eq 0 ] && [ -n "${backup_file}" ] \
     && grep -qx "local-version" "${backup_file}" \
     && [ "${worktree_content}" = "ci-version" ]; then
    pass "W-2 untracked .threat_reports.json quarantined outside repo (CI wins)"
  else
    fail "W-2" "rc=${rc} backup=${backup_file:-none} worktree=${worktree_content} out=${out}"
  fi
}

t_w2b_no_quarantine_when_remote_untracked() {
  new_sandbox
  mkdir -p "${SB}/mac-clone/10_Threat_Reports"
  printf 'local-only\n' > "${SB}/mac-clone/10_Threat_Reports/.threat_reports.json"
  run_wrapper
  backup_count="$(find "${SB}/backups" -type f 2>/dev/null | wc -l | tr -d ' ')"
  if [ "${rc}" -eq 0 ] && [ "${backup_count}" -eq 0 ] \
     && grep -qx "local-only" "${SB}/mac-clone/10_Threat_Reports/.threat_reports.json"; then
    pass "W-2b local-only json is left alone (no pointless quarantine)"
  else
    fail "W-2b" "rc=${rc} backups=${backup_count} out=${out}"
  fi
}

t_w3_auto_rebase() {
  new_sandbox
  printf 'mine\n' > "${SB}/mac-clone/notes/w3-local.md"
  git -C "${SB}/mac-clone" add notes/w3-local.md
  git -C "${SB}/mac-clone" commit -qm "local note"
  ci_commit_push "notes/w3-ci.md" "ci"
  run_wrapper
  merges="$(git -C "${SB}/origin.git" rev-list --merges refs/heads/main | wc -l | tr -d ' ')"
  if [ "${rc}" -eq 0 ] && origin_has_path "notes/w3-local.md" \
     && origin_has_path "notes/w3-ci.md" && [ "${merges}" -eq 0 ]; then
    pass "W-3 wrapper auto-rebases past a CI push (linear history)"
  else
    fail "W-3" "rc=${rc} merges=${merges} out=${out}"
  fi
}

t_w4_secret_gate_blocks() {
  new_sandbox
  before_sha="$(origin_main_sha)"
  printf 'API_KEY=sekrit\n' > "${SB}/mac-clone/.env"
  printf 'note\n' > "${SB}/mac-clone/notes/w4.md"
  run_wrapper
  staged="$(git -C "${SB}/mac-clone" diff --cached --name-only)"
  if [ "${rc}" -ne 0 ] \
     && printf '%s' "${out}" | grep -q "secret-looking" \
     && printf '%s' "${out}" | grep -q "CLAUDE.md" \
     && ! printf '%s\n' "${staged}" | grep -qx ".env" \
     && [ "$(origin_main_sha)" = "${before_sha}" ]; then
    pass "W-4 staged secret gate hard-stops (.env unstaged, nothing pushed)"
  else
    fail "W-4" "rc=${rc} staged=${staged} out=${out}"
  fi
}

t_w4b_env_example_passes() {
  new_sandbox
  printf 'API_KEY=\n' > "${SB}/mac-clone/.env.example"
  run_wrapper
  if [ "${rc}" -eq 0 ] && origin_has_path ".env.example"; then
    pass "W-4b .env.example passes the gate (allowlist)"
  else
    fail "W-4b" "rc=${rc} out=${out}"
  fi
}

t_w5_ref_corruption_stops() {
  new_sandbox
  before_sha="$(origin_main_sha)"
  cp "${SB}/mac-clone/.git/refs/heads/main" "${SB}/mac-clone/.git/refs/heads/main 2"
  printf 'note\n' > "${SB}/mac-clone/notes/w5.md"
  run_wrapper
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "iCloud" \
     && [ "$(origin_main_sha)" = "${before_sha}" ]; then
    pass "W-5 iCloud ref corruption detected: stop without touching anything"
  else
    fail "W-5" "rc=${rc} out=${out}"
  fi
}

t_w5b_icloud_placeholder_stops() {
  new_sandbox
  touch "${SB}/mac-clone/.git/objects/evicted-pack.icloud"
  run_wrapper
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "iCloud"; then
    pass "W-5b .icloud placeholder under .git detected: stop"
  else
    fail "W-5b" "rc=${rc} out=${out}"
  fi
}

t_w6_autostash_conflict_stops() {
  new_sandbox
  ci_commit_push "notes/base.md" "ci-edit"
  printf 'dirty-local-edit\n' > "${SB}/mac-clone/notes/base.md"   # uncommitted
  run_wrapper
  pushed_base="$(git -C "${SB}/origin.git" show refs/heads/main:notes/base.md)"
  if [ "${rc}" -ne 0 ] && [ "${pushed_base}" = "ci-edit" ] \
     && ! printf '%s' "${pushed_base}" | grep -q "<<<<<<<"; then
    pass "W-6 autostash conflict stops before commit (no marker/loss pushed)"
  else
    fail "W-6" "rc=${rc} pushed_base=${pushed_base} out=${out}"
  fi
}

t_w7_rebase_conflict_aborts() {
  new_sandbox
  printf 'local-edit\n' > "${SB}/mac-clone/notes/base.md"
  git -C "${SB}/mac-clone" add notes/base.md
  git -C "${SB}/mac-clone" commit -qm "local edit"
  local_sha="$(git -C "${SB}/mac-clone" rev-parse HEAD)"
  ci_commit_push "notes/base.md" "ci-edit"
  run_wrapper
  in_rebase=0
  [ -d "$(git -C "${SB}/mac-clone" rev-parse --git-path rebase-merge)" ] && in_rebase=1
  [ -d "$(git -C "${SB}/mac-clone" rev-parse --git-path rebase-apply)" ] && in_rebase=1
  if [ "${rc}" -ne 0 ] && [ "${in_rebase}" -eq 0 ] \
     && [ "$(git -C "${SB}/mac-clone" rev-parse HEAD)" = "${local_sha}" ] \
     && grep -qx "local-edit" "${SB}/mac-clone/notes/base.md"; then
    pass "W-7 rebase conflict: aborted, work tree restored, loud stop"
  else
    fail "W-7" "rc=${rc} in_rebase=${in_rebase} out=${out}"
  fi
}

t_w9_inworktree_backup_dir_rejected() {
  # regression: PR #117 CodeRabbit — a VAULT_OPS_BACKUP_DIR override pointing
  # into the vault must be rejected before the mv (else `git add -A` could
  # commit the backup itself).
  new_sandbox
  ci_commit_push "10_Threat_Reports/.threat_reports.json" "ci-version"
  mkdir -p "${SB}/mac-clone/10_Threat_Reports"
  printf 'local-version\n' > "${SB}/mac-clone/10_Threat_Reports/.threat_reports.json"
  before_sha="$(origin_main_sha)"
  set +e
  out="$(PERM_NOTE_PATH="${SB}/mac-clone" VAULT_OPS_BACKUP_DIR="${SB}/mac-clone/backups-inside" \
         bash "${WRAPPER}" 2>&1)"
  rc=$?
  set -e
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "worktree の外" \
     && grep -qx "local-version" "${SB}/mac-clone/10_Threat_Reports/.threat_reports.json" \
     && [ "$(origin_main_sha)" = "${before_sha}" ]; then
    pass "W-9 in-worktree VAULT_OPS_BACKUP_DIR rejected before quarantine"
  else
    fail "W-9" "rc=${rc} out=${out}"
  fi
}

t_w8_quarantine_dir_never_pushed() {
  new_sandbox
  mkdir -p "${SB}/mac-clone/10_Threat_Reports/_quarantine"
  printf 'untrusted body\n' > "${SB}/mac-clone/10_Threat_Reports/_quarantine/evil.md"
  printf 'note\n' > "${SB}/mac-clone/notes/w8.md"
  run_wrapper
  if [ "${rc}" -eq 0 ] && origin_has_path "notes/w8.md" \
     && ! git -C "${SB}/origin.git" ls-tree -r --name-only refs/heads/main | grep -q "_quarantine"; then
    pass "W-8 *_quarantine* is excluded from staging and never pushed"
  else
    fail "W-8" "rc=${rc} out=${out}"
  fi
}

# ---------------------------------------------------------------------------
# I: install-vault-ops.sh
# ---------------------------------------------------------------------------

run_installer() { # extra flags...
  set +e
  out="$(HOME="${SB}/home" ZDOTDIR= PERM_NOTE_PATH= \
         bash "${INSTALLER}" --perm-note-path "${SB}/mac-clone" "$@" 2>&1)"
  rc=$?
  set -e
}

t_i1_first_install() {
  new_sandbox
  mkdir -p "${SB}/home"
  # decoy: pre-staged unrelated change must NOT be swept into the hook commit
  printf 'decoy\n' > "${SB}/mac-clone/decoy.md"
  git -C "${SB}/mac-clone" add decoy.md
  run_installer
  link_target="$(readlink "${SB}/home/.claude/bin/safe-vault-push-perm.sh" || true)"
  hook_commit_files="$(git -C "${SB}/mac-clone" show --name-only --format= HEAD)"
  hookspath="$(git -C "${SB}/mac-clone" config core.hooksPath)"
  if [ "${rc}" -eq 0 ] && [ "${link_target}" = "${WRAPPER}" ] \
     && [ -x "${SB}/mac-clone/.githooks/pre-push" ] \
     && [ "${hookspath}" = ".githooks" ] \
     && [ "${hook_commit_files}" = ".githooks/pre-push" ] \
     && [ ! -f "${SB}/home/.zshrc" ]; then
    pass "I-1 first install (symlink, hook committed alone, zshrc untouched)"
  else
    fail "I-1" "rc=${rc} link=${link_target} commit_files=${hook_commit_files} out=${out}"
  fi
}

t_i2_idempotent_and_zshrc() {
  new_sandbox
  mkdir -p "${SB}/home"
  printf "alias vault-push-perm='old-unsafe'\n" > "${SB}/home/.zshrc"
  run_installer --write-zshrc
  run_installer --write-zshrc
  hook_commits="$(git -C "${SB}/mac-clone" log --oneline -- .githooks/pre-push | wc -l | tr -d ' ')"
  blocks="$(grep -c '^# >>> vault-ops managed >>>$' "${SB}/home/.zshrc")"
  superseded="$(grep -c '^# vault-ops superseded: ' "${SB}/home/.zshrc")"
  backups="$(find "${SB}/home" -name '.zshrc.vault-ops.bak.*' | wc -l | tr -d ' ')"
  if [ "${rc}" -eq 0 ] && [ "${hook_commits}" -eq 1 ] && [ "${blocks}" -eq 1 ] \
     && [ "${superseded}" -eq 1 ] && [ "${backups}" -ge 1 ] \
     && grep -q "PERM_NOTE_PATH=" "${SB}/home/.zshrc"; then
    pass "I-2 idempotent re-run (1 hook commit, 1 managed block, old alias kept commented)"
  else
    fail "I-2" "rc=${rc} hook_commits=${hook_commits} blocks=${blocks} superseded=${superseded} out=${out}"
  fi
}

t_i3_copy_mode() {
  new_sandbox
  mkdir -p "${SB}/home"
  run_installer --copy
  dst="${SB}/home/.claude/bin/safe-vault-push-perm.sh"
  if [ "${rc}" -eq 0 ] && [ -f "${dst}" ] && [ ! -L "${dst}" ] && [ -x "${dst}" ]; then
    pass "I-3 --copy installs an independent executable copy"
  else
    fail "I-3" "rc=${rc} out=${out}"
  fi
}

t_i4_ignored_dotfiles_vault() {
  # regression: PR #117 Codex P2 — Obsidian-style `.*` gitignore hid the
  # untracked .githooks/pre-push from `git status --porcelain`, so the
  # installer skipped the initial commit and the hook never reached other
  # clones. The installer must force-add it (same rationale as the CI's
  # `git add -f` for .threat_reports.json).
  new_sandbox
  mkdir -p "${SB}/home"
  printf '.*\n' > "${SB}/mac-clone/.gitignore"
  git -C "${SB}/mac-clone" add -f .gitignore
  git -C "${SB}/mac-clone" commit -qm "ignore all dotfiles"
  run_installer
  if [ "${rc}" -eq 0 ] \
     && git -C "${SB}/mac-clone" ls-files --error-unmatch -- .githooks/pre-push >/dev/null 2>&1 \
     && [ "$(git -C "${SB}/mac-clone" show --name-only --format= HEAD)" = ".githooks/pre-push" ]; then
    pass "I-4 hook committed even in a dotfile-ignoring vault (add -f)"
  else
    fail "I-4" "rc=${rc} out=${out}"
  fi
}

t_i5_quoted_path_zshrc_function() {
  # regression: PR #117 CodeRabbit — the generated zshrc entry must keep a
  # path containing quotes/spaces literal. Round-trip: install into a vault
  # named with a single quote, eval the generated function with a stub
  # wrapper, and check PERM_NOTE_PATH arrives byte-identical.
  new_sandbox
  mkdir -p "${SB}/home"
  qvault="${SB}/vault's dir"
  git clone -q "${SB}/origin.git" "${qvault}"
  repo_cfg "${qvault}"
  git -C "${qvault}" checkout -qB main origin/main
  set +e
  out="$(HOME="${SB}/home" ZDOTDIR= PERM_NOTE_PATH= \
         bash "${INSTALLER}" --perm-note-path "${qvault}" --write-zshrc 2>&1)"
  rc=$?
  set -e
  func_line="$(grep '^vault-push-perm()' "${SB}/home/.zshrc" || true)"
  rm -f "${SB}/home/.claude/bin/safe-vault-push-perm.sh"
  printf '#!/usr/bin/env bash\nprintf "%%s" "${PERM_NOTE_PATH}"\n' \
    > "${SB}/home/.claude/bin/safe-vault-push-perm.sh"
  chmod +x "${SB}/home/.claude/bin/safe-vault-push-perm.sh"
  received="$(HOME="${SB}/home" bash -c "${func_line}; vault-push-perm" 2>/dev/null || true)"
  if [ "${rc}" -eq 0 ] && [ -n "${func_line}" ] && [ "${received}" = "${qvault}" ]; then
    pass "I-5 quoted/space path survives zshrc round-trip (shell-escaped function)"
  else
    fail "I-5" "rc=${rc} received=${received} expected=${qvault} out=${out}"
  fi
}

# ---------------------------------------------------------------------------

main() {
  t_h1_ff_push_allowed
  t_h2_nonff_rejected
  t_h3_force_push_rejected
  t_h4_feature_to_main_rejected
  t_h5_delete_skipped
  t_h6_tag_push_skipped
  t_h7_new_branch_allowed
  t_h8_remote_object_absent_rejected
  t_w1_e2e_happy_path
  t_w2_json_quarantine
  t_w2b_no_quarantine_when_remote_untracked
  t_w3_auto_rebase
  t_w4_secret_gate_blocks
  t_w4b_env_example_passes
  t_w5_ref_corruption_stops
  t_w5b_icloud_placeholder_stops
  t_w6_autostash_conflict_stops
  t_w7_rebase_conflict_aborts
  t_w8_quarantine_dir_never_pushed
  t_w9_inworktree_backup_dir_rejected
  t_i1_first_install
  t_i2_idempotent_and_zshrc
  t_i3_copy_mode
  t_i4_ignored_dotfiles_vault
  t_i5_quoted_path_zshrc_function

  printf '%s\n' "----------------------------------------"
  printf 'vault-ops tests: %d passed, %d failed\n' "${PASS}" "${FAIL}"
  [ "${FAIL}" -eq 0 ]
}

main
