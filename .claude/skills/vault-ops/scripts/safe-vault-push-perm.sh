#!/usr/bin/env bash
# safe-vault-push-perm.sh — safe manual push for the dual-writer vault repo.
#
# Replaces the bare `vault-push-perm` zsh alias (which had no pull and lost
# races against the weekly ingest CI). Shipped in obsidian-ai-pipeline under
# .claude/skills/vault-ops/scripts/ and symlinked into ~/.claude/bin by
# install-vault-ops.sh. The vault location is injected via $PERM_NOTE_PATH
# (or $1); no machine-specific or vault-identifying path is hardcoded here.
#
# Flow (each stop condition is a deliberate escalation boundary; everything
# else self-heals without asking the user anything):
#   1. resolve vault path ($1 > $PERM_NOTE_PATH > cwd) and preflight
#   2. detect iCloud-induced .git corruption -> stop (ref surgery is a human
#      task; the canonical recovery procedure lives in the vault management
#      note "iCloud による git 破損")
#   3. fetch (offline -> still stage/gate/commit locally, try one push, stop
#      with guidance so nothing is lost)
#   4. quarantine an untracked <TR_DIR>/.threat_reports.json only when the
#      remote already tracks it (CI version wins; backup goes OUTSIDE the
#      work tree so `git add -A` can never commit the backup itself)
#   5. rebase --autostash onto FETCH_HEAD (conflict -> abort & stop; an
#      autostash left behind in the stash -> stop before committing, so a
#      half-applied work tree is never pushed)
#   6. stage everything EXCEPT *_quarantine* (untrusted report bodies must
#      never enter git history), then run the staged secret gate — the only
#      mandatory hard stop = the security boundary
#   7. commit (skip when clean) and push; on failure fetch+rebase and retry
#      with bounded backoff (same strategy as the ingest CI)
#
# Compatibility: macOS bash 3.2 (no mapfile / readarray / assoc arrays /
# ${var,,}). English comments; Japanese user-facing messages (deny messages
# without emoji per the obsidian-ai-pipeline guard style).

set -euo pipefail

TR_DIR="${VAULT_TR_DIR:-10_Threat_Reports}"
BACKUP_DIR="${VAULT_OPS_BACKUP_DIR:-$HOME/.claude/vault-ops/backups}"
REMOTE="${VAULT_REMOTE:-origin}"

die() { printf '%s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

rebase_log=""
cleanup() { [ -n "${rebase_log}" ] && rm -f "${rebase_log}" || true; }
trap cleanup EXIT

abort_rebase_if_in_progress() {
  if [ -d "$(git rev-parse --git-path rebase-merge)" ] \
     || [ -d "$(git rev-parse --git-path rebase-apply)" ]; then
    git rebase --abort || true
  fi
}

# Stage the whole vault except quarantined (untrusted) report bodies, then
# run the staged secret gate. NOTE: `git add -A` is the operational norm for
# the vault repo (a human pushing all note edits at once); the repo-wide
# "no -A" rule in obsidian-ai-pipeline's CLAUDE.md governs that pipeline
# repo's own commits. The gate below is what compensates here.
stage_and_gate() {
  # Default pathspec wildcards match across '/', so *_quarantine* excludes
  # any path containing "_quarantine" at any depth.
  git add -A -- . ':(exclude)*_quarantine*'
  if git diff --cached --name-only | grep -i '_quarantine' >/dev/null; then
    die "内部エラー: _quarantine 配下が staged に含まれています。push を中止しました (untrusted 本文は commit しない設計)。"
  fi

  # Staged secret gate — shell copy (4th system) of SECRET_RE in
  # .claude/hooks/block-secret-git.cjs. SLA: when token/file patterns change,
  # update both in the same PR (CLAUDE.md "Secret-pattern の維持").
  SECRET_ERE='(^|/)\.env(\.|$)|(^|/)x_tokens\.json$|(^|/)data/tokens\.json$|(^|/)pkce_state\.json$|(^|/)credentials[^/]*\.json$|(^|/)service-account[^/]*\.json$|[^/]*token[^/]*\.json$|(^|/)pipeline_config\.json$|\.(key|pem)$|(^|/)id_(rsa|ed25519)$|(^|/)secrets\.(json|ya?ml)$|(^|/)secrets/'
  ALLOW_ERE='(^|/)\.env\.example$'
  offenders="$(git diff --cached --name-only | grep -ivE "${ALLOW_ERE}" | grep -iE "${SECRET_ERE}" || true)"
  if [ -n "${offenders}" ]; then
    printf '%s\n' "${offenders}" | while IFS= read -r f; do
      git restore --staged -- "${f}" || true
    done
    {
      printf '%s\n' "secret-looking file を vault に commit しようとしています:"
      printf '%s\n' "${offenders}"
      printf '%s\n' "obsidian-ai-pipeline の CLAUDE.md「Secrets / sensitive files — never commit」によりブロックしました。"
      printf '%s\n' "該当ファイルは staged から外してあります。vault に置くべきでない秘密情報なら削除・移動し、誤検知なら .gitignore への追加やファイル名の変更を検討してください。"
    } >&2
    exit 1
  fi
}

commit_if_needed() {
  if git diff --cached --quiet; then
    info "ℹ️ 変更なし (commit スキップ)"
  else
    git commit -m "vault: update $(date +%Y-%m-%d)"
    info "✅ commit 作成: vault: update $(date +%Y-%m-%d)"
  fi
}

push_with_rebase_retry() {
  attempt=1
  while [ "${attempt}" -le 3 ]; do
    if git push "${REMOTE}" "${BRANCH}"; then
      info "✅ vault push 完了 (attempt ${attempt})"
      return 0
    fi
    info "⚠️ push 失敗 (attempt ${attempt}) — remote を取り込んで再試行します"
    if git fetch "${REMOTE}" "${BRANCH}"; then
      if ! git rebase FETCH_HEAD; then
        abort_rebase_if_in_progress
        die "push 前の rebase が衝突したため中止しました (作業ツリーは復元済み)。git pull --rebase で手動解消後、vault-push-perm を再実行してください。"
      fi
    fi
    if [ "${attempt}" -lt 3 ]; then
      sleep $((2 ** attempt))
    fi
    attempt=$((attempt + 1))
  done
  die "push が 3 回失敗しました。ネットワーク / 認証 (ssh key・deploy key) を確認して vault-push-perm を再実行してください。"
}

# ---- 1. resolve vault path + preflight --------------------------------------
VAULT_PATH="${1:-${PERM_NOTE_PATH:-$PWD}}"
[ -d "${VAULT_PATH}" ] || die "vault パスが存在しません: ${VAULT_PATH}
PERM_NOTE_PATH を設定するか、引数でパスを渡してください。"
cd "${VAULT_PATH}"
git rev-parse --git-dir >/dev/null 2>&1 || die "git リポジトリではありません: ${VAULT_PATH}"
GIT_DIR_PATH="$(git rev-parse --git-dir)"

# ---- 2. iCloud-induced .git corruption detection (detect & stop only) -------
# Duplicated refs ("refs/heads/main 2") appear as ref files with a space in
# the name or as malformed packed-refs lines; evicted files appear as
# *.icloud placeholders. Repair is destructive and stays a human decision.
bad_refs="$(find "${GIT_DIR_PATH}/refs" -name '* *' 2>/dev/null || true)"
icloud_ph="$(find "${GIT_DIR_PATH}" -name '*.icloud' 2>/dev/null | head -5 || true)"
packed_dup=""
if [ -f "${GIT_DIR_PATH}/packed-refs" ]; then
  packed_dup="$(grep -E 'refs/heads/.+ [0-9]+$' "${GIT_DIR_PATH}/packed-refs" || true)"
fi
if [ -n "${bad_refs}${icloud_ph}${packed_dup}" ]; then
  {
    printf '%s\n' "iCloud 同期による .git 破損の兆候を検知したため中止しました (自動修復はしません):"
    [ -n "${bad_refs}" ] && printf '  ref 重複: %s\n' "${bad_refs}"
    [ -n "${packed_dup}" ] && printf '  packed-refs 異常: %s\n' "${packed_dup}"
    [ -n "${icloud_ph}" ] && printf '  iCloud placeholder: %s\n' "${icloud_ph}"
    printf '%s\n' "復旧手順は vault 管理ノート「iCloud による git 破損」節を参照してください (ref の削除は破壊的操作のため人間が実施)。"
  } >&2
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "${BRANCH}" != "HEAD" ] || die "detached HEAD 状態です。ブランチを checkout してから vault-push-perm を再実行してください。"
if [ -d "$(git rev-parse --git-path rebase-merge)" ] \
   || [ -d "$(git rev-parse --git-path rebase-apply)" ]; then
  die "未完了の rebase が残っています。git rebase --abort (破棄) か git rebase --continue (続行) で解消してから再実行してください。"
fi
if [ -n "$(git ls-files -u)" ]; then
  die "unmerged なファイルが残っています (前回の衝突が未解消)。解消して commit してから再実行してください。"
fi

# ---- 3. fetch (offline degrades to local-commit + one push attempt) ---------
info "🔄 ${REMOTE}/${BRANCH} を取得中..."
if ! git fetch "${REMOTE}" "${BRANCH}"; then
  info "⚠️ fetch 失敗 (オフライン?) — ローカル commit まで行い、push を 1 回だけ試します"
  stage_and_gate
  commit_if_needed
  if git push "${REMOTE}" "${BRANCH}"; then
    info "✅ vault push 完了"
    exit 0
  fi
  die "push できませんでした。変更はローカルに commit 済みです (失われません)。ネットワーク回復後に vault-push-perm を再実行してください。"
fi

# ---- 4. conditional quarantine of untracked .threat_reports.json ------------
# Only when the remote already tracks the file (CI has pushed it) AND the
# local copy is untracked: the rebase below would otherwise refuse to
# overwrite it. CI output is authoritative; the local copy is preserved
# outside the work tree (so the backup itself can never be committed).
JSON_REL="${TR_DIR}/.threat_reports.json"
if [ -f "${JSON_REL}" ] \
   && ! git ls-files --error-unmatch -- "${JSON_REL}" >/dev/null 2>&1 \
   && git cat-file -e "FETCH_HEAD:${JSON_REL}" 2>/dev/null; then
  mkdir -p "${BACKUP_DIR}"
  # The backup must live OUTSIDE the work tree: the later `git add -A` would
  # otherwise commit the backup itself. Reject an env override that points
  # back into the vault (PR #117 CodeRabbit).
  vault_abs="$(pwd -P)"
  backup_abs="$(cd "${BACKUP_DIR}" && pwd -P)"
  case "${backup_abs}/" in
    "${vault_abs}/"*)
      die "VAULT_OPS_BACKUP_DIR は vault worktree の外に設定してください: ${BACKUP_DIR}"
      ;;
  esac
  backup_path="${BACKUP_DIR}/$(date +%Y%m%d-%H%M%S)-threat_reports.local.json"
  mv "${JSON_REL}" "${backup_path}"
  info "📦 未追跡の ${JSON_REL} を退避しました (CI 版を正として採用): ${backup_path}"
fi

# ---- 5. rebase --autostash onto FETCH_HEAD ----------------------------------
stash_before="$(git stash list | wc -l | tr -d ' ')"
rebase_log="$(mktemp "${TMPDIR:-/tmp}/vault-ops-rebase.XXXXXX")"
if ! git rebase --autostash FETCH_HEAD 2>&1 | tee "${rebase_log}"; then
  abort_rebase_if_in_progress
  if grep -qi "untracked working tree files" "${rebase_log}"; then
    die "rebase 中止: リモートの変更と衝突する未追跡ファイルがあります (上記一覧)。該当ファイルを退避 (例: mv ファイル名 ファイル名.local) してから vault-push-perm を再実行してください。"
  fi
  die "rebase が衝突したため中止しました (作業ツリーは元の状態に復元済み)。git pull --rebase で手動解消後、vault-push-perm を再実行してください。"
fi
# Guard both known autostash-conflict behaviors: (a) conflict markers +
# unmerged index entries, (b) work tree reset with the stash kept. Either
# way, committing now would push a state that silently omits (or mangles)
# the user's uncommitted edits — stop before staging.
if [ -n "$(git ls-files -u)" ]; then
  die "rebase 後の autostash 適用が衝突しています。衝突を解消してから vault-push-perm を再実行してください (このまま push すると衝突マーカーが commit されます)。"
fi
stash_after="$(git stash list | wc -l | tr -d ' ')"
if [ "${stash_after}" -gt "${stash_before}" ]; then
  die "autostash の適用が衝突し、作業中の変更が stash に退避されています。git stash pop で復元・解消してから vault-push-perm を再実行してください (このまま push すると作業中の変更が含まれません)。"
fi

# ---- 6-7. stage + secret gate + commit + push --------------------------------
stage_and_gate
commit_if_needed
if [ "$(git rev-list --count FETCH_HEAD..HEAD)" -eq 0 ]; then
  info "✅ リモートと同期済み (push 不要)"
  exit 0
fi
push_with_rebase_retry
