#!/usr/bin/env bash
# install-vault-ops.sh — one-command installer for the vault write-safety kit.
#
# Run this on the Mac from a local clone of obsidian-ai-pipeline:
#
#   bash .claude/skills/vault-ops/scripts/install-vault-ops.sh \
#     --perm-note-path "/path/to/vault"
#
# What it does (idempotent — safe to re-run):
#   1. copies vault-pre-push.hook into <vault>/.githooks/pre-push (+x)
#   2. sets `git config core.hooksPath .githooks` in the vault clone
#      (local config: must be re-run for every new clone of the vault)
#   3. commits the hook with a pathspec commit (`git commit -- .githooks/...`)
#      so unrelated staged changes in the vault are never swept in
#   4. links ~/.claude/bin/safe-vault-push-perm.sh -> this clone (symlink =
#      auto-updates on `git pull`, the drift-resistant option recommended by
#      CLAUDE.md; use --copy to install an independent copy instead — then
#      YOU own keeping it fresh at the quarterly pattern review)
#   5. prints the two lines to add to ~/.zshrc (default: print only;
#      --write-zshrc backs up the file, comments out any old
#      `alias vault-push-perm=...` line and appends a managed block)
#
# Flags:
#   --perm-note-path <path>  vault clone location (or env PERM_NOTE_PATH)
#   --copy                   copy the wrapper instead of symlinking
#   --write-zshrc            actually edit ~/.zshrc (default: print only)
#   --self-test              run the sandboxed acceptance tests and exit
#                            (touches neither the real vault nor real $HOME)
#
# Compatibility: macOS bash 3.2. No sed -i (BSD/GNU divergence) — zshrc is
# rewritten via awk + temp file + mv.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

die() { printf '%s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

VAULT_PATH="${PERM_NOTE_PATH:-}"
COPY_MODE=0
WRITE_ZSHRC=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --perm-note-path)
      [ "$#" -ge 2 ] || die "--perm-note-path には値が必要です"
      VAULT_PATH="$2"; shift 2 ;;
    --copy) COPY_MODE=1; shift ;;
    --write-zshrc) WRITE_ZSHRC=1; shift ;;
    --self-test)
      exec bash "${SCRIPT_DIR}/../tests/run_vault_ops_tests.sh" ;;
    -h|--help)
      grep '^#' "$0" | grep -v '^#!' | cut -c 3-; exit 0 ;;
    *) die "不明なオプション: $1 (--help を参照)" ;;
  esac
done

[ -n "${VAULT_PATH}" ] || die "vault のパスが未指定です。--perm-note-path <path> か PERM_NOTE_PATH env で渡してください。
探し方の例: find ~ -maxdepth 6 -iname '*permanent*note*' -type d 2>/dev/null"
[ -d "${VAULT_PATH}" ] || die "vault パスが存在しません: ${VAULT_PATH}"
git -C "${VAULT_PATH}" rev-parse --git-dir >/dev/null 2>&1 \
  || die "git リポジトリではありません: ${VAULT_PATH}"

# ---- 1-3. pre-push hook into the vault repo ---------------------------------
HOOK_SRC="${SCRIPT_DIR}/vault-pre-push.hook"
HOOK_DST="${VAULT_PATH}/.githooks/pre-push"
[ -f "${HOOK_SRC}" ] || die "hook テンプレートが見つかりません: ${HOOK_SRC}"

mkdir -p "${VAULT_PATH}/.githooks"
if [ -f "${HOOK_DST}" ] && cmp -s "${HOOK_SRC}" "${HOOK_DST}"; then
  info "✅ pre-push hook は最新です (変更なし)"
else
  cp "${HOOK_SRC}" "${HOOK_DST}"
  info "📦 pre-push hook を配置: ${HOOK_DST}"
fi
chmod +x "${HOOK_DST}"

git -C "${VAULT_PATH}" config core.hooksPath .githooks
info "✅ core.hooksPath = .githooks (local config — vault の新しい clone では installer を再実行)"

# Commit the hook so it travels with the vault repo. Obsidian vaults commonly
# gitignore all dotfiles (`.*`) — the same reason the weekly CI force-adds
# `.threat_reports.json` — which hides an untracked .githooks/ from
# `git status --porcelain` and would wrongly take the "already committed"
# path, leaving every other clone unprotected (PR #117 Codex P2). `git add -f`
# is ignore-proof; once tracked, later updates behave normally. The pathspec
# commit keeps any unrelated staged changes in the vault out of this commit.
git -C "${VAULT_PATH}" add -f -- .githooks/pre-push
if git -C "${VAULT_PATH}" diff --cached --quiet -- .githooks/pre-push; then
  info "✅ hook は commit 済みです"
else
  git -C "${VAULT_PATH}" commit -m "chore: add vault-ops pre-push guard (non-ff/force push protection)" -- .githooks/pre-push
  info "✅ hook を commit しました (次回の vault push で共有されます)"
fi

# ---- 4. wrapper into ~/.claude/bin ------------------------------------------
WRAPPER_SRC="${SCRIPT_DIR}/safe-vault-push-perm.sh"
BIN_DIR="${HOME}/.claude/bin"
WRAPPER_DST="${BIN_DIR}/safe-vault-push-perm.sh"
mkdir -p "${BIN_DIR}"

if [ "${COPY_MODE}" -eq 1 ]; then
  cp -f "${WRAPPER_SRC}" "${WRAPPER_DST}"
  chmod +x "${WRAPPER_DST}"
  info "📦 wrapper をコピー配置: ${WRAPPER_DST}"
  info "⚠️ コピー配置は git 管理外の独立コピーです — 四半期の secret-pattern レビュー時に必ず更新してください (CLAUDE.md「Secret-pattern の維持」)"
else
  if [ -e "${WRAPPER_DST}" ] && [ ! -L "${WRAPPER_DST}" ]; then
    mv "${WRAPPER_DST}" "${WRAPPER_DST}.bak.$(date +%s)"
    info "📦 既存の実ファイルを退避しました: ${WRAPPER_DST}.bak.*"
  fi
  ln -sfn "${WRAPPER_SRC}" "${WRAPPER_DST}"
  info "✅ wrapper を symlink 配置: ${WRAPPER_DST} -> ${WRAPPER_SRC}"
  info "   (git pull で自動更新。clone を移動/削除すると壊れる点だけ注意)"
fi

# ---- 5. zshrc ----------------------------------------------------------------
ZSHRC="${ZDOTDIR:-$HOME}/.zshrc"
BEGIN_MARK="# >>> vault-ops managed >>>"
END_MARK="# <<< vault-ops managed <<<"
# Single-quote-escape for embedding a literal value in generated shell text
# (close quote, insert \', reopen). Keeps paths containing quotes / spaces /
# $ / backticks literal when .zshrc is sourced (PR #117 CodeRabbit). A shell
# function instead of an alias also forwards extra arguments.
sq() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }
ALIAS_LINE="vault-push-perm() { PERM_NOTE_PATH='$(sq "${VAULT_PATH}")' \"\$HOME/.claude/bin/safe-vault-push-perm.sh\" \"\$@\"; }"

if [ "${WRITE_ZSHRC}" -eq 0 ]; then
  info ""
  info "次の managed block を ${ZSHRC} に追記してください (自動追記は --write-zshrc):"
  info "  ${BEGIN_MARK}"
  info "  ${ALIAS_LINE}"
  info "  ${END_MARK}"
else
  if [ -f "${ZSHRC}" ]; then
    cp "${ZSHRC}" "${ZSHRC}.vault-ops.bak.$(date +%s)"
    info "📦 backup: ${ZSHRC}.vault-ops.bak.*"
  else
    : > "${ZSHRC}"
  fi
  TMP_ZSHRC="$(mktemp "${TMPDIR:-/tmp}/vault-ops-zshrc.XXXXXX")"
  # Drop any previous managed block; comment out any live (non-managed) old
  # alias definition instead of deleting it, per the migration instruction.
  awk -v begin="${BEGIN_MARK}" -v end="${END_MARK}" '
    $0 == begin { inblock = 1; next }
    $0 == end   { inblock = 0; next }
    inblock     { next }
    /^[[:space:]]*alias vault-push-perm=/ {
      print "# vault-ops superseded: " $0; next
    }
    { print }
  ' "${ZSHRC}" > "${TMP_ZSHRC}"
  {
    printf '%s\n' "${BEGIN_MARK}"
    printf '%s\n' "${ALIAS_LINE}"
    printf '%s\n' "${END_MARK}"
  } >> "${TMP_ZSHRC}"
  mv "${TMP_ZSHRC}" "${ZSHRC}"
  info "✅ ${ZSHRC} を更新しました (旧 alias はコメントアウトで温存)"
fi

info ""
info "🎉 導入完了。受け入れ確認:"
info "  1. bash ${SCRIPT_DIR}/install-vault-ops.sh --self-test   # サンドボックス検証"
info "  2. 新しいターミナルで: vault-push-perm                    # 実 vault で動作確認"
info "  3. (任意) vault repo で素の git push を試し、CI 先行時に拒否されることを確認"
