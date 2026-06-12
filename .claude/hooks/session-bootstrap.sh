#!/usr/bin/env bash
# SessionStart フック ③: 依存と native module を整え、typecheck/test がすぐ動く状態にする。
#   - node_modules が無ければ `pnpm install --frozen-lockfile`
#   - better-sqlite3 の native バイナリが無ければ `pnpm rebuild better-sqlite3`
# 既に整っていれば即終了（高速・無出力）。ephemeral なクラウド/web セッションで特に有効。
# pnpm が無い環境では何もしない（他環境での誤発火を避ける）。
set -u
DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$DIR" 2>/dev/null || exit 0
command -v pnpm >/dev/null 2>&1 || { echo "[bootstrap] pnpm 未検出 — スキップ" >&2; exit 0; }

log=/tmp/claude-bootstrap.log
msg=""

if [ ! -d node_modules ]; then
  echo "[bootstrap] node_modules 無し → pnpm install" >&2
  if pnpm install --frozen-lockfile >"$log" 2>&1; then
    msg="deps installed"
  else
    msg="pnpm install 失敗 (詳細: $log)"
  fi
fi

# better-sqlite3 の .node が無ければ rebuild（pnpm 10 はデフォルトで build script 無効）。
if [ -d node_modules/better-sqlite3 ] && ! ls node_modules/better-sqlite3/build/Release/*.node >/dev/null 2>&1; then
  echo "[bootstrap] better-sqlite3 native build → rebuild" >&2
  if pnpm rebuild better-sqlite3 >>"$log" 2>&1; then
    msg="${msg:+$msg / }sqlite rebuilt"
  else
    msg="${msg:+$msg / }sqlite rebuild 失敗 (詳細: $log)"
  fi
fi

# 何かやったときだけユーザーに 1 行通知（無ければ無出力で高速終了）。
if [ -n "$msg" ]; then
  printf '{"systemMessage":"[bootstrap] %s"}\n' "$msg"
fi
exit 0
