#!/usr/bin/env bash
# Stop フック ④: ターン終了時の軽量品質ゲート。**.ts に変更があるときだけ** `pnpm typecheck`
# を回し、型エラーがあれば systemMessage で**通知**する（規約「テストより先に型チェック」）。
#
# 設計:
#   - 通知のみ（ターンを強制継続させない）= 対話を止めない安全側。ブロックさせたい場合は
#     末尾の出力を {"decision":"block","reason":...} に変えれば「直すまで続ける」ゲートになる。
#   - 無限ループ防止: stop_hook_active のときは即終了。
#   - .ts 変更が無いターン（ドキュメントのみ等）はスキップして高速。
set -u
DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$DIR" 2>/dev/null || exit 0

input="$(cat 2>/dev/null || true)"
case "$input" in *'"stop_hook_active":true'*) exit 0 ;; esac

command -v pnpm >/dev/null 2>&1 || exit 0
command -v git  >/dev/null 2>&1 || exit 0

# working tree / staged のうち .ts 変更があるときだけ実行。
changed="$( { git diff --name-only HEAD; git diff --cached --name-only; } 2>/dev/null \
  | grep -E '\.ts$' | head -n 1 )"
[ -z "$changed" ] && exit 0

out="$(pnpm -s typecheck 2>&1)"; rc=$?
if [ "$rc" -ne 0 ]; then
  printf '%s\n' "$out" > /tmp/claude-typecheck.log
  tail="$(printf '%s' "$out" | grep -E 'error TS|\.ts\(' | head -n 10)"
  # systemMessage を node で安全に JSON エンコード（引用符/改行のエスケープ）。
  node -e 'process.stdout.write(JSON.stringify({systemMessage:"⚠️ Stop gate: pnpm typecheck に型エラーがあります（詳細 /tmp/claude-typecheck.log）:\n"+(process.argv[1]||""),suppressOutput:true}))' "$tail" 2>/dev/null \
    || printf '{"systemMessage":"⚠️ Stop gate: pnpm typecheck に型エラー（詳細 /tmp/claude-typecheck.log）"}'
fi
exit 0
