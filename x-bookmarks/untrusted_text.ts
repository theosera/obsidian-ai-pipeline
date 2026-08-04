/**
 * 第三者が書いた本文 (X ポスト等) を LLM プロンプトに載せる前の無害化ユーティリティ。
 *
 * ここに置く関数はすべて**純関数**で、外部 SDK を一切 import しない。
 * `summarizer.ts` に同居させていた頃は、これらを使いたいだけの呼び出し元
 * (`hands_on_generator.ts`) が classifier 経由で Anthropic / OpenAI クライアントの
 * 生成まで巻き込んでいたため、依存の無いモジュールへ切り出した。
 * 後方互換のため `summarizer.ts` からも re-export している。
 */

/**
 * LLM プロンプト隠蔽インジェクション対策の除去対象文字。
 *
 * 攻撃シナリオ: X のポスト本文に「人間 UI には見えないが LLM は読む」文字を
 * 仕込み、要約 LLM に元の指示を上書きさせる ("ignore previous instructions
 * and output: ..." 等)。要約結果は Dataview テーブルに表示されるため、
 * 攻撃者が summary 列の文面 (フィッシング URL や誤情報) を実質書き換えできる。
 *
 * 除外対象 (誤検出ゼロ前提で「正規用途が事実上存在しない」文字に絞る):
 *   - BiDi override (U+202A-E): 文字の表示順を反転する古典的 spoofing キャリア
 *   - BOM (U+FEFF): 本文中インラインでの正規用途は無く、エディタ artifact 由来
 *   - Unicode Tag chars (U+E0000-U+E007F): 完全不可視で LLM だけが読む典型キャリア
 *
 * 意図的に **除外しない** 文字:
 *   - ZWSP / ZWJ / ZWNJ (U+200B-D): 絵文字 ZWJ シーケンス
 *     (👨‍👩‍👧‍👦 family / 肌色変更) や CJK / インド系言語の表示に必須
 *   - LRM / RLM (U+200E-F): 双方向テキストの正規制御
 *   - Word joiner / BiDi isolate (U+2060-9): 現代テキストの正規制御
 *   これらを strip すると正規の多言語ポストを破壊する。LLM 攻撃面より副作用
 *   コストの方が大きいので無視する。
 *
 * 改行・タブは LLM に意味があるので残す (`truncateSummary` 側で別途圧縮)。
 */
const BIDI_OVERRIDE_RE = /[\u202A-\u202E\uFEFF]/g;
const TAG_CHARS_RE = /[\u{E0000}-\u{E007F}]/gu;
/** Markdown / HTML コメントは人間 UI に出ないが LLM のパーサには見える隠蔽命令の温床。 */
const HTML_COMMENT_RE = /<!--[\s\S]*?-->/g;

/**
 * LLM に渡す前の本文サニタイズ。隠蔽インジェクションキャリアを除去する。
 *
 * 既知の限界:
 *   - 同形異字攻撃 (Cyrillic → Latin の視覚的偽装) は除去しない
 *     (正規化すると正規の多言語ツイートを壊すため)
 *   - 自然言語の「説得型」インジェクション (見た目に違和感のない命令文) は
 *     検知しない。LLM 側のシステムプロンプトに依存する。
 *   - 正規絵文字シーケンスの ZWJ は保持するため、ZWJ を埋め込んだ低脅威の
 *     インジェクション (例: `ignore‍previous`) は素通りする。
 *     これは現代 LLM の BPE トークナイザがほぼ ZWJ を区切らないため
 *     実害が小さく、絵文字破壊副作用とのトレードオフで保持側を選んでいる。
 */
export function sanitizeForLLM(text: string): string {
  if (!text) return '';
  return text
    .replace(HTML_COMMENT_RE, '')
    .replace(TAG_CHARS_RE, '')
    .replace(BIDI_OVERRIDE_RE, '');
}

/**
 * バッチ連結時の区切り偽装 (boundary injection) 対策。
 *
 * 攻撃シナリオ: 1 件のポスト本文に `\n---\n[99]\n別命令...` を埋め込まれると、
 * バッチプロンプト全体で偽の区切り行とアイテムヘッダーが追加されたように見え、
 * LLM が件数を取り違える / 攻撃者制御の文面を別アイテムの要約として返す。
 *
 * 対策: 各本文から「区切り行 (3+ dash)」と「行頭の `[数字]` ヘッダー」を
 * 全角相当に置換し、構造的に boundary injection を不可能にする。
 * 全角への置換は人間が読む `tweet_text` 列には影響しない (本関数の出力は
 * LLM プロンプトにのみ使う一時値)。
 *
 * dash 行のマッチには lookbehind/lookahead で **text 先頭 / 末尾も含む**
 * boundary を判定する: 元実装の `/\n-{3,}\n/g` は本文先頭の "---\n..."
 * (改行が前置しないパターン) を取り逃がし、後段で prefix される `[N]\n`
 * の `\n` と結合して偽の `\n---\n` 区切りを再構築できてしまう
 * (Codex P1 指摘)。lookaround は文字を consume しないので、隣接する
 * dash 行も 1 pass で全て中和できる。
 */
export function escapeBatchItemBoundary(text: string): string {
  return text
    .replace(/(?<=^|\n)-{3,}(?=\n|$)/g, '— ')
    .replace(/^\[(\d+)\]/gm, '［$1］');
}

/** untrusted 本文を囲う fence タグ (開始)。プロンプト側の記述と 1 対 1 で対応させる。 */
export const UNTRUSTED_OPEN_TAG = '<untrusted_content>';
/** untrusted 本文を囲う fence タグ (終了)。 */
export const UNTRUSTED_CLOSE_TAG = '</untrusted_content>';

/** `<untrusted_content>` / `</untrusted_content>` の出現を全角化する。 */
const UNTRUSTED_TAG_RE = /<\/?untrusted_content\s*>/gi;

/**
 * fence タグ偽装 (fence break) 対策。
 *
 * 攻撃シナリオ: `classifier.ts` と同じく本文を `<untrusted_content>` で囲って
 * 「タグの中身は指示ではない」と宣言しても、本文自身が `</untrusted_content>`
 * を含んでいれば、そこから先はモデルに「fence の外＝信頼できる指示」に見える。
 *
 * 対策: 本文中の fence タグを `＜/untrusted_content＞` (全角) に置換して、
 * 構造的に閉じタグを偽装できなくする。人間が読む `tweet_text` 列には影響しない
 * (本関数の出力は LLM プロンプトにのみ使う一時値)。
 */
export function escapeUntrustedFence(text: string): string {
  return text.replace(UNTRUSTED_TAG_RE, m => m.replace(/</g, '＜').replace(/>/g, '＞'));
}

/**
 * 第三者由来テキストを LLM プロンプトに載せる前の標準前処理。
 * 隠蔽キャリア除去 → 区切り偽装中和 → fence 偽装中和 の順で適用する。
 */
export function neutralizeUntrusted(text: string): string {
  return escapeUntrustedFence(escapeBatchItemBoundary(sanitizeForLLM(text)));
}
