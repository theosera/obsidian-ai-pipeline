/**
 * Claude (Messages API) の応答から「答えの文字」を取り出す共通の口と、
 * Claude 5 系に合わせた要求の調整。
 *
 * - Claude 5 系 (`claude-sonnet-5-5` / `claude-haiku-5-5` 等) は、要求が `thinking` を
 *   指定しなくても adaptive thinking が走り、応答の頭に `thinking` ブロックが来うる。
 *   `content[0]` を答えとして読むと壊れるので、`type === 'text'` のブロックだけを集める。
 * - 安全分類器が断った応答は HTTP 200 + `stop_reason: 'refusal'` で返る。content を
 *   読む前に判定する (Haiku 5.5 には server-side fallback が無い)。
 * - thinking も `max_tokens` に数えられる。呼出側の「答えの予算」は保ったまま、
 *   thinking の分を上乗せする。
 *
 * classifier.ts のクライアント生成 (import 時の副作用) を巻き込まないよう、
 * SDK の型だけに依存する独立モジュールにしている。
 */
import type Anthropic from '@anthropic-ai/sdk';

export type AnthropicTextResult =
  | { ok: true; text: string }
  | { ok: false; reason: 'refusal' | 'no_text'; stopReason: Anthropic.StopReason | null };

/** 応答から答えの文字を取り出す。refusal と「text ブロックが無い」(thinking だけで max_tokens に達した等) を区別して返す。 */
export function readAnthropicText(message: Pick<Anthropic.Message, 'content' | 'stop_reason'>): AnthropicTextResult {
  if (message.stop_reason === 'refusal') {
    return { ok: false, reason: 'refusal', stopReason: message.stop_reason };
  }
  const text = message.content
    .filter((block): block is Anthropic.TextBlock => block.type === 'text')
    .map((block) => block.text)
    .join('')
    .trim();
  if (!text) {
    return { ok: false, reason: 'no_text', stopReason: message.stop_reason };
  }
  return { ok: true, text };
}

/** `readAnthropicText` の失敗を 1 行の説明にする (ログ・例外の文言用)。 */
export function describeAnthropicFailure(result: Extract<AnthropicTextResult, { ok: false }>): string {
  return `Anthropic returned no answer text (reason=${result.reason}, stop_reason=${result.stopReason ?? 'null'})`;
}

/**
 * `output_config.effort` を受け付けるモデルか。Claude 5 系だけを true にする。
 * 保存済みの設定や env の上書きで Claude Haiku 4.5 等が来たとき、effort を送ると 400 になるため、
 * 分からないモデルには送らない側に倒す。
 */
const EFFORT_MODEL_PATTERN = /^claude-(?:opus|sonnet|haiku)-5(?:-|$)/;

export function supportsEffort(model: string): boolean {
  return EFFORT_MODEL_PATTERN.test(model);
}

/** 短い出力の経路 (分類・要約・該当性の判定) に付ける effort。対応しないモデルには何も付けない。 */
export function lowEffortFor(model: string): Pick<Anthropic.MessageCreateParamsNonStreaming, 'output_config'> {
  return supportsEffort(model) ? { output_config: { effort: 'low' } } : {};
}

/**
 * thinking の分の `max_tokens` の上乗せ。呼出側が渡す答えの予算 (例: 分類の 300) に足す。
 * 非 streaming の要求のまま SDK の長時間要求の警告に届かない大きさに留める。
 */
export const THINKING_HEADROOM_TOKENS = 2048;
