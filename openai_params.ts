/**
 * OpenAI の Chat Completions に付ける推論の指定。
 *
 * 分類・要約・該当性の判定は出力が短い (300〜400 tokens)。推論の token も出力の上限に
 * 数えられるので、推論を走らせると答えの本文が空のまま上限に達し得る。
 * そこで `reasoning_effort: 'none'` を受け付けると確かめたモデルにだけ none を付ける。
 */

/**
 * `reasoning_effort: 'none'` を付けるモデル。2026-11-17 に実の呼び出しで、none・temperature・
 * `max_completion_tokens`・`response_format: json_object` を一緒に送って 200 と推論 0 tokens を
 * 確かめた 2 つだけを true にする。保存済みの設定や env の上書きで別のモデル (gpt-4o 系や
 * none を受けないモデル) が来たとき、送ると 400 になり得るため、分からないモデルには送らない側に倒す。
 */
const NO_REASONING_MODEL_PATTERN = /^gpt-(?:6-luna|6\.1-terra)$/;

export function supportsNoReasoning(model: string): boolean {
  return NO_REASONING_MODEL_PATTERN.test(model);
}

/** 短い出力の経路に付ける推論の指定。対応しないモデルには何も付けない。 */
export function noReasoningFor(model: string): { reasoning_effort?: 'none' } {
  return supportsNoReasoning(model) ? { reasoning_effort: 'none' } : {};
}
