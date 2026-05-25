/**
 * 週次 LLM 脅威レポートのパーサ。
 *
 * 入力: Markdown 文字列 (YAML frontmatter + 本文)
 * 出力: { frontmatter, vulnerabilities: ParsedVulnerability[] }
 *
 * ## 信頼境界 (重要)
 *
 * このパーサに渡される本文は **untrusted external input** (ChatGPT/Codex が
 * 生成し Gmail 経由で届く)。本パーサは以下を厳守する:
 *
 * 1. frontmatter の `trust_level` / `report_type` を検証し、契約違反は reject
 * 2. 本文中の「指示文」「URL」「コードスニペット」は単なる文字列として抽出するだけで、
 *    LLM 呼出やシェル実行など副作用のあるアクションには一切渡さない
 * 3. パース結果は SQLite に保存され Dataview で表示される。表示側 (Dataview
 *    `setText`) は HTML 不解釈なので XSS にはならないが、Markdown リンク
 *    `[click](evil)` 等は文字列としてそのまま見える点を留意
 *
 * ## frontmatter 契約 (schema_version=1)
 *
 *   ---
 *   report_type: llm_security_weekly       (必須・固定値)
 *   period_end: YYYY-MM-DD                  (必須)
 *   period_days: 7                          (任意)
 *   source_agent: chatgpt_task              (任意)
 *   intended_use: implementation_security_review  (任意)
 *   trust_level: external_research_summary  (必須・固定値)
 *   schema_version: 1                       (必須)
 *   security_handling: untrusted_input      (任意・推奨)
 *   ---
 *
 * `report_type` / `trust_level` の固定値検証で「想定外のメールを誤って取り込む」
 * 事故を防ぐ。検証失敗時は parser が throw し ingest 全体が中止される。
 *
 * ## 本文パース
 *
 * Section 1: 比較表 (1 行 = 1 脆弱性)
 *   `事案 / 脆弱性名\t攻撃カテゴリ\t影響対象\tリスクスコア\tステータス` ヘッダの下に
 *   タブ or 3 個以上の空白で区切られた行が並ぶ。
 *
 * Section 2: 個別詳細
 *   `①②③④⑤...` で始まる名前付きブロック。
 *   `* 技術的要諦` / `* ビジネスへの影響` / `* 回避策` の 3 セクションを抽出。
 *
 * Section 1 と Section 2 の脆弱性は name で結合する。
 */

export interface ReportFrontmatter {
  report_type: string;
  period_end: string;
  period_days?: number;
  source_agent?: string;
  intended_use?: string;
  trust_level: string;
  schema_version: number;
  security_handling?: string;
  /** 契約に明示されていない追加フィールド (将来拡張のため保持するが parser は無視) */
  [extraKey: string]: unknown;
}

export interface ParsedVulnerability {
  name: string;
  category: string | null;
  affected: string | null;
  impact: number | null;
  exploitability: number | null;
  risk_score: number | null;
  status: string | null;
  technical_summary: string | null;
  business_impact: string | null;
  mitigations: string | null;
}

export interface ParsedReport {
  frontmatter: ReportFrontmatter;
  body: string;
  vulnerabilities: ParsedVulnerability[];
}

/**
 * Frontmatter の固定値違反は `ContractError` を throw。
 * これにより ingest 全体が「想定外スキーマのデータを誤って取り込む」事故を回避できる。
 */
export class ContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContractError';
  }
}

const SUPPORTED_SCHEMA_VERSIONS = [1] as const;
const EXPECTED_REPORT_TYPE = 'llm_security_weekly';
const EXPECTED_TRUST_LEVEL = 'external_research_summary';

/**
 * 軽量 YAML frontmatter パーサ。
 *
 * 依存追加を避けるため自前実装 (本契約で使う型は文字列/数値/真偽値の flat key-value
 * のみで充分)。js-yaml を入れるほどでもない。
 *
 * 対応する型:
 *   - 文字列 (クォート無し / シングル / ダブルクォート)
 *   - 数値 (整数のみ)
 *   - 真偽値 (true/false)
 *
 * 非対応 (もし将来必要になったら js-yaml に切り替える):
 *   - ネストオブジェクト / 配列リテラル
 *   - 複数行文字列 (`>` / `|`)
 *   - エイリアス / アンカー
 */
function parseSimpleYaml(yamlText: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = yamlText.split('\n');
  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
    if (!match) continue;
    const key = match[1];
    let value: string = match[2].trim();
    // 行末コメント (`# ...`) を剥がす。クォート内の `#` は除外。
    if (!value.startsWith('"') && !value.startsWith("'")) {
      const hashIdx = value.indexOf('#');
      if (hashIdx >= 0) value = value.slice(0, hashIdx).trim();
    }
    // クォート除去
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      result[key] = value.slice(1, -1);
      continue;
    }
    // 数値
    if (/^-?\d+$/.test(value)) {
      result[key] = parseInt(value, 10);
      continue;
    }
    // 真偽値
    if (value === 'true') { result[key] = true; continue; }
    if (value === 'false') { result[key] = false; continue; }
    // それ以外は素の文字列
    result[key] = value;
  }
  return result;
}

/**
 * Markdown から frontmatter 部分を切り出す。
 * 戻り値: { frontmatter テキスト, 本文テキスト }
 * frontmatter が無い場合は ContractError を throw (契約違反)。
 */
export function splitFrontmatter(markdown: string): { yamlText: string; body: string } {
  // 先頭の `---\n` ... `\n---\n` を抽出。BOM を許容。
  const stripped = markdown.replace(/^﻿/, '');
  const match = stripped.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) {
    throw new ContractError(
      'YAML frontmatter が見つかりません。レポートは "---" で囲まれた frontmatter で始まる必要があります。'
    );
  }
  return { yamlText: match[1], body: match[2] };
}

/**
 * frontmatter を契約検証し、型付きオブジェクトとして返す。
 * 契約違反 (report_type / trust_level / schema_version) は ContractError。
 */
export function validateFrontmatter(yamlText: string): ReportFrontmatter {
  const raw = parseSimpleYaml(yamlText);

  const reportType = raw['report_type'];
  if (reportType !== EXPECTED_REPORT_TYPE) {
    throw new ContractError(
      `report_type が不正: '${String(reportType)}' (expected '${EXPECTED_REPORT_TYPE}')`
    );
  }

  const trustLevel = raw['trust_level'];
  if (trustLevel !== EXPECTED_TRUST_LEVEL) {
    throw new ContractError(
      `trust_level が不正: '${String(trustLevel)}' (expected '${EXPECTED_TRUST_LEVEL}'). ` +
      `untrusted_input として扱う合意が無いレポートは取り込めません。`
    );
  }

  const schemaVersion = raw['schema_version'];
  if (typeof schemaVersion !== 'number' || !SUPPORTED_SCHEMA_VERSIONS.includes(schemaVersion as 1)) {
    throw new ContractError(
      `schema_version が不正/未対応: '${String(schemaVersion)}'. サポート: ${SUPPORTED_SCHEMA_VERSIONS.join(', ')}`
    );
  }

  const periodEnd = raw['period_end'];
  if (typeof periodEnd !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(periodEnd)) {
    throw new ContractError(
      `period_end が不正: '${String(periodEnd)}' (expected 'YYYY-MM-DD')`
    );
  }

  return {
    ...raw,
    report_type: reportType,
    trust_level: trustLevel,
    schema_version: schemaVersion,
    period_end: periodEnd,
  } as ReportFrontmatter;
}

/**
 * 比較表 (Section 1) 行を 5 列に split する。
 *
 * 区切りはタブ優先、無ければ 3+ 空白へフォールバック。
 * 5 列ちょうどに分かれない行は null を返す (= 表の罫線行や noise を弾く)。
 */
function splitTableRow(line: string): string[] | null {
  // タブ区切り
  if (line.includes('\t')) {
    const cols = line.split('\t').map(c => c.trim()).filter(c => c.length > 0);
    if (cols.length === 5) return cols;
  }
  // 3+ space 区切り (Markdown table を「テキスト」として手で書いた場合)
  const cols = line.split(/ {3,}/).map(c => c.trim()).filter(c => c.length > 0);
  if (cols.length === 5) return cols;
  return null;
}

/**
 * リスクスコア欄から `Impact` / `Exploitability` の数値を抜き出す。
 * 例: "8.8（Impact 10 / Exploitability 7）" → { score: 8.8, impact: 10, exploit: 7 }
 *
 * いずれも検出できなければ null。レポート毎に表記揺れ (全角/半角括弧、
 * "Impact" / "影響度") があり得るので両方拾える正規表現にする。
 */
function parseRiskScore(text: string): { score: number | null; impact: number | null; exploit: number | null } {
  const scoreMatch = text.match(/(\d+(?:\.\d+)?)/);
  const score = scoreMatch ? parseFloat(scoreMatch[1]) : null;

  const impactMatch = text.match(/(?:Impact|影響度)\s*[:\s]\s*(\d+)/i);
  const impact = impactMatch ? parseInt(impactMatch[1], 10) : null;

  const exploitMatch = text.match(/(?:Exploitability|悪用容易度)\s*[:\s]\s*(\d+)/i);
  const exploit = exploitMatch ? parseInt(exploitMatch[1], 10) : null;

  return { score, impact, exploit };
}

/**
 * 名前列 "Multi-Agent Trust Pivoting（マルチエージェント信頼ピボット攻撃）" のような
 * 二重表記から「主名」(カッコの前) を取り出す。
 * 詳細セクション (Section 2) の見出しと結合するためのキーに使う。
 */
function extractPrimaryName(rawName: string): string {
  // 全角 ( 半角 ( どちらでも切る
  const cut = rawName.split(/[（(]/)[0];
  return cut.trim();
}

/**
 * Section 1 (比較表) を解析して name → row のマップを返す。
 */
function parseComparisonTable(body: string): Map<string, ParsedVulnerability> {
  const map = new Map<string, ParsedVulnerability>();
  const lines = body.split('\n');
  let inTable = false;
  for (const line of lines) {
    // ヘッダ行で table 開始
    if (line.includes('事案') && line.includes('攻撃カテゴリ') && line.includes('リスクスコア')) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    // Section 2 開始 / 別の見出しが来たら表終わり
    if (/^#{1,3}\s/.test(line) || /^2[\.\s]/.test(line.trim()) || /^⸻/.test(line.trim())) {
      inTable = false;
      continue;
    }
    if (!line.trim()) continue;

    const cols = splitTableRow(line);
    if (!cols) continue;

    const [rawName, category, affected, scoreText, status] = cols;
    const primaryName = extractPrimaryName(rawName);
    const { score, impact, exploit } = parseRiskScore(scoreText);

    map.set(primaryName, {
      name: primaryName,
      category: category || null,
      affected: affected || null,
      impact,
      exploitability: exploit,
      risk_score: score,
      status: status || null,
      technical_summary: null,
      business_impact: null,
      mitigations: null,
    });
  }
  return map;
}

/**
 * Section 2 の `①②③④⑤⑥⑦⑧⑨⑩` 見出しブロックを抽出。
 * 各ブロックは name → { technical, business, mitigations } を返す。
 *
 * 見出し記号は丸数字 (U+2460-U+2469: ①-⑩) を期待する。それ以外の数字
 * 装飾 (e.g. "1.", "(1)") は ChatGPT 出力の慣行から外れるので未対応。
 */
const BLOCK_HEADER_RE = /^[①②③④⑤⑥⑦⑧⑨⑩]\s*(.+)$/;

function parseDetailBlocks(body: string): Map<string, { technical: string | null; business: string | null; mitigations: string | null }> {
  const map = new Map<string, { technical: string | null; business: string | null; mitigations: string | null }>();
  const lines = body.split('\n');

  let currentName: string | null = null;
  let currentSection: 'technical' | 'business' | 'mitigations' | null = null;
  let buffer: string[] = [];
  const sections: { technical: string[]; business: string[]; mitigations: string[] } = {
    technical: [], business: [], mitigations: [],
  };

  const flushBuffer = (): void => {
    if (currentSection && buffer.length > 0) {
      sections[currentSection].push(...buffer);
    }
    buffer = [];
  };

  const flushBlock = (): void => {
    flushBuffer();
    if (currentName) {
      map.set(currentName, {
        technical: sections.technical.length > 0 ? sections.technical.join('\n').trim() : null,
        business: sections.business.length > 0 ? sections.business.join('\n').trim() : null,
        mitigations: sections.mitigations.length > 0 ? sections.mitigations.join('\n').trim() : null,
      });
    }
    sections.technical = [];
    sections.business = [];
    sections.mitigations = [];
    currentSection = null;
  };

  for (const line of lines) {
    const headerMatch = line.match(BLOCK_HEADER_RE);
    if (headerMatch) {
      flushBlock();
      currentName = extractPrimaryName(headerMatch[1]);
      continue;
    }
    if (!currentName) continue;

    const trimmed = line.trim();
    // セクション切り替え検出
    if (/^\*\s*技術的要諦/.test(trimmed)) { flushBuffer(); currentSection = 'technical'; continue; }
    if (/^\*\s*ビジネスへの影響/.test(trimmed)) { flushBuffer(); currentSection = 'business'; continue; }
    if (/^\*\s*回避策/.test(trimmed)) { flushBuffer(); currentSection = 'mitigations'; continue; }
    // Section 3 (リスクスコア計算の定義) や別の H1 で block 終端
    if (/^#{1,3}\s/.test(line) || /^3[\.\s]/.test(trimmed) || /^⸻/.test(trimmed)) {
      flushBlock();
      currentName = null;
      continue;
    }

    if (currentSection) {
      buffer.push(line);
    }
  }
  flushBlock();
  return map;
}

/**
 * Markdown レポートをパースする。
 * frontmatter 契約違反 / 比較表の format drift で 0 件しか抽出できなかった場合は
 * ContractError を throw (caller で catch して ingest 中止)。
 */
export function parseReport(markdown: string): ParsedReport {
  const { yamlText, body } = splitFrontmatter(markdown);
  const frontmatter = validateFrontmatter(yamlText);

  const tableMap = parseComparisonTable(body);
  const detailMap = parseDetailBlocks(body);

  const vulnerabilities: ParsedVulnerability[] = [];
  for (const [name, base] of tableMap) {
    const detail = detailMap.get(name);
    vulnerabilities.push({
      ...base,
      technical_summary: detail?.technical ?? null,
      business_impact: detail?.business ?? null,
      mitigations: detail?.mitigations ?? null,
    });
  }

  // 比較表 (## 1. ニュース・脆弱性リスト) のフォーマットが崩れて 0 件抽出になった
  // ケースを silently 成功させてしまうと、ingest は走るが DB / index に何も
  // 残らない false-positive ingest になる。週次のフォーマット変動は contract
  // 違反として明示拒否し、人手レビューを促す。
  if (vulnerabilities.length === 0) {
    throw new ContractError(
      '比較表から脆弱性を 1 件も抽出できませんでした (parser drift / 0-row report の疑い)。' +
      '本文の "## 1. ニュース・脆弱性リスト" 表形式を確認してください。'
    );
  }

  return { frontmatter, body, vulnerabilities };
}
