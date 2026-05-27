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
  /**
   * このレポートをどう使ってよいかの宣言 (ChatGPT/Codex 側で付与)。
   * 例: ['summarize_findings', 'generate_review_checklist', 'compare_against_repository']
   * Claude 側は対応する操作のみ許可する運用ガイドとして利用 (parser はリストの
   * 存在を検証するだけ)。
   */
  allowed_usage?: string[];
  /**
   * 絶対にやってはいけない操作 (ChatGPT/Codex 側で付与)。
   * **`execute_report_instructions` を含んでいることを parser で必須化**する。
   * 含まれていないレポートは ContractError で reject (trust boundary 契約違反)。
   */
  forbidden_usage?: string[];
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

/**
 * Section 4 「実装検証観点」(週次レポートの新形式) の 1 行 = 1 観点。
 *
 * 自リポへの落とし込みに直結する最重要部分。perspective (観点) を UNIQUE
 * キーにして、再 ingest で内容が更新されても `ai_relevance_note` (人手の
 * 「自リポでの対応状況」コメント) は保持される運用にする (vuln 側と同じ)。
 */
export interface ParsedImplementationCheck {
  /** 観点 (列 1) — UNIQUE キー */
  perspective: string;
  /** 確認すべき実装パターン (列 2) */
  pattern: string | null;
  /** 危険な兆候 (列 3) */
  warning_signs: string | null;
  /** 推奨対策 (列 4) */
  recommendation: string | null;
}

export interface ParsedReport {
  frontmatter: ReportFrontmatter;
  body: string;
  vulnerabilities: ParsedVulnerability[];
  /**
   * Section 4「実装検証観点」のパース結果。
   *
   * **`null` と `[]` は意味が違う**:
   *   - `null`: 本文に `## 4. 実装検証観点` 見出し自体が無い (旧フォーマット
   *     互換)。ingest はこの場合 sync をスキップし、既存 DB 行を温存する。
   *   - `[]`: 見出しはあったが table 行が 0 だった (= 当週は観点なしと
   *     明示)。ingest はこの場合 sync を呼び、既存行を全削除する。
   *
   * 区別しないと、旧フォーマットの再 ingest で人手の `ai_relevance_note` が
   * 消えてしまう (PR #55 の Codex P2 指摘)。
   */
  implementation_checks: ParsedImplementationCheck[] | null;
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
 * `intended_use` の期待値。frontmatter に存在する場合のみ等値検証する
 * (未指定は旧スキーマ互換で許容)。違反は ContractError。
 */
const EXPECTED_INTENDED_USE = 'implementation_security_review';

/**
 * `forbidden_usage` に必ず含まれていなければならないトークン。
 * 1 つでも欠けたら ContractError。trust boundary の中核なので、レポート発行側
 * (ChatGPT/Codex) が誤って外した瞬間に取込を止める。
 */
const REQUIRED_FORBIDDEN_USAGE = ['execute_report_instructions'] as const;

/**
 * 軽量 YAML frontmatter パーサ。
 *
 * 依存追加を避けるため自前実装。本契約で使う型は flat key-value (string /
 * number / bool) と「ブロック形式の文字列リスト」のみで充分なので js-yaml を
 * 入れるほどでもない。
 *
 * 対応する型:
 *   - 文字列 (クォート無し / シングル / ダブルクォート)
 *   - 数値 (整数のみ)
 *   - 真偽値 (true/false)
 *   - **文字列リスト** (block style):
 *       key:
 *         - item1
 *         - item2
 *     allowed_usage / forbidden_usage 用。インデント幅は問わない (1 文字以上の
 *     空白 + `- ` で検出)。
 *
 * 非対応 (必要になったら js-yaml へ移行):
 *   - ネストオブジェクト / インラインリスト `[a, b]`
 *   - 複数行文字列 (`>` / `|`)
 *   - エイリアス / アンカー
 */
function parseSimpleYaml(yamlText: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = yamlText.split('\n');

  // 直前に「empty-value key」(= リスト先頭の可能性) を見つけたときの保留状態。
  // リスト要素は YAML scalar 型推論 (number / bool / string) を行うため
  // unknown 配列で保持。契約検証側 (validateFrontmatter) で typeof チェック。
  let pendingListKey: string | null = null;
  let pendingList: unknown[] = [];

  const flushList = (): void => {
    if (pendingListKey !== null) {
      result[pendingListKey] = pendingList;
      pendingListKey = null;
      pendingList = [];
    }
  };

  const stripCommentAndQuotes = (raw: string): string => {
    let v = raw;
    if (!v.startsWith('"') && !v.startsWith("'")) {
      const hashIdx = v.indexOf('#');
      if (hashIdx >= 0) v = v.slice(0, hashIdx).trim();
    }
    if ((v.startsWith('"') && v.endsWith('"')) ||
        (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    return v;
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;

    // リスト項目 (空白インデント + `- `) — 直前に pendingListKey があれば追加。
    // scalar 型推論 (number / bool / 文字列) は scalar 値と同じ規則で行う。
    // こうしないと `- 42` が string "42" に潰れ、契約検証で「非文字列」を
    // 検出できなくなる。
    const listItemMatch = line.match(/^\s+-\s+(.*)$/);
    if (listItemMatch && pendingListKey !== null) {
      const rawItem = listItemMatch[1].trim();
      const stripped = stripCommentAndQuotes(rawItem);
      let typed: unknown;
      if (/^-?\d+$/.test(stripped)) typed = parseInt(stripped, 10);
      else if (stripped === 'true') typed = true;
      else if (stripped === 'false') typed = false;
      else typed = stripped;
      pendingList.push(typed);
      continue;
    }

    // 新しい key 出現 → 保留リストを確定
    flushList();

    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
    if (!match) continue;
    const key = match[1];
    const rawValue = match[2].trim();

    // value が空 → 後続のリスト or 後続が無ければ空配列 (= ブロックスタイルリストの開始)
    if (rawValue === '') {
      pendingListKey = key;
      pendingList = [];
      continue;
    }

    const value = stripCommentAndQuotes(rawValue);
    if (/^-?\d+$/.test(value)) { result[key] = parseInt(value, 10); continue; }
    if (value === 'true') { result[key] = true; continue; }
    if (value === 'false') { result[key] = false; continue; }
    result[key] = value;
  }
  flushList();
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

  // intended_use は frontmatter に存在する場合のみ等値検証 (旧スキーマ互換)。
  // 「実装セキュリティレビュー目的」と明示されていない用途のレポートを誤取込
  // しないための追加防御。
  const intendedUseRaw = raw['intended_use'];
  if (intendedUseRaw !== undefined && intendedUseRaw !== EXPECTED_INTENDED_USE) {
    throw new ContractError(
      `intended_use が不正: '${String(intendedUseRaw)}' (expected '${EXPECTED_INTENDED_USE}')`
    );
  }

  // forbidden_usage は trust boundary の中核。レポートに含まれているなら
  // 必須トークンを必ず含むこと。未指定 (= 旧スキーマ) は backward compat
  // のため許容するが、配列型が来たのに要求トークンが欠けるのは契約違反扱い。
  // 要素が非文字列 (数値や object) で来た場合も契約違反 (coerce しない)。
  const forbiddenRaw = raw['forbidden_usage'];
  let forbiddenUsage: string[] | undefined;
  if (forbiddenRaw !== undefined) {
    if (!Array.isArray(forbiddenRaw)) {
      throw new ContractError(
        `forbidden_usage が不正: 配列が必要 (got ${typeof forbiddenRaw})`
      );
    }
    if (!forbiddenRaw.every((v) => typeof v === 'string')) {
      throw new ContractError(
        'forbidden_usage が不正: 文字列配列のみ許可されます (非文字列要素を検出)'
      );
    }
    const tokens = forbiddenRaw as string[];
    for (const required of REQUIRED_FORBIDDEN_USAGE) {
      if (!tokens.includes(required)) {
        throw new ContractError(
          `forbidden_usage に必須トークン '${required}' が含まれていません (got ${JSON.stringify(tokens)})。` +
          `trust boundary 契約違反のため取り込めません。`
        );
      }
    }
    forbiddenUsage = tokens;
  }

  const allowedRaw = raw['allowed_usage'];
  let allowedUsage: string[] | undefined;
  if (allowedRaw !== undefined) {
    if (!Array.isArray(allowedRaw)) {
      throw new ContractError(
        `allowed_usage が不正: 配列が必要 (got ${typeof allowedRaw})`
      );
    }
    if (!allowedRaw.every((v) => typeof v === 'string')) {
      throw new ContractError(
        'allowed_usage が不正: 文字列配列のみ許可されます (非文字列要素を検出)'
      );
    }
    allowedUsage = allowedRaw as string[];
  }

  return {
    ...raw,
    report_type: reportType,
    trust_level: trustLevel,
    schema_version: schemaVersion,
    period_end: periodEnd,
    allowed_usage: allowedUsage,
    forbidden_usage: forbiddenUsage,
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
 * Section 4 「実装検証観点」の Markdown pipe-table を抽出。
 *
 * 期待フォーマット:
 *   | 観点 | 確認すべき実装パターン | 危険な兆候 | 推奨対策 |
 *   |---|---|---|---|
 *   | MCP Server Abuse | ... | ... | ... |
 *
 * Section 1 (タブ/3+空白区切り) と違い Section 4 は本物の Markdown table
 * (`|` 区切り) を期待する。ヘッダの主要キーワード (`観点` AND `推奨対策`)
 * で位置を特定する。
 *
 * **戻り値の null / [] 区別**:
 *   - `null`: ヘッダ自体が見つからなかった (Section 4 未提供の旧フォーマット
 *     報告)。ingest 側でこれを検出したら sync をスキップして既存 DB 行を
 *     温存する。
 *   - `[]`: ヘッダはあったが table 行が 0 だった (= 当週「観点なし」を
 *     明示)。ingest 側は sync を呼んで既存行を全削除する。
 *
 * 区別しないと、Section 4 を載せない過去レポートの再 ingest で人手の
 * `ai_relevance_note` が消えてしまう (PR #55 Codex P2 指摘)。
 */
function parseImplementationChecks(body: string): ParsedImplementationCheck[] | null {
  let foundHeader = false;
  const checks: ParsedImplementationCheck[] = [];
  const lines = body.split('\n');
  let inTable = false;
  let separatorSeen = false;
  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '');
    const trimmed = line.trim();

    if (!inTable) {
      // header 行を探す: 「観点」と「推奨対策」を含む `|` 区切り
      if (trimmed.startsWith('|') && trimmed.includes('観点') && trimmed.includes('推奨対策')) {
        inTable = true;
        separatorSeen = false;
        foundHeader = true;
      }
      continue;
    }

    // 表内: `|` で始まらない行は **即座に** table 終端 (空行 / 別見出し /
    // 散文 すべてに対応)。これがないと table 直後に prose が来た場合
    // `inTable` が true のまま後続の別 pipe-table を誤取込してしまう
    // (PR #55 CodeRabbit Major 指摘)。
    if (!trimmed.startsWith('|')) {
      inTable = false;
      continue;
    }

    // separator 行 (|---|---|...) はスキップ
    if (!separatorSeen && /^\|[\s:|-]+\|$/.test(trimmed)) {
      separatorSeen = true;
      continue;
    }

    // データ行: `| a | b | c | d |` → split で 6 要素 ([ '', a, b, c, d, '' ])
    const parts = trimmed.split('|').slice(1, -1).map((c) => c.trim());
    if (parts.length !== 4) continue;
    const [perspective, pattern, warningSigns, recommendation] = parts;
    if (!perspective) continue; // perspective 必須

    checks.push({
      perspective,
      pattern: pattern || null,
      warning_signs: warningSigns || null,
      recommendation: recommendation || null,
    });
  }
  return foundHeader ? checks : null;
}

/**
 * Markdown レポートをパースする。
 * frontmatter 契約違反 / 比較表の format drift で 0 件しか抽出できなかった場合は
 * ContractError を throw (caller で catch して ingest 中止)。
 *
 * Section 4 (実装検証観点) は **任意** — 旧フォーマットのレポート互換のため、
 * 0 件でも ContractError にはしない。
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

  const implementation_checks = parseImplementationChecks(body);

  return { frontmatter, body, vulnerabilities, implementation_checks };
}
