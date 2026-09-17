/**
 * Gmail fetcher の純関数ヘルパーに対するユニットテスト。
 *
 * 副作用 (Gmail API / fs / DB) を伴う部分は Actions 上で実 OAuth 経路で
 * 検証する想定で、ここでは:
 *   - period_end 抽出 / サニタイズ (path traversal 防御の核心)
 *   - raw path 二重防御
 *   - text/plain 抽出 (multipart message walking)
 * の決定論的ロジックだけをテストする。
 */

import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TestRunner, type TestSuiteResult } from './helpers';
import {
  extractPeriodEnd,
  isSafePeriodEnd,
  isSafeRawPath,
  extractPlainTextBody,
  envOrUndefined,
  buildPendingLabels,
  writePendingLabels,
  readPendingLabels,
  gateAndRoute,
  isInvalidGrantError,
  withOAuthErrorHint,
  readQuarantinePendingSourceRefs,
  appendQuarantineQueueEntry,
  promoteStagedRaw,
  discardFailedPromotion,
  quarantineBody,
  extractBodyParts,
  extractSubject,
  selectReportMessages,
  buildSourceRef,
  threadSourceRef,
  isPeriodEndTooFarInFuture,
  printSummary,
  GATE_SUBDIR,
  PERIOD_END_RE,
  PERIOD_END_FUTURE_HORIZON_DAYS,
  QUARANTINE_QUEUE_SCHEMA,
  type FetcherOutcome,
  type GateRunner,
  type PendingLabel,
} from '../scripts/llm_sec_weekly_fetcher';
import { getThreatReportsBaseFolder } from '../threat-reports/config';
import type { gmail_v1 } from '@googleapis/gmail';

const ARCHIVE_DIR = '/tmp/vault/Permanent Note/10_Threat_Reports/raw';

function base64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

export async function run(): Promise<TestSuiteResult> {
  const t = new TestRunner();

  t.section('PERIOD_END_RE / isSafePeriodEnd');

  t.test('正常な YYYY-MM-DD は通る', () => {
    assert.strictEqual(isSafePeriodEnd('2026-05-25'), true);
  });

  t.test('null は弾く', () => {
    assert.strictEqual(isSafePeriodEnd(null), false);
  });

  t.test('path-traversal (../../../etc/passwd) は弾く', () => {
    assert.strictEqual(isSafePeriodEnd('../../../etc/passwd'), false);
  });

  t.test('前後空白付きは弾く (sanitize は抽出側責務にしない)', () => {
    assert.strictEqual(isSafePeriodEnd(' 2026-05-25 '), false);
  });

  t.test('1 桁月日 (2026-5-25) は弾く', () => {
    assert.strictEqual(isSafePeriodEnd('2026-5-25'), false);
  });

  t.test('日付以外の文字混入 (2026-05-25; rm -rf /) は弾く', () => {
    assert.strictEqual(isSafePeriodEnd('2026-05-25; rm -rf /'), false);
    assert.strictEqual(isSafePeriodEnd('2026-05-25\n#injection'), false);
  });

  t.section('extractPeriodEnd (frontmatter parser)');

  t.test('標準的な frontmatter から抽出', () => {
    const body = [
      '---',
      'report_type: llm_security_weekly',
      'period_end: 2026-05-25',
      'schema_version: 1',
      '---',
      'body',
    ].join('\n');
    assert.strictEqual(extractPeriodEnd(body), '2026-05-25');
  });

  t.test('引用符付き値も剥がす', () => {
    const body = ['---', 'period_end: "2026-05-25"', '---'].join('\n');
    assert.strictEqual(extractPeriodEnd(body), '2026-05-25');
    const body2 = ['---', "period_end: '2026-05-25'", '---'].join('\n');
    assert.strictEqual(extractPeriodEnd(body2), '2026-05-25');
  });

  t.test('frontmatter が無いと null', () => {
    assert.strictEqual(extractPeriodEnd('no frontmatter here'), null);
  });

  t.test('frontmatter 内に period_end が無いと null', () => {
    const body = ['---', 'report_type: foo', '---'].join('\n');
    assert.strictEqual(extractPeriodEnd(body), null);
  });

  t.test('frontmatter 外の period_end は無視 (本文偽装防御)', () => {
    const body = ['---', 'schema_version: 1', '---', 'period_end: 2026-05-25'].join('\n');
    assert.strictEqual(extractPeriodEnd(body), null);
  });

  t.test('インジェクションを含む period_end も抽出 (=その後 isSafePeriodEnd で弾く設計)', () => {
    const body = ['---', 'period_end: 2026-05-25; rm -rf /', '---'].join('\n');
    // 抽出は通っても、後続の isSafePeriodEnd で弾かれることを担保
    const v = extractPeriodEnd(body);
    assert.strictEqual(v, '2026-05-25; rm -rf /');
    assert.strictEqual(isSafePeriodEnd(v), false);
  });

  t.section('isSafeRawPath (path traversal 二重防御)');

  t.test('archive 直下の <date>.md は OK', () => {
    assert.strictEqual(isSafeRawPath(`${ARCHIVE_DIR}/2026-05-25.md`, ARCHIVE_DIR), true);
  });

  t.test('archive の親に書こうとすると NG', () => {
    assert.strictEqual(
      isSafeRawPath(`${ARCHIVE_DIR}/../escape.md`, ARCHIVE_DIR),
      false
    );
  });

  t.test('archive 配下のサブディレクトリは NG (フラット運用前提)', () => {
    assert.strictEqual(
      isSafeRawPath(`${ARCHIVE_DIR}/sub/2026-05-25.md`, ARCHIVE_DIR),
      false
    );
  });

  t.test('.md 以外の拡張子は NG', () => {
    assert.strictEqual(
      isSafeRawPath(`${ARCHIVE_DIR}/2026-05-25.sh`, ARCHIVE_DIR),
      false
    );
  });

  t.section('extractPlainTextBody (Gmail multipart 走査)');

  t.test('単一 text/plain payload', () => {
    const msg: gmail_v1.Schema$Message = {
      payload: {
        mimeType: 'text/plain',
        body: { data: base64url('hello') },
      },
    };
    assert.strictEqual(extractPlainTextBody(msg), 'hello');
  });

  t.test('multipart/alternative の text/plain part を選ぶ', () => {
    const msg: gmail_v1.Schema$Message = {
      payload: {
        mimeType: 'multipart/alternative',
        parts: [
          { mimeType: 'text/html', body: { data: base64url('<p>html</p>') } },
          { mimeType: 'text/plain', body: { data: base64url('plain') } },
        ],
      },
    };
    assert.strictEqual(extractPlainTextBody(msg), 'plain');
  });

  t.test('text/plain が無いと null (= HTML のみのメールは弾く)', () => {
    const msg: gmail_v1.Schema$Message = {
      payload: {
        mimeType: 'text/html',
        body: { data: base64url('<p>only html</p>') },
      },
    };
    assert.strictEqual(extractPlainTextBody(msg), null);
  });

  t.test('payload なしの message は null', () => {
    assert.strictEqual(extractPlainTextBody({}), null);
  });

  t.test('深くネストされた text/plain も拾う', () => {
    const msg: gmail_v1.Schema$Message = {
      payload: {
        mimeType: 'multipart/mixed',
        parts: [
          {
            mimeType: 'multipart/related',
            parts: [
              {
                mimeType: 'multipart/alternative',
                parts: [
                  { mimeType: 'text/html', body: { data: base64url('html') } },
                  { mimeType: 'text/plain', body: { data: base64url('deep plain') } },
                ],
              },
            ],
          },
        ],
      },
    };
    assert.strictEqual(extractPlainTextBody(msg), 'deep plain');
  });

  t.section('envOrUndefined (空文字 secret injection 防御)');

  t.test('未設定環境変数は undefined', () => {
    delete process.env.__TEST_LLM_SEC_VAR;
    assert.strictEqual(envOrUndefined('__TEST_LLM_SEC_VAR'), undefined);
  });

  t.test('空文字は undefined に正規化 (Actions の未設定 secret injection)', () => {
    process.env.__TEST_LLM_SEC_VAR = '';
    assert.strictEqual(envOrUndefined('__TEST_LLM_SEC_VAR'), undefined);
    delete process.env.__TEST_LLM_SEC_VAR;
  });

  t.test('非空文字はそのまま返る', () => {
    process.env.__TEST_LLM_SEC_VAR = 'hello';
    assert.strictEqual(envOrUndefined('__TEST_LLM_SEC_VAR'), 'hello');
    delete process.env.__TEST_LLM_SEC_VAR;
  });

  t.section('PERIOD_END_RE 形式');

  t.test('正規表現がエクスポートされている', () => {
    assert.ok(PERIOD_END_RE instanceof RegExp);
    assert.ok(PERIOD_END_RE.test('2026-05-25'));
    assert.ok(!PERIOD_END_RE.test('not a date'));
  });

  // -------------------------------------------------------------------
  // pending-labels.json (フェーズ 1 ⇄ フェーズ 2 の橋渡し)
  //
  // ここが label-before-push race の解消経路。
  // フェーズ 1 が成功 thread を JSON に書き、push 後にフェーズ 2 が読み出して
  // label する。push 失敗時は label しない (= 永久 skip 回避)。
  // -------------------------------------------------------------------
  t.section('buildPendingLabels (ingested + periodEnd 有り だけ抽出)');

  t.test('ingested だけ、periodEnd 必須', () => {
    const outcomes: FetcherOutcome[] = [
      { threadId: 't1', messageId: 'm1', periodEnd: '2026-05-25', status: 'ingested' },
      { threadId: 't2', messageId: 'm2', periodEnd: '2026-05-18', status: 'error', reason: 'x' },
      { threadId: 't3', messageId: 'm3', periodEnd: null, status: 'skipped', reason: 'y' },
      // 防御的: ingested なのに periodEnd null (理論的には起きないが) は除外
      { threadId: 't4', messageId: 'm4', periodEnd: null, status: 'ingested' },
      { threadId: 't5', messageId: 'm5', periodEnd: '2026-05-11', status: 'ingested' },
    ];
    const pending = buildPendingLabels(outcomes);
    assert.deepStrictEqual(pending, [
      { threadId: 't1', periodEnd: '2026-05-25', messageId: 'm1' },
      { threadId: 't5', periodEnd: '2026-05-11', messageId: 'm5' },
    ]);
  });

  t.test('全件 error/skipped なら空配列', () => {
    const outcomes: FetcherOutcome[] = [
      { threadId: 't1', messageId: 'm1', periodEnd: '2026-05-25', status: 'error', reason: 'x' },
      { threadId: 't2', messageId: 'm2', periodEnd: null, status: 'skipped', reason: 'y' },
    ];
    assert.deepStrictEqual(buildPendingLabels(outcomes), []);
  });

  t.section('writePendingLabels / readPendingLabels (atomic 書込 + 空時は削除)');

  function tmpFile(): string {
    return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sec-weekly-')), 'pending.json');
  }

  t.test('threads >= 1 件: ファイル書き出し、読み戻しで等価', () => {
    const fp = tmpFile();
    const threads: PendingLabel[] = [
      { threadId: 't1', periodEnd: '2026-05-25', messageId: 'm1' },
      { threadId: 't2', periodEnd: '2026-05-18', messageId: 'm2' },
    ];
    writePendingLabels(fp, threads);
    assert.ok(fs.existsSync(fp), 'ファイルが作られる');
    const back = readPendingLabels(fp);
    assert.deepStrictEqual(back, threads);
  });

  t.test('空配列: 既存ファイルがあれば削除される (= phase 2 は no-op)', () => {
    const fp = tmpFile();
    writePendingLabels(fp, [{ threadId: 't1', periodEnd: '2026-05-25', messageId: 'm1' }]);
    assert.ok(fs.existsSync(fp));
    writePendingLabels(fp, []);
    assert.strictEqual(fs.existsSync(fp), false);
  });

  t.test('空配列 + ファイル不在: 何もしない (エラーも起きない)', () => {
    const fp = tmpFile();
    assert.strictEqual(fs.existsSync(fp), false);
    writePendingLabels(fp, []);
    assert.strictEqual(fs.existsSync(fp), false);
  });

  t.test('readPendingLabels: ファイル不在は空配列', () => {
    const fp = tmpFile();
    assert.deepStrictEqual(readPendingLabels(fp), []);
  });

  t.test('readPendingLabels: 不正な JSON (threads が無い) は throw', () => {
    const fp = tmpFile();
    fs.writeFileSync(fp, JSON.stringify({ written_at: 'now' }), 'utf8');
    assert.throws(() => readPendingLabels(fp), /threads.*配列がない/);
  });

  t.test('readPendingLabels: 一部 entry が壊れていたら有効分だけ返す', () => {
    const fp = tmpFile();
    fs.writeFileSync(
      fp,
      JSON.stringify({
        written_at: 'now',
        threads: [
          { threadId: 't1', periodEnd: '2026-05-25', messageId: 'm1' },
          { threadId: 't2', periodEnd: 123, messageId: 'm2' }, // periodEnd 型違い
          { threadId: null, periodEnd: '2026-05-18', messageId: 'm3' }, // threadId 型違い
          'not-an-object',
        ],
      }),
      'utf8'
    );
    const back = readPendingLabels(fp);
    assert.deepStrictEqual(back, [{ threadId: 't1', periodEnd: '2026-05-25', messageId: 'm1' }]);
  });

  // -------------------------------------------------------------------
  // インジェクション・ゲートのルーティング (ingest 前段)
  //
  // ゲート本体 (L1+L3) の判定ロジックは python の決定論テスト
  // (.claude/skills/scan-threat-report/tests/run_gate_tests.py) が担う。
  // ここでは fetcher 側の配線 = 「clean は ingest へ / non-clean は
  // _quarantine/ へ退避して継続 / 実行失敗は fail-closed で隔離」だけを
  // stub GateRunner で検証する。
  // -------------------------------------------------------------------
  t.section('gateAndRoute (clean=ingest / non-clean=隔離 / fail-closed)');

  function gateFixture(): { rawPath: string; quarantineDir: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-gate-'));
    const rawPath = path.join(dir, 'raw', '2026-06-08.md');
    fs.mkdirSync(path.dirname(rawPath), { recursive: true });
    fs.writeFileSync(rawPath, 'body', 'utf8');
    return { rawPath, quarantineDir: path.join(dir, '_quarantine') };
  }

  t.test('clean → action=ingest、raw はその場に残る', () => {
    const { rawPath, quarantineDir } = gateFixture();
    const gate: GateRunner = () => ({ verdict: 'clean', detail: '' });
    const out = gateAndRoute(rawPath, quarantineDir, gate);
    assert.deepStrictEqual(out, { action: 'ingest' });
    assert.ok(fs.existsSync(rawPath), 'raw が残る');
    assert.strictEqual(fs.existsSync(quarantineDir), false);
  });

  t.test('suspicious → 隔離へ移動 + verdict/detail を返す (バッチは継続できる)', () => {
    const { rawPath, quarantineDir } = gateFixture();
    const gate: GateRunner = () => ({ verdict: 'suspicious', detail: 'final_rule=l1-multiline-demoted' });
    const out = gateAndRoute(rawPath, quarantineDir, gate);
    assert.deepStrictEqual(out, {
      action: 'quarantine',
      verdict: 'suspicious',
      detail: 'final_rule=l1-multiline-demoted',
      quarantinedPath: path.join(quarantineDir, '2026-06-08.md'),
    });
    assert.strictEqual(fs.existsSync(rawPath), false, 'raw は残らない');
    assert.ok(fs.existsSync(path.join(quarantineDir, '2026-06-08.md')), '隔離先へ移動');
  });

  t.test('blocked → 同様に隔離', () => {
    const { rawPath, quarantineDir } = gateFixture();
    const gate: GateRunner = () => ({ verdict: 'blocked', detail: 'final_rule=l0-contract' });
    const out = gateAndRoute(rawPath, quarantineDir, gate);
    assert.strictEqual(out.action, 'quarantine');
    assert.ok(fs.existsSync(path.join(quarantineDir, '2026-06-08.md')));
  });

  t.test('ゲート実行失敗 (verdict=error) は fail-closed で隔離 (素通りさせない)', () => {
    const { rawPath, quarantineDir } = gateFixture();
    const gate: GateRunner = () => ({ verdict: 'error', detail: 'L1 scanner 実行失敗: spawn python3 ENOENT' });
    const out = gateAndRoute(rawPath, quarantineDir, gate);
    assert.strictEqual(out.action, 'quarantine');
    assert.strictEqual(fs.existsSync(rawPath), false);
  });

  // -------------------------------------------------------------------
  // 再取込ループ防止ガード (sc-1 回帰)
  //
  // ガードのキーは **原本 thread の同一性 (source_ref)**。period_end で
  // skip すると、untrusted 本文が名乗るだけの値で「その週」を恒久的に
  // 塞げてしまう (しかも skipped = 成功扱いで CI は緑のまま)。
  // -------------------------------------------------------------------
  t.section('readQuarantinePendingSourceRefs (再取込ループ防止ガード)');

  function queuePath(vaultRoot: string): string {
    return path.join(vaultRoot, getThreatReportsBaseFolder(), GATE_SUBDIR, 'quarantine_queue.json');
  }

  function vaultWithQueue(items: unknown[] | null): string {
    const vaultRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-vault-'));
    if (items !== null) {
      fs.mkdirSync(path.dirname(queuePath(vaultRoot)), { recursive: true });
      fs.writeFileSync(
        queuePath(vaultRoot),
        JSON.stringify({ schema: QUARANTINE_QUEUE_SCHEMA, items }),
        'utf8'
      );
    }
    return vaultRoot;
  }

  t.test('pending の source_ref だけを返す (裁定済みは対象外)', () => {
    const vaultRoot = vaultWithQueue([
      { period_end: '2026-06-08', source_ref: 'gmail:t1', status: 'pending' },
      { period_end: '2026-06-01', source_ref: 'gmail:t2', status: 'ingested' },
      { period_end: '2026-05-25', source_ref: 'gmail:t3', status: 'rejected' },
      { period_end: '2026-06-15', source_ref: 123, status: 'pending' }, // 型違いは無視
    ]);
    assert.deepStrictEqual(readQuarantinePendingSourceRefs(vaultRoot), new Set(['gmail:t1']));
  });

  t.test('source_ref の fragment は落として thread 同一性で突き合わせる', () => {
    const vaultRoot = vaultWithQueue([
      { period_end: '2026-06-08', source_ref: 'gmail:t1#text-plain-of-2,msg=m9', status: 'pending' },
    ]);
    const pending = readQuarantinePendingSourceRefs(vaultRoot);
    assert.ok(pending.has(threadSourceRef('t1')));
  });

  t.test('sc-1: 未来の週を騙る隔離 pending は別 thread の正規レポートを塞がない', () => {
    // 攻撃者が「未来の月曜」を名乗る non-clean メールを送り隔離させたケース。
    const vaultRoot = vaultWithQueue([
      { period_end: '2026-12-28', source_ref: 'gmail:tPOISON', status: 'pending' },
      { period_end: '2027-01-04', source_ref: 'gmail:tPOISON2', status: 'pending' },
    ]);
    const pending = readQuarantinePendingSourceRefs(vaultRoot);
    // 塞がれるのは隔離された thread 自身だけ。
    assert.ok(pending.has(threadSourceRef('tPOISON')));
    assert.strictEqual(pending.has(threadSourceRef('tGENUINE')), false);
    // period_end はガードのキーではない (週単位の恒久 skip を作らない)。
    assert.strictEqual(pending.has('2026-12-28'), false);
  });

  t.test('キューが無ければ空 Set (ゲート自体は毎回走るので安全側)', () => {
    const vaultRoot = vaultWithQueue(null);
    assert.deepStrictEqual(readQuarantinePendingSourceRefs(vaultRoot), new Set());
  });

  t.test('キューが壊れた JSON でも throw せず空 Set', () => {
    const vaultRoot = vaultWithQueue(null);
    fs.mkdirSync(path.dirname(queuePath(vaultRoot)), { recursive: true });
    fs.writeFileSync(queuePath(vaultRoot), '{not json', 'utf8');
    assert.deepStrictEqual(readQuarantinePendingSourceRefs(vaultRoot), new Set());
  });

  t.section('isPeriodEndTooFarInFuture (未来の週を騙る period_end の多層防御)');

  const NOW = new Date('2026-06-08T00:00:00Z');

  t.test('当週・過去は通す', () => {
    assert.strictEqual(isPeriodEndTooFarInFuture('2026-06-08', NOW), false);
    assert.strictEqual(isPeriodEndTooFarInFuture('2026-05-25', NOW), false);
  });

  t.test(`+${PERIOD_END_FUTURE_HORIZON_DAYS} 日までは通し、それを超えたら弾く`, () => {
    assert.strictEqual(isPeriodEndTooFarInFuture('2026-06-22', NOW), false); // +14d
    assert.strictEqual(isPeriodEndTooFarInFuture('2026-06-29', NOW), true); // +21d
    assert.strictEqual(isPeriodEndTooFarInFuture('2026-12-28', NOW), true);
  });

  t.test('形式は正しいが実在しない日付も弾く (2026-02-31)', () => {
    assert.strictEqual(isPeriodEndTooFarInFuture('2026-02-31', NOW), true);
  });

  // -------------------------------------------------------------------
  // 隔離キューへの fetcher 側追記 (sc-3 回帰)
  //
  // gate_decision.py の queue_add は suspicious/blocked のときだけ走るため、
  // verdict=error (exit 4 / spawn 失敗 / timeout) はキューに 1 件も載らない。
  // 載らないと裁定対象から漏れ、ガードも噛まず毎 run 隔離を繰り返す。
  // -------------------------------------------------------------------
  // -------------------------------------------------------------------
  // ★ #143 Codex P1: ingest が ContractError で落ちても raw/ には昇格済みの
  // 本文が残っていた。llm-sec-weekly.yml は `git add -f .../raw/` で commit/push
  // するので不正本文が正典として確定し、terminal ラベルで原本は取り直されない。
  // 訂正版が後から届いても promoteStagedRaw が `conflict` を返して恒久的に
  // 隔離され続ける。
  // -------------------------------------------------------------------
  t.section('discardFailedPromotion (ingest 失敗時に raw/ を残さない)');

  function rawWith(vaultRoot: string, body: string): string {
    const rawPath = path.join(vaultRoot, 'raw', '2026-06-08.md');
    fs.mkdirSync(path.dirname(rawPath), { recursive: true });
    fs.writeFileSync(rawPath, body, 'utf8');
    return rawPath;
  }

  t.test('promoted なら raw/ から退避し、キューに載せる', () => {
    const vaultRoot = vaultWithQueue(null);
    const rawPath = rawWith(vaultRoot, '不正な本文');
    const quarantineDir = path.join(vaultRoot, '_quarantine');
    const r = discardFailedPromotion({
      promotion: 'promoted', rawPath, quarantineDir,
      queuePath: queuePath(vaultRoot),
      periodEnd: '2026-06-08', sourceRef: 'gmail:t1', reason: '契約違反: テスト',
    });
    assert.strictEqual(r, 'quarantined');
    assert.strictEqual(fs.existsSync(rawPath), false, 'raw/ に残ってはいけない');
    assert.strictEqual(fs.readFileSync(path.join(quarantineDir, '2026-06-08.md'), 'utf8'), '不正な本文');
    const items = JSON.parse(fs.readFileSync(queuePath(vaultRoot), 'utf8')).items;
    assert.strictEqual(items.length, 1);
    assert.strictEqual(items[0].verdict, 'error');
  });

  t.test('退避後は訂正版が conflict にならず昇格できる (P1 の実害の解消)', () => {
    const vaultRoot = vaultWithQueue(null);
    const rawPath = rawWith(vaultRoot, '不正な本文');
    discardFailedPromotion({
      promotion: 'promoted', rawPath, quarantineDir: path.join(vaultRoot, '_quarantine'),
      queuePath: queuePath(vaultRoot), periodEnd: '2026-06-08',
      sourceRef: 'gmail:t1', reason: '契約違反: テスト',
    });
    const staged = path.join(vaultRoot, 'staged.md');
    fs.writeFileSync(staged, '訂正版の本文', 'utf8');
    assert.strictEqual(promoteStagedRaw(staged, rawPath), 'promoted');
  });

  t.test('identical は【この run の産物ではない】ので触らない', () => {
    const vaultRoot = vaultWithQueue(null);
    const rawPath = rawWith(vaultRoot, '既存の正しい本文');
    const r = discardFailedPromotion({
      promotion: 'identical', rawPath, quarantineDir: path.join(vaultRoot, '_quarantine'),
      queuePath: queuePath(vaultRoot), periodEnd: '2026-06-08',
      sourceRef: 'gmail:t1', reason: '契約違反: テスト',
    });
    assert.strictEqual(r, 'skipped');
    assert.strictEqual(fs.readFileSync(rawPath, 'utf8'), '既存の正しい本文');
    assert.strictEqual(fs.existsSync(queuePath(vaultRoot)), false, 'キューにも載せない');
  });

  t.section('appendQuarantineQueueEntry (error 判定をキューに可視化)');

  function fetcherEntry(overrides: Partial<Parameters<typeof appendQuarantineQueueEntry>[1]> = {}) {
    return {
      periodEnd: '2026-06-08',
      file: '/tmp/_quarantine/2026-06-08.md',
      sourceRef: 'gmail:t1',
      verdict: 'error',
      reason: 'L1 scanner 実行失敗: spawn python3 ENOENT',
      ...overrides,
    };
  }

  t.test('キュー未作成でも作られ、pending として guard に効く', () => {
    const vaultRoot = vaultWithQueue(null);
    assert.strictEqual(appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry()), true);
    const written = JSON.parse(fs.readFileSync(queuePath(vaultRoot), 'utf8'));
    assert.strictEqual(written.schema, QUARANTINE_QUEUE_SCHEMA);
    assert.strictEqual(written.items.length, 1);
    assert.strictEqual(written.items[0].status, 'pending');
    assert.strictEqual(written.items[0].verdict, 'error');
    // 追記した瞬間からガードが噛む = 翌 run で同じ thread を再隔離しない。
    assert.ok(readQuarantinePendingSourceRefs(vaultRoot).has(threadSourceRef('t1')));
  });

  // ★ #143 Codex P2: 秒精度の時刻だけでは id が衝突する。同じ period_end を
  // 名乗る別スレッドが同一 run で積まれると decision_id が一致し、queue_id は
  // 下 4 桁 (分秒) しか使わないので時刻が違っても衝突する。衝突すると
  // gate_decision.py の `queue --resolve` が曖昧になり裁定できない。
  t.test('同じ週を名乗る別原本は queue_id / decision_id が衝突しない', () => {
    const vaultRoot = vaultWithQueue(null);
    assert.strictEqual(
      appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry({ sourceRef: 'gmail:tA' })), true);
    assert.strictEqual(
      appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry({ sourceRef: 'gmail:tB' })), true);
    const items = JSON.parse(fs.readFileSync(queuePath(vaultRoot), 'utf8')).items;
    assert.strictEqual(items.length, 2);
    assert.notStrictEqual(items[0].queue_id, items[1].queue_id);
    assert.notStrictEqual(items[0].decision_id, items[1].decision_id);
    // gate_decision.py と同じ規約: queue_id の末尾 4 桁 = decision_id の末尾 4 桁。
    assert.ok(String(items[0].queue_id).endsWith(String(items[0].decision_id).slice(-4)));
  });

  t.test('判別子は時刻ではなく原本で決まる (同じ原本なら同じ末尾)', () => {
    const a = vaultWithQueue(null);
    const b = vaultWithQueue(null);
    appendQuarantineQueueEntry(queuePath(a), fetcherEntry({ sourceRef: 'gmail:tA' }));
    appendQuarantineQueueEntry(queuePath(b), fetcherEntry({ sourceRef: 'gmail:tA#text-plain-of-2' }));
    const ia = JSON.parse(fs.readFileSync(queuePath(a), 'utf8')).items[0];
    const ib = JSON.parse(fs.readFileSync(queuePath(b), 'utf8')).items[0];
    // fragment は原本の同一性に含めない = 同じ thread なら同じ判別子。
    assert.strictEqual(String(ia.decision_id).slice(-4), String(ib.decision_id).slice(-4));
  });

  t.test('同じ原本が pending のままなら二重登録しない (idempotent)', () => {
    const vaultRoot = vaultWithQueue(null);
    assert.strictEqual(appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry()), true);
    assert.strictEqual(
      appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry({ sourceRef: 'gmail:t1#text-plain-of-2' })),
      false
    );
    assert.strictEqual(JSON.parse(fs.readFileSync(queuePath(vaultRoot), 'utf8')).items.length, 1);
  });

  t.test('既存エントリは保持したまま追記する', () => {
    const vaultRoot = vaultWithQueue([
      { period_end: '2026-06-01', source_ref: 'gmail:t0', status: 'pending' },
    ]);
    assert.strictEqual(appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry()), true);
    const items = JSON.parse(fs.readFileSync(queuePath(vaultRoot), 'utf8')).items;
    assert.strictEqual(items.length, 2);
    assert.strictEqual(items[0].source_ref, 'gmail:t0');
  });

  t.test('schema が違うキューは上書きしない (人手データを壊さない)', () => {
    const vaultRoot = vaultWithQueue(null);
    fs.mkdirSync(path.dirname(queuePath(vaultRoot)), { recursive: true });
    fs.writeFileSync(queuePath(vaultRoot), JSON.stringify({ schema: 'other@9', items: [] }), 'utf8');
    assert.strictEqual(appendQuarantineQueueEntry(queuePath(vaultRoot), fetcherEntry()), false);
    assert.strictEqual(
      JSON.parse(fs.readFileSync(queuePath(vaultRoot), 'utf8')).schema, 'other@9');
  });

  // -------------------------------------------------------------------
  // staging → raw/ 昇格 (sc-3 回帰)
  //
  // raw/ に直接書いてからゲートすると、隔離判定の rename が既存 archive を
  // 削除し、workflow の `git add -f raw/` がその削除を stage して push する
  // (= メール 1 通で過去の正規レポートを消せる)。
  // -------------------------------------------------------------------
  t.section('promoteStagedRaw (clean のみ raw/ へ昇格 / 既存は上書きしない)');

  function stagingFixture(rawContent: string | null): { stagedPath: string; rawPath: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-stage-'));
    const stagedPath = path.join(dir, '_staging', '2026-06-08.md');
    const rawPath = path.join(dir, 'raw', '2026-06-08.md');
    fs.mkdirSync(path.dirname(stagedPath), { recursive: true });
    fs.writeFileSync(stagedPath, 'new body', 'utf8');
    if (rawContent !== null) {
      fs.mkdirSync(path.dirname(rawPath), { recursive: true });
      fs.writeFileSync(rawPath, rawContent, 'utf8');
    }
    return { stagedPath, rawPath };
  }

  t.test('既存なし → promoted (raw/ に移動、staging は空になる)', () => {
    const { stagedPath, rawPath } = stagingFixture(null);
    assert.strictEqual(promoteStagedRaw(stagedPath, rawPath), 'promoted');
    assert.strictEqual(fs.readFileSync(rawPath, 'utf8'), 'new body');
    assert.strictEqual(fs.existsSync(stagedPath), false);
  });

  t.test('既存と同一内容 → identical (再取込の self-healing 経路を壊さない)', () => {
    const { stagedPath, rawPath } = stagingFixture('new body');
    assert.strictEqual(promoteStagedRaw(stagedPath, rawPath), 'identical');
    assert.strictEqual(fs.readFileSync(rawPath, 'utf8'), 'new body');
    assert.strictEqual(fs.existsSync(stagedPath), false);
  });

  t.test('sc-3: 既存と内容が違う → conflict。既存 raw を上書きも削除もしない', () => {
    const { stagedPath, rawPath } = stagingFixture('archived genuine report');
    assert.strictEqual(promoteStagedRaw(stagedPath, rawPath), 'conflict');
    assert.strictEqual(fs.readFileSync(rawPath, 'utf8'), 'archived genuine report');
    assert.ok(fs.existsSync(stagedPath), 'staging は呼び出し側が隔離へ回す');
  });

  t.test('sc-3: non-clean 判定は staging だけを動かし、既存 raw に触らない', () => {
    const { stagedPath, rawPath } = stagingFixture('archived genuine report');
    const quarantineDir = path.join(path.dirname(path.dirname(stagedPath)), '_quarantine');
    const gate: GateRunner = () => ({ verdict: 'blocked', detail: 'final_rule=l0-contract' });
    const out = gateAndRoute(stagedPath, quarantineDir, gate);
    assert.strictEqual(out.action, 'quarantine');
    // 既存 archive は無傷 (以前は rawPath 自体が隔離先へ rename されていた)。
    assert.strictEqual(fs.readFileSync(rawPath, 'utf8'), 'archived genuine report');
    assert.ok(fs.existsSync(path.join(quarantineDir, '2026-06-08.md')));
  });

  t.test('quarantineBody: 同名が既にあれば連番で退避 (先行の証拠を消さない)', () => {
    const { stagedPath } = stagingFixture(null);
    const quarantineDir = path.join(path.dirname(path.dirname(stagedPath)), '_quarantine');
    const first = quarantineBody(stagedPath, quarantineDir);
    fs.writeFileSync(stagedPath, 'second body', 'utf8');
    const second = quarantineBody(stagedPath, quarantineDir);
    assert.notStrictEqual(first, second);
    assert.strictEqual(fs.readFileSync(first, 'utf8'), 'new body');
    assert.strictEqual(fs.readFileSync(second, 'utf8'), 'second body');
  });

  // -------------------------------------------------------------------
  // 1 件の恒久エラーで run 全体を落とさない (sc-2 回帰)
  //
  // exit 1 にすると後続 step が success() 条件で丸ごと skip され、
  // 取り込めた健全なレポートまで runner ごと破棄される。代わりに
  // (a) terminal な失敗はラベルを付けて終端させ、(b) ::error:: 注釈で可視化する。
  // -------------------------------------------------------------------
  t.section('sc-2: terminal な失敗の終端化と ::error:: 注釈');

  t.test('terminal な error は pending-labels に積む (窓を永久占有させない)', () => {
    const outcomes: FetcherOutcome[] = [
      { threadId: 't1', messageId: 'm1', periodEnd: '2026-06-08', status: 'ingested' },
      // 決定論的失敗 = 再試行しても同じ → ラベルを付けて打ち切る
      { threadId: 't2', messageId: 'm2', periodEnd: null, status: 'error', terminal: true, reason: 'text/plain part が見つからない' },
      // 一過性の失敗 = 次回 cron で再試行したいので積まない
      { threadId: 't3', messageId: 'm3', periodEnd: '2026-06-01', status: 'error', reason: 'EBUSY' },
      // 隔離は人間の裁定後に再取込したいので積まない
      { threadId: 't4', messageId: 'm4', periodEnd: '2026-05-25', status: 'quarantined', reason: 'ゲート blocked' },
    ];
    assert.deepStrictEqual(buildPendingLabels(outcomes), [
      { threadId: 't1', periodEnd: '2026-06-08', messageId: 'm1' },
      { threadId: 't2', periodEnd: 'unknown', messageId: 'm2' },
    ]);
  });

  t.test('printSummary は error を ::error:: 注釈で出す (CI に見える形で劣化させる)', () => {
    const lines: string[] = [];
    const origError = console.error;
    const origWarn = console.warn;
    const origLog = console.log;
    console.error = (...a: unknown[]) => { lines.push(a.join(' ')); };
    console.warn = (...a: unknown[]) => { lines.push(a.join(' ')); };
    console.log = () => { /* サマリ本体は検証対象外 */ };
    try {
      printSummary([
        { threadId: 't2', messageId: 'm2', periodEnd: null, status: 'error', terminal: true, reason: 'text/plain part が見つからない' },
        { threadId: 't4', messageId: 'm4', periodEnd: '2026-05-25', status: 'quarantined', sourceRef: 'gmail:t4', reason: 'ゲート blocked' },
      ]);
    } finally {
      console.error = origError;
      console.warn = origWarn;
      console.log = origLog;
    }
    assert.ok(lines.some(l => l.startsWith('::error::') && l.includes('t2')), 'error は ::error:: 注釈');
    assert.ok(lines.some(l => l.startsWith('::warning::') && l.includes('t4')), '隔離は ::warning:: 注釈');
  });

  // -------------------------------------------------------------------
  // message 単位の選別 / source_ref (sc-6 / sc-7)
  // -------------------------------------------------------------------
  t.section('selectReportMessages / buildSourceRef');

  function msgWithSubject(id: string, subject: string): gmail_v1.Schema$Message {
    return {
      id,
      payload: {
        mimeType: 'text/plain',
        headers: [{ name: 'Subject', value: subject }],
        body: { data: base64url('body') },
      },
    };
  }

  t.test('Subject 前置詞を持たない message は対象外 (thread 単位ヒットの取りこぼし防止)', () => {
    const thread: gmail_v1.Schema$Thread = {
      messages: [
        msgWithSubject('m1', 'Re: 雑談'),
        msgWithSubject('m2', '[LLM-Sec-Weekly] 2026-06-08'),
      ],
    };
    assert.deepStrictEqual(selectReportMessages(thread).map(m => m.id), ['m2']);
  });

  t.test('同一 thread に複数のレポートがあれば全件返す (2 通目の恒久 skip 防止)', () => {
    const thread: gmail_v1.Schema$Thread = {
      messages: [
        msgWithSubject('m1', '[LLM-Sec-Weekly] 2026-06-01'),
        msgWithSubject('m2', '[LLM-Sec-Weekly] 2026-06-08'),
      ],
    };
    assert.deepStrictEqual(selectReportMessages(thread).map(m => m.id), ['m1', 'm2']);
  });

  t.test('Subject ヘッダの取り出しは大文字小文字を問わない', () => {
    assert.strictEqual(
      extractSubject({ payload: { headers: [{ name: 'subject', value: 'x' }] } }),
      'x'
    );
    assert.strictEqual(extractSubject({}), null);
  });

  t.test('extractBodyParts: text/html 兄弟の存在を報告する (裁定者の原本照合用)', () => {
    const msg: gmail_v1.Schema$Message = {
      payload: {
        mimeType: 'multipart/alternative',
        parts: [
          { mimeType: 'text/html', body: { data: base64url('<p>html</p>') } },
          { mimeType: 'text/plain', body: { data: base64url('plain') } },
        ],
      },
    };
    assert.deepStrictEqual(extractBodyParts(msg), {
      plain: 'plain',
      hasHtml: true,
      bodyPartCount: 2,
    });
  });

  t.test('buildSourceRef: 単一 part / 単一 message なら base のまま', () => {
    assert.strictEqual(buildSourceRef('t1', 'm1', 1, 1), 'gmail:t1');
  });

  t.test('buildSourceRef: 乖離しうる場合だけ fragment を足す (guard の比較キーは不変)', () => {
    assert.strictEqual(buildSourceRef('t1', 'm1', 2, 1), 'gmail:t1#text-plain-of-2');
    assert.strictEqual(buildSourceRef('t1', 'm9', 2, 2), 'gmail:t1#text-plain-of-2,msg=m9');
    assert.strictEqual(buildSourceRef('t1', 'm9', 1, 2), 'gmail:t1#msg=m9');
  });

  t.section('isInvalidGrantError (OAuth refresh 失敗の検出)');

  t.test('GaxiosError の response.data.error=invalid_grant を検出', () => {
    assert.strictEqual(
      isInvalidGrantError({ response: { data: { error: 'invalid_grant' } } }),
      true
    );
  });

  t.test('message に invalid_grant を含む error を検出', () => {
    assert.strictEqual(isInvalidGrantError(new Error('invalid_grant')), true);
  });

  t.test('別の OAuth error (invalid_client) は誤検出しない', () => {
    assert.strictEqual(
      isInvalidGrantError({ response: { data: { error: 'invalid_client' } } }),
      false
    );
    assert.strictEqual(isInvalidGrantError(new Error('Not Found')), false);
  });

  t.test('null / 非 error でも throw せず false', () => {
    assert.strictEqual(isInvalidGrantError(null), false);
    assert.strictEqual(isInvalidGrantError(undefined), false);
    assert.strictEqual(isInvalidGrantError('invalid_grant'), false);
  });

  t.section('withOAuthErrorHint (invalid_grant 翻訳)');

  await t.testAsync('invalid_grant を実行可能メッセージに翻訳し cause を保持', async () => {
    const original = new Error('invalid_grant');
    await assert.rejects(
      () => withOAuthErrorHint(async () => { throw original; }),
      (e: unknown) => {
        assert.ok(e instanceof Error);
        assert.notStrictEqual(e, original); // 別 Error に翻訳されている
        assert.strictEqual(e.cause, original); // 元 error は cause で保持
        assert.match(e.message, /refresh token/); // 実行可能な復旧メッセージ
        return true;
      }
    );
  });

  await t.testAsync('非 invalid_grant error はそのまま透過 (翻訳しない)', async () => {
    const original = new Error('Not Found');
    await assert.rejects(
      () => withOAuthErrorHint(async () => { throw original; }),
      (e: unknown) => e === original
    );
  });

  await t.testAsync('成功時は戻り値をそのまま返す', async () => {
    assert.strictEqual(await withOAuthErrorHint(async () => 42), 42);
  });

  return t.report();
}
