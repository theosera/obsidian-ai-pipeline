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
  readQuarantinePendingPeriodEnds,
  GATE_SUBDIR,
  PERIOD_END_RE,
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

  t.section('readQuarantinePendingPeriodEnds (再取込ループ防止ガード)');

  function vaultWithQueue(items: unknown[] | null): string {
    const vaultRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-vault-'));
    if (items !== null) {
      const gateDir = path.join(vaultRoot, getThreatReportsBaseFolder(), GATE_SUBDIR);
      fs.mkdirSync(gateDir, { recursive: true });
      fs.writeFileSync(
        path.join(gateDir, 'quarantine_queue.json'),
        JSON.stringify({ schema: 'quarantine-queue@1', items }),
        'utf8'
      );
    }
    return vaultRoot;
  }

  t.test('pending の period_end だけを返す (裁定済みは対象外)', () => {
    const vaultRoot = vaultWithQueue([
      { period_end: '2026-06-08', status: 'pending' },
      { period_end: '2026-06-01', status: 'ingested' },
      { period_end: '2026-05-25', status: 'rejected' },
      { period_end: 123, status: 'pending' }, // 型違いは無視
    ]);
    assert.deepStrictEqual(readQuarantinePendingPeriodEnds(vaultRoot), new Set(['2026-06-08']));
  });

  t.test('キューが無ければ空 Set (ゲート自体は毎回走るので安全側)', () => {
    const vaultRoot = vaultWithQueue(null);
    assert.deepStrictEqual(readQuarantinePendingPeriodEnds(vaultRoot), new Set());
  });

  t.test('キューが壊れた JSON でも throw せず空 Set', () => {
    const vaultRoot = vaultWithQueue(null);
    const gateDir = path.join(vaultRoot, getThreatReportsBaseFolder(), GATE_SUBDIR);
    fs.mkdirSync(gateDir, { recursive: true });
    fs.writeFileSync(path.join(gateDir, 'quarantine_queue.json'), '{not json', 'utf8');
    assert.deepStrictEqual(readQuarantinePendingPeriodEnds(vaultRoot), new Set());
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
