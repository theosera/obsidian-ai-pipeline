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
import { TestRunner, type TestSuiteResult } from './helpers';
import {
  extractPeriodEnd,
  isSafePeriodEnd,
  isSafeRawPath,
  extractPlainTextBody,
  envOrUndefined,
  PERIOD_END_RE,
} from '../scripts/llm_sec_weekly_fetcher';
import type { gmail_v1 } from '@googleapis/gmail';

const ARCHIVE_DIR = '/tmp/vault/Permanent Note/10_Threat_Reports/raw';

function base64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

export function run(): TestSuiteResult {
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

  return t.report();
}
