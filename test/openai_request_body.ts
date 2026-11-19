/**
 * OpenAI を呼ぶ 3 か所 (classifier.ts の askAI・askAIText、merge-articles.ts の callSmartModel) が、
 * 実際に要求の本体へ何を載せるかの試験。
 *
 * 重点:
 *   - askAI・askAIText は max_completion_tokens を送り、max_tokens は送らない
 *   - reasoning_effort: 'none' は確かめた 2 つのモデル (gpt-6-luna・gpt-6.1-terra) にだけ付く
 *   - merge-articles は前から上限を送らない。reasoning_effort の付き方だけを見る
 *
 * 本物の API は呼ばない。127.0.0.1 に偽の OpenAI サーバを立て、OPENAI_BASE_URL をそこへ向けた
 * 子プロセスで 3 か所を呼び、受けた本体を見る。classifier.ts は読み込むときに OpenAI の client を
 * 作るので、env を先に持つ子プロセスで読み込む。各呼び出しの user の文に印 (MARK-...) を入れて分ける。
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TestRunner, type TestSuiteResult } from './helpers';

const VERIFIED_NO_REASONING = new Set(['gpt-6-luna', 'gpt-6.1-terra']);
const REPLY = JSON.stringify({ proposedPath: 'Engineer', isNewFolderRequired: false, confidence: 0.95, reasoning: 'テスト' });

// 子の argv[1] はモジュールの URL にする。merge-articles.ts は argv[1] が自分のときだけ本処理を始める。
const CHILD = `
const [configUrl, classifierUrl, mergeUrl] = process.argv.slice(1);
const fs = await import('node:fs');
const os = await import('node:os');
const path = await import('node:path');
const { setVaultRoot } = await import(configUrl);
const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'openai-request-body-vault-'));
setVaultRoot(vault);
const { askAIText, classifyArticle } = await import(classifierUrl);
const { callSmartModel } = await import(mergeUrl);
try {
  await askAIText('MARK-text-default', 'sys', 'fast', 123, { provider: 'openai' });
  await askAIText('MARK-text-custom', 'sys', 'fast', 77, { provider: 'openai', model: 'gpt-4o-mini' });
  await classifyArticle('https://example.invalid/a', 'MARK-classify-default', 'body');
  process.env.OPENAI_FAST_MODEL = 'gpt-4o-mini';
  await classifyArticle('https://example.invalid/b', 'MARK-classify-custom', 'body');
  delete process.env.OPENAI_FAST_MODEL;
  await callSmartModel('MARK-merge-default', 'sys');
  process.env.OPENAI_SMART_MODEL = 'gpt-4o';
  await callSmartModel('MARK-merge-custom', 'sys');
} finally {
  fs.rmSync(vault, { recursive: true, force: true });
}
`;

interface Received { url: string | undefined; body: Record<string, unknown> }

function startServer(received: Received[]): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', chunk => { raw += String(chunk); });
    req.on('end', () => {
      let body: Record<string, unknown> = {};
      try { body = JSON.parse(raw); } catch { body = { unparsable: raw }; }
      received.push({ url: req.url, body });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        id: 'chatcmpl-test', object: 'chat.completion', created: 0, model: String(body.model ?? ''),
        choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: REPLY } }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }));
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function runChild(port: number): Promise<{ code: number | null; errors: string }> {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const url = (file: string) => new URL(`../${file}`, import.meta.url).href;
  const child = spawn(process.execPath, [
    '--import', 'tsx', '--input-type=module', '-e', CHILD,
    url('config.ts'), url('classifier.ts'), url('merge-articles.ts'),
  ], {
    cwd: root,
    // 親の env は引き継がない (手元の鍵やモデルの設定を混ぜない)。鍵は試験用の偽の値。
    env: {
      PATH: process.env.PATH ?? '', HOME: os.tmpdir(), TMPDIR: os.tmpdir(),
      OPENAI_API_KEY: 'test-dummy-not-a-real-key', OPENAI_BASE_URL: `http://127.0.0.1:${port}/v1`,
      AI_PROVIDER: 'openai',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = '';
  child.stdout!.resume();
  child.stderr!.on('data', chunk => { errors += String(chunk); });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, 60_000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, errors }); });
  });
}

/** 印を含む要求だけを、受けた順に返す。 */
function marked(received: Received[], mark: string): Received[] {
  return received.filter(r => JSON.stringify(r.body.messages ?? []).includes(mark));
}

/** 全ての要求に共通の決まり: 送り先・max_tokens を送らない・reasoning_effort は確かめたモデルにだけ。 */
function assertCommon(r: Received, label: string): void {
  assert.equal(r.url, '/v1/chat/completions', label);
  assert.ok(!('max_tokens' in r.body), `${label}: max_tokens を送らない`);
  if (VERIFIED_NO_REASONING.has(String(r.body.model))) {
    assert.equal(r.body.reasoning_effort, 'none', `${label}: ${r.body.model} には reasoning_effort: 'none'`);
  } else {
    assert.ok(!('reasoning_effort' in r.body), `${label}: ${r.body.model} には reasoning_effort を送らない`);
  }
}

export async function run(): Promise<TestSuiteResult> {
  const runner = new TestRunner();
  runner.section('OpenAI の要求の本体 (127.0.0.1 の偽のサーバで受ける)');

  const received: Received[] = [];
  const server = await startServer(received);
  let child: { code: number | null; errors: string };
  try {
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    child = await runChild(address.port);
  } finally {
    server.close();
  }

  runner.test('子プロセスが終了コード 0 で終わり、全ての要求に印がある', () => {
    assert.equal(child.code, 0, child.errors);
    const marks = ['MARK-text-default', 'MARK-text-custom', 'MARK-classify-default', 'MARK-classify-custom', 'MARK-merge-default', 'MARK-merge-custom'];
    for (const r of received) {
      assert.ok(marks.some(m => JSON.stringify(r.body.messages ?? []).includes(m)), `印の無い要求: ${JSON.stringify(r.body).slice(0, 200)}`);
    }
  });

  runner.test('askAIText (既定 gpt-6-luna): max_completion_tokens と reasoning_effort: none', () => {
    const rs = marked(received, 'MARK-text-default');
    assert.equal(rs.length, 1);
    assertCommon(rs[0], 'askAIText 既定');
    assert.equal(rs[0].body.model, 'gpt-6-luna');
    assert.equal(rs[0].body.max_completion_tokens, 123);
  });

  runner.test('askAIText (保存済みの gpt-4o-mini): max_completion_tokens は付き、reasoning_effort は付かない', () => {
    const rs = marked(received, 'MARK-text-custom');
    assert.equal(rs.length, 1);
    assertCommon(rs[0], 'askAIText gpt-4o-mini');
    assert.equal(rs[0].body.model, 'gpt-4o-mini');
    assert.equal(rs[0].body.max_completion_tokens, 77);
  });

  runner.test('askAI (classifyArticle・既定 gpt-6-luna): max_completion_tokens 300 と reasoning_effort: none', () => {
    const rs = marked(received, 'MARK-classify-default');
    assert.ok(rs.length >= 1);
    rs.forEach((r, i) => assertCommon(r, `askAI 既定 #${i}`));
    assert.equal(rs[0].body.model, 'gpt-6-luna');
    assert.equal(rs[0].body.max_completion_tokens, 300);
    assert.deepEqual(rs[0].body.response_format, { type: 'json_object' });
    assert.equal(rs[0].body.temperature, 0.1);
  });

  runner.test('askAI (OPENAI_FAST_MODEL=gpt-4o-mini): max_completion_tokens 300 は付き、reasoning_effort は付かない', () => {
    const rs = marked(received, 'MARK-classify-custom');
    assert.ok(rs.length >= 1);
    rs.forEach((r, i) => assertCommon(r, `askAI gpt-4o-mini #${i}`));
    assert.equal(rs[0].body.model, 'gpt-4o-mini');
    assert.equal(rs[0].body.max_completion_tokens, 300);
  });

  runner.test('merge-articles (既定 gpt-6.1-terra): reasoning_effort: none と temperature 0.3・上限は前から送らない', () => {
    const rs = marked(received, 'MARK-merge-default');
    assert.equal(rs.length, 1);
    assertCommon(rs[0], 'merge 既定');
    assert.equal(rs[0].body.model, 'gpt-6.1-terra');
    assert.equal(rs[0].body.temperature, 0.3);
    assert.ok(!('max_completion_tokens' in rs[0].body));
  });

  runner.test('merge-articles (OPENAI_SMART_MODEL=gpt-4o): reasoning_effort は付かない', () => {
    const rs = marked(received, 'MARK-merge-custom');
    assert.equal(rs.length, 1);
    assertCommon(rs[0], 'merge gpt-4o');
    assert.equal(rs[0].body.model, 'gpt-4o');
  });

  return runner.report();
}
