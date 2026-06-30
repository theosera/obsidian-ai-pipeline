/**
 * Level 2 grep 証拠 (repo_evidence.ts) のユニットテスト。
 * 設計上の不変条件を検証する:
 *   - 検索語抽出は決定的・コード識別子のみ (散文/秘密パターンを grep 種にしない)
 *   - 走査は秘密ファイル / node_modules / .git を除外し bounded
 *   - **返すのは file:line と一致語のみ (行内容を漏らさない)** = ノート経由 exfil 防止
 */
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { TestRunner, type TestSuiteResult } from './helpers';
import {
  extractSearchTerms,
  isSecretFile,
  buildRepoScanner,
  formatEvidenceForPrompt,
  formatCandidatesForNote,
  type EvidenceHit,
} from '../threat-reports/repo_evidence';

function mkRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

export function run(): TestSuiteResult {
  const runner = new TestRunner();

  runner.section('extractSearchTerms: コード識別子のみを決定的に拾う');

  runner.test('camelCase / snake_case / dotted API / 拡張子を拾い、純散文は捨てる', () => {
    const terms = extractSearchTerms([
      'child_process.exec で任意コード実行',
      'readFileSync を使った path traversal',
      'storage.ts の ensureSafePath',
      'this is plain english prose without identifiers',
    ]);
    assert.ok(terms.includes('child_process.exec'), 'dotted API');
    assert.ok(terms.includes('readFileSync'), 'camelCase');
    assert.ok(terms.includes('ensureSafePath'), 'camelCase 2');
    assert.ok(terms.includes('storage.ts'), 'ファイル名');
    assert.ok(!terms.includes('english'), '純粋な英単語は除外');
    assert.ok(!terms.includes('prose'), '純粋な英単語は除外');
  });

  runner.test('秘密パターン (AKIA... 等 大文字山なし語) は grep 種にしない', () => {
    // ドット/アンダースコア/camel の山が無い大文字塊は除外される (exfil 経路を作らない)。
    const terms = extractSearchTerms(['AKIAIOSFODNN7EXAMPLE という鍵が漏洩']);
    assert.ok(!terms.includes('AKIAIOSFODNN7EXAMPLE'), '大文字塊は code-like 判定外で除外');
  });

  runner.test('重複除去 / 最大 12 件 / 前後区切りを剥がす', () => {
    const fields = Array.from({ length: 30 }, (_, i) => `mod_${i}.run mod_${i}.run`);
    const terms = extractSearchTerms(fields);
    assert.ok(terms.length <= 12, '最大 12 件に cap');
    assert.strictEqual(new Set(terms).size, terms.length, '重複なし');
    assert.ok(terms.every(t => !/^[._/$-]|[._/$-]$/.test(t)), '前後の区切り文字は剥がす');
  });

  runner.test('null / 空フィールドを安全に無視', () => {
    assert.deepStrictEqual(extractSearchTerms([null, undefined, '']), []);
  });

  runner.section('isSecretFile: 秘密ファイル名を除外対象と判定');

  runner.test('.env / *.key / *.pem / x_tokens.json / credentials* を秘密と判定', () => {
    for (const n of ['.env', '.env.local', 'server.key', 'cert.pem', 'x_tokens.json', 'credentials.json', 'id_rsa']) {
      assert.ok(isSecretFile(n), `${n} は秘密`);
    }
    for (const n of ['index.ts', 'config.json', 'README.md']) {
      assert.ok(!isSecretFile(n), `${n} は非秘密`);
    }
  });

  runner.section('buildRepoScanner: bounded な read-only grep / 行内容を返さない');

  runner.test('一致語の file:line を返す (行内容は含まない)', () => {
    const dir = mkRepo({
      'a.ts': 'const x = 1;\nimport { readFileSync } from "fs";\n',
      'sub/b.ts': 'readFileSync(p);\n',
    });
    const scanner = buildRepoScanner(dir);
    const hits = scanner.find(['readFileSync']);
    assert.ok(hits.length >= 2, '2 箇所一致');
    const a = hits.find(h => h.file === 'a.ts');
    assert.strictEqual(a?.line, 2, '1-based 行番号');
    assert.strictEqual(a?.term, 'readFileSync');
    // EvidenceHit は file/line/term のみ — content フィールドが無いこと (型 + 実体)。
    assert.deepStrictEqual(Object.keys(a as EvidenceHit).sort(), ['file', 'line', 'term']);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  runner.test('node_modules / .git / 秘密ファイルは走査しない', () => {
    const dir = mkRepo({
      'src.ts': 'SECRET_TOKEN_marker here\n',
      'node_modules/dep/x.ts': 'SECRET_TOKEN_marker here\n',
      '.git/config': 'SECRET_TOKEN_marker here\n',
      '.env': 'SECRET_TOKEN_marker=abc\n',
      'server.key': 'SECRET_TOKEN_marker\n',
    });
    const scanner = buildRepoScanner(dir);
    const hits = scanner.find(['SECRET_TOKEN_marker']);
    assert.strictEqual(hits.length, 1, 'src.ts のみ (node_modules/.git/.env/.key は除外)');
    assert.strictEqual(hits[0].file, 'src.ts');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  runner.test('maxFiles 上限で走査を打ち切り truncated=true', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 10; i++) files[`f${i}.ts`] = 'needleNeedle\n';
    const dir = mkRepo(files);
    const scanner = buildRepoScanner(dir, { maxFiles: 3 });
    assert.ok(scanner.truncated, '上限到達で truncated');
    assert.ok(scanner.filesLoaded <= 3);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  runner.test('短すぎる語 (<4) は一致対象にしない', () => {
    const dir = mkRepo({ 'a.ts': 'ab cd ef\n' });
    const scanner = buildRepoScanner(dir);
    assert.deepStrictEqual(scanner.find(['ab']), [], '3 文字以下は無視');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  runner.section('formatEvidenceForPrompt / formatCandidatesForNote');

  runner.test('証拠なし → 明示メッセージ / 候補なし → 空文字', () => {
    assert.ok(formatEvidenceForPrompt([]).includes('見つからなかった'));
    assert.strictEqual(formatCandidatesForNote([]), '');
  });

  runner.test('prompt 用は file:line のみ・行内容を含まない', () => {
    const hits: EvidenceHit[] = [{ file: 'a.ts', line: 2, term: 'readFileSync' }];
    const out = formatEvidenceForPrompt(hits);
    assert.ok(out.includes('a.ts:2'));
    assert.ok(out.includes('readFileSync'));
    assert.ok(/行の内容は含まない/.test(out), '行内容を含まない旨を明示');
  });

  runner.test('候補は重複除去して最大 3 件', () => {
    const hits: EvidenceHit[] = [
      { file: 'a.ts', line: 1, term: 't' },
      { file: 'a.ts', line: 1, term: 't' }, // 重複
      { file: 'b.ts', line: 2, term: 't' },
      { file: 'c.ts', line: 3, term: 't' },
      { file: 'd.ts', line: 4, term: 't' },
    ];
    const note = formatCandidatesForNote(hits);
    assert.ok(note.includes('a.ts:1') && note.includes('b.ts:2') && note.includes('c.ts:3'));
    assert.ok(!note.includes('d.ts:4'), '4 件目は載らない (cap 3)');
  });

  return runner.report();
}
