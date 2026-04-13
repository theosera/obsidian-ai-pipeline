/**
 * 統合テストランナー。
 * test/ 配下の各スイート (security, classifier, router, storage) を集約実行し、
 * 結果をレポートして失敗があれば exit 1 で終了する。
 *
 * 各スイートは `export function run(): { passed, failed }` を提供する。
 */
import { run as runSecurity } from './test/security';
import { run as runClassifier } from './test/classifier';
import { run as runRouter } from './test/router';
import { run as runStorage } from './test/storage';

interface Suite {
  name: string;
  run: () => { passed: number; failed: number };
}

const suites: Suite[] = [
  { name: 'Security', run: runSecurity },
  { name: 'Classifier', run: runClassifier },
  { name: 'Router', run: runRouter },
  { name: 'Storage', run: runStorage },
];

let totalPassed = 0;
let totalFailed = 0;
const suiteResults: { name: string; passed: number; failed: number }[] = [];

for (const suite of suites) {
  console.log(`\n======== ${suite.name} ========`);
  let result: { passed: number; failed: number };
  try {
    result = suite.run();
  } catch (err: any) {
    // suite 自身が throw した場合でも集計サマリーが出力されるようにガードする
    console.error(`  ❌ ${suite.name} suite crashed`);
    console.error(`     ${err?.message ?? String(err)}`);
    result = { passed: 0, failed: 1 };
  }
  totalPassed += result.passed;
  totalFailed += result.failed;
  suiteResults.push({ name: suite.name, ...result });
}

// =====================================================
// サマリー
// =====================================================
console.log('\n========================================');
console.log('📊 テスト結果サマリー');
console.log('========================================');
for (const r of suiteResults) {
  const status = r.failed === 0 ? '✅' : '❌';
  console.log(`  ${status} ${r.name.padEnd(12)}  ${r.passed} passed, ${r.failed} failed`);
}
console.log('----------------------------------------');
console.log(`  合計: ${totalPassed} passed, ${totalFailed} failed`);
console.log('========================================\n');

if (totalFailed > 0) {
  console.error('❌ テストに失敗があります！');
  process.exit(1);
}

console.log('🎉 全テスト合格！');
