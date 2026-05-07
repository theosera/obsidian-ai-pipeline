/**
 * 共通テストヘルパー。
 * 各テストファイルは TestRunner を使ってテストケースを登録し、
 * run() 関数を export することで test_runner.ts から集約実行される。
 */
export class TestRunner {
  passed = 0;
  failed = 0;

  test(name: string, fn: () => void): void {
    try {
      fn();
      console.log(`  ✅ ${name}`);
      this.passed++;
    } catch (err: any) {
      console.error(`  ❌ ${name}`);
      console.error(`     ${err.message}`);
      this.failed++;
    }
  }

  /** Async test variant. Use for tests that need await (mocked fetch etc.). */
  async testAsync(name: string, fn: () => Promise<void>): Promise<void> {
    try {
      await fn();
      console.log(`  ✅ ${name}`);
      this.passed++;
    } catch (err: any) {
      console.error(`  ❌ ${name}`);
      console.error(`     ${err.message}`);
      this.failed++;
    }
  }

  section(name: string): void {
    console.log(`\n--- ${name} ---`);
  }

  report(): { passed: number; failed: number } {
    return { passed: this.passed, failed: this.failed };
  }
}

export interface TestSuiteResult {
  passed: number;
  failed: number;
}
