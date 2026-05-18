// 最小 ESLint 設定 (flat config / ESLint 10 + typescript-eslint 8)。
//
// 方針 (本リポジトリの性質を鑑みた "必要最小限"):
//   - 対象は **ルート Claude 側のみ** (`*.ts` + `pipeline/**` + `test/**`)。
//     apps/* / packages/* (Codex 側) は対象外 — Claude-vs-Codex 対照実験の
//     独立性を尊重する。
//   - ルールは **バグ検出のみ**。スタイル統一は CodeRabbit に委譲する。
//   - recommended セットは使わず、価値が確実な 4 ルールだけ明示有効化する。
//
// 最重要は `no-floating-promises`: await 忘れの Promise を CI で弾く。
// async が多い本コードベース (X API / spawn / fetch) で実バグ予防になる。

import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // Codex 側 workspace / アーカイブ / ビルド成果物 / 非 TS を一切対象にしない
    ignores: [
      'apps/**',
      'packages/**',
      'chrome-extension/**',
      'scripts/**',
      'dist/**',
      'node_modules/**',
      'utils/**',
      '**/*.js',
      '**/*.cjs',
      '**/*.mjs',
    ],
  },
  {
    files: ['*.ts', 'pipeline/**/*.ts', 'test/**/*.ts'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        // type-aware linting (no-floating-promises 等に必須)。
        // projectService が各ファイルの tsconfig を自動解決する。
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
    },
    rules: {
      // await 忘れの Promise を検出 (最重要・type-aware)
      '@typescript-eslint/no-floating-promises': 'error',
      // `if (asyncFn())` 等の Promise 誤用を検出 (type-aware)
      '@typescript-eslint/no-misused-promises': 'error',
      // 未使用変数。`_` プレフィックスは意図的な未使用として許容
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
      // 再代入されない let を const に
      'prefer-const': 'error',
    },
  },
);
