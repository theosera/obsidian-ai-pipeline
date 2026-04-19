# scripts/ — アーカイブ (参照用)

> ⚠️ **このディレクトリはアーカイブです。新規実行には使わないでください。**

## 概要

`scripts/` は TypeScript 化以前の **旧 JavaScript 版** パイプライン一式です。現在の正規実装はリポジトリルート配下の `*.ts` ファイル (index.ts, classifier.ts, router.ts, storage.ts など) で、`tsx` により直接実行されます。

## 保持する理由

- **実装リファレンス**: TypeScript 版へのリファクタリング前に動いていたロジック (依存ライブラリのバージョンを含む) を参照できるようにする
- **リグレッション調査**: TypeScript 化に伴う挙動差を疑う際のベースライン
- **歴史的記録**: プロジェクトの進化を残す

## 実行非推奨である理由

- 依存関係 (`scripts/package.json` / `scripts/package-lock.json`) はリポジトリルートの pnpm 管理とは独立しており、更新されていません
- セキュリティ修正 (`ensureSafePath` 7フェーズ化、VAULT_ROOT の設定ファイル化、`--dry-run` など) は一切反映されていません
- ハードコードされたパスや旧バージョンの API キー取扱が残っている可能性があります

## 正規の実行方法

ルートディレクトリで:

```bash
pnpm install
pnpm start -- --config              # 初回設定
pnpm start ../context/OneTab.txt    # 実行
pnpm start ../context/OneTab.txt --dry-run  # dry-run
pnpm test                           # セキュリティテスト + ユニットテスト
```

詳しくはルートの `README.md` を参照してください。
