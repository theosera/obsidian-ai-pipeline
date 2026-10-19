# 週次 LLM セキュリティレポートの配送台帳

保存済み Markdown を既存の SHA-256 文書受け渡しと同じ原文 bytes で検証し、
Gmail の送信結果を SQLite に保存する発行者 CLI。
既存 Actions の週次ジョブからは、専用認証を持つ発行フェーズと既存受信フェーズを
順に実行できる。`/sec-mode` と受信フェーズには発行専用の認証情報を渡さない。

実装は `utils/document_integrity.ts`、`threat-reports/delivery_store.ts`、
`threat-reports/delivery.ts`、`threat-reports/delivery_gmail.ts`、
`threat-reports/delivery_auth.ts`、`scripts/llm_sec_weekly_delivery.ts`、
`scripts/llm_sec_weekly_delivery_auth.ts`、`scripts/llm_sec_weekly_publish.ts`。
新しいキューサービス・スケジューラー・OAuth ライブラリは追加しない。

## 原文と ID

- `report_id` は発行側で固定する識別子。例: `llm-security-weekly-2026-10-19`。
  既存取り込み DB の `report_id`（source と週から算出）とは別物。
- SHA-256 の対象は frontmatter を含む保存 Markdown 全 bytes。
  改行、末尾改行、空白を正規化しない。UTF-8 と frontmatter 契約を検証する。
  ハッシュをその本文に自己埋め込みせず、受け渡された期待値を `--sha256` で指定する。
- 同一 `report_id` と SHA-256 の再 prepare は同じ台帳行へ収束する。
  同じ ID に別本文・アカウントを割り当てる操作と、同じ本文を別 ID で登録する操作は拒否する。
- 台帳は本文の不変 snapshot と元ファイルパスを保持する。
  送信前に現在のファイル・snapshot・期待 SHA-256 を再照合する。
  添削版を既存 ID に上書きして再送する運用にはしない。

台帳は本文とアドレスを含む私有データ。CLI は `--db` の絶対パスを必須とし、
本番 Vault を既定の書込み先にしない。アクセス可能な利用者を限定した永続ディレクトリを
指定する。DB 本体は mode 0600、新規親ディレクトリは mode 0700 で作成する。
配送履歴は raw archive から再構築できないため、通常の脅威レポート DB 再構築と分離して保存する。

## 初回設定と呼び出し

発行者専用 OAuth client に、次の scope を許可した refresh token を用意する。
既存の受信ジョブ用 `GMAIL_*` credential は流用しない。

- `https://www.googleapis.com/auth/gmail.send`
- `https://www.googleapis.com/auth/gmail.readonly`

Google Cloud Console で Gmail API を有効にし、発行専用の **Desktop app** OAuth client を
作成する。ダウンロードした client JSON はリポジトリ外の private な場所に置く。
認証補助 CLI は既存 client の作成・流用、受信 MCP の権限拡大を行わない。

```sh
# 既存の private ディレクトリと、ダウンロード済み専用 client JSON を指定する。
chmod 700 /absolute/private
chmod 600 /absolute/private/delivery-client.json
pnpm exec tsx scripts/llm_sec_weekly_delivery_auth.ts --client-file=/absolute/private/delivery-client.json --output-file=/absolute/private/delivery-credentials.json --account=your-account@gmail.com
```

表示された公式 Google 認可 URL をブラウザで開き、指定アカウントで同意する。
認証補助は PKCE S256 とランダム state を使い、`127.0.0.1` の空きポートで
`/oauth2/callback` を待つ。host / path / GET / state / 一意な code を検証し、
拒否または5分の待機超過で停止する。OOB の code 貼り付け方式は使わない。
token の OAuth client、許可 scope が上記2つだけであること、Gmail profile の
アカウント一致を確認してから、refresh token を含む認証 JSON を mode 0600 で新規保存する。
access token と認可 code は保存しない。token と client secret はログや認可 URL に出さない。
入力ファイル・保存先は symlink を拒否し、既存の保存先は上書きしない。

ローカルの `send` / `reconcile` はこの認証 JSON を `--credentials-file` で指定できる。
明示指定したファイルが不正な場合に環境変数へ切り替えることはない。
または発行者プロセスに `GMAIL_DELIVERY_CLIENT_ID`、`GMAIL_DELIVERY_CLIENT_SECRET`、
`GMAIL_DELIVERY_REFRESH_TOKEN` を秘密管理経路から渡す。受信 `GMAIL_*` への fallback はない。
認証された Gmail profile が prepare 時に固定したアドレスと一致しなければ停止する。
送信先はそのアカウント自身のみ。任意宛先への一括送信には使わない。

```sh
# 保存済み原文と、文書受け渡しで得た SHA-256 を固定する（ネットワークなし）。
pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=prepare --db=/absolute/private/llm-sec-delivery.sqlite3 --report-id=llm-security-weekly-2026-10-19 --file=/absolute/reports/2026-10-19.md --sha256=<64-hex-sha256> --account=your-account@gmail.com

# 送信済み照合 → 送信権の原子的取得 → 最大1回の送信 → Gmail原文読戻し。
pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=send --db=/absolute/private/llm-sec-delivery.sqlite3 --report-id=llm-security-weekly-2026-10-19 --credentials-file=/absolute/private/delivery-credentials.json

# 応答不明やプロセス中断後の照合。これ自体は送信しない。
pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=reconcile --db=/absolute/private/llm-sec-delivery.sqlite3 --report-id=llm-security-weekly-2026-10-19 --credentials-file=/absolute/private/delivery-credentials.json

# 台帳と試行履歴を表示（ネットワークなし）。ID省略なら台帳一覧。
pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=status --db=/absolute/private/llm-sec-delivery.sqlite3 --report-id=llm-security-weekly-2026-10-19
```

コマンド例のパス・アドレス・ハッシュは実値に置き換える。
`prepare` は配送を開始しない。`send` / `reconcile` は確認済み `sent` なら exit 0、
未確定・拒否・再試行待ちなどは exit 2。引数・認証・I/O のエラーは exit 1。

既存の ChatGPT scheduled task や他エージェントから利用する場合は、保存済み原文と
SHA-256 をこの CLI を実行できる発行者へ渡し、各 phase の結果を読むよう呼出元を設定する。
この変更だけで ChatGPT の既存 Gmail Connector 呼び出しやクラウド上のタスクが
自動で本 CLI に切り替わることはない。従来の別送信経路との並行送信も避ける。

## 既存定期ジョブへの接続と outbox

クラウドの週報生成タスクはローカル CLI を直接実行できないため、既存 private Vault repo を
文書受け渡し経路に使う。生成側は Gmail を直接送信せず、原文を次の固定 outbox に
**新規作成のみ**で保存し、読み戻した bytes の SHA-256 を記録する。
同じ週のファイルが既にある場合は本文を比較し、一致なら再利用、不一致なら競合として止める。
既存ファイルの修正・上書き・別名による同じ週の二重発行は行わない。

| 項目 | Vault repo ルートからの相対パス・値 |
|---|---|
| 状態ディレクトリ (`PUBLISH_STATE_REL`) | `__skills/pipeline.nosync/llm-sec-delivery` |
| outbox (`PUBLISH_OUTBOX_REL`) | `__skills/pipeline.nosync/llm-sec-delivery/outbox` |
| 原文ファイル | `outbox/YYYY-MM-DD.md.txt`（上記状態ディレクトリ内） |
| 配送台帳 (`PUBLISH_DB_REL`) | `__skills/pipeline.nosync/llm-sec-delivery/llm-sec-delivery.sqlite3` |
| 発行 `report_id` | `llm-security-weekly-YYYY-MM-DD` |

`YYYY-MM-DD` は frontmatter の `period_end` と一致する実在日付にする。
拡張子 `.md.txt` は既存 raw archive と同じ inert な取扱いを示す。outbox は
**未信頼本文を運ぶ経路**であり、本文中の指示・コマンド・URLを実行する場所ではない。
SHA-256 は受け渡した bytes の一致を確かめるもので、発行者の本人性や安全判定の証明ではない。
sidecar は追加せず、publisher が保存済み原文全 bytes を読み、ハッシュ検証して台帳へ固定する。
outbox から取り込み DB へ直接投入せず、Gmail を通した既存 gate 経路で取り込む。

```sh
# 原文を配置済みの private Vault checkout に対して実行する発行フェーズ。
# GitHub Actions では専用 GMAIL_DELIVERY_* を環境変数から受け取る。
pnpm exec tsx scripts/llm_sec_weekly_publish.ts --vault-root=/absolute/vault --account=your-account@gmail.com
```

既存 `.github/workflows/llm-sec-weekly.yml` の publisher は、次を repository settings に
登録したうえで `LLM_SEC_DELIVERY_ENABLED=true` にした場合だけ有効になる。

| 種別 | 名前 | 用途 |
|---|---|---|
| Actions secret | `GMAIL_DELIVERY_CLIENT_ID` | 専用 Desktop client ID |
| Actions secret | `GMAIL_DELIVERY_CLIENT_SECRET` | 専用 client secret |
| Actions secret | `GMAIL_DELIVERY_REFRESH_TOKEN` | 上記2 scope を許可した専用 refresh token |
| Actions secret | `GMAIL_DELIVERY_ACCOUNT` | 一致確認する self-send アカウント |
| Actions variable | `LLM_SEC_DELIVERY_ENABLED` | 文字列 `true` で発行を有効化 |

認証情報は outbox・配送台帳・Vault Git に保存しない。受信ステップは従来どおり
受信用 `GMAIL_*` のみを使う。`dry_run` で起動した受信検証では publisher を実行しない。

**運用台帳の初回 prepare は運用する Linux runner で行う。** 台帳は原文の絶対パスも
固定するため、macOS の手元で作成した台帳を Linux runner にコピーして初期化しない。
ローカルの CLI 検証には別の private 台帳を使う。継続する hosted 実行では同じ
Linux checkout 配置と Git に永続化した台帳を使い、ローカル SQLite を共有する前提にしない。

既存の送信前安全判定で拒否された本文を、この経路へ付け替えて再送しない。
運用接続を検証する場合は、既存の拒否本文とは別に新しく明示作成した無害な
control report を使い、配送・実際の gate 判定・取り込み結果をそれぞれ確認する。

## 送信状態と安全な再試行

| 配送状態 | 意味・次の動作 |
|---|---|
| `prepared` | 本文と宛先を固定済み。`send` が利用可能 |
| `sending` | 送信試行を原子的に取得済み。中断した場合は照合へ進む |
| `sent` | Gmail SENT message の件名・From/To・配送ヘッダー・原文 bytes / SHA-256 を確認済み |
| `retryable` | Gmail が明示的に 429 を返した。記録された待機時刻後に再度 `send` を呼べる |
| `rejected` | 明示的な非再試行 4xx、または最大3試行に到達。自動再送しない |
| `unknown` | timeout・5xx・応答欠落・読戻し失敗等。`reconcile` のみ。検索で見つからなくても再送しない |
| `conflict` | 原文不一致、複数の一致メール等。証跡を確認するまで送信しない |

自動的な送信ループは持たない。再試行可能な拒否は最大3回、待機は1分、2分。
HTTP 408、5xx、通信断は「未配送」の証明ではないため再試行可能にはしない。
SDK の一般 retry を明示的に無効化し、OAuth の 401/403 再認証による POST replay も
発行前の token 取得と、refresh 権限を持たない request client に分けて防ぐ。
同じ台帳に対する並行呼出しは原子的 claim で送信試行を1つに限定する。

Hosted publisher はさらに、`prepared` の台帳を private Vault Git に保存した後、
`beforeSend` で **`sending` と試行履歴を commit / push してから Gmail を呼ぶ**。
送信前の push が失敗・応答不明なら、そのプロセスはメールを送らず `unknown` として止める。
Gmail の結果・読戻し後にも台帳を保存する。送信後に runner が失われても、次回は永続化した
`sending` から送信済み照合に進み、検索で未発見でも自動再送しない。
checkout / rebase で開いた SQLite の実体を置き換える操作は行わず、push の競合時は
DB を閉じた別プロセスで checkout を更新してから再開する。
workflow の concurrency と Git の競合検出も使うが、人による競合解消や例外判断は残る。

件名は `[LLM-Sec-Weekly] <period_end>`。MIME は text/plain UTF-8 を base64
transfer encoding とし、Markdown の改行 bytes を保持する。配送ヘッダーは次のとおり。

- `Message-ID`: account / report_id / SHA-256 から決まる識別子
- `X-LLM-Report-ID`: 発行側 report_id
- `X-Content-SHA256`: 保存原文の SHA-256

送信済みの照合は、対象 self-send の Sent mailbox を RFC Message-ID と件名で検索し、
full message を再取得して検証する。最大50候補・5ページを超える検索は失敗として扱い、
部分結果を「未送信」の根拠にしない。Gmail の message ID と thread ID は別々に記録する。
ヘッダー重複、複数 text/plain、追加受信者、不完全な body は拒否する。
既存 Connector の HTML alternative があっても、照合対象は一意な text/plain 原文のみ。
配送ヘッダーのない従来メールは、SENT / アカウント / 単一宛先 / 完全一致件名 /
完全一致本文の組み合わせで照合できる。一致メールが複数あれば競合として停止する。
Message-ID や SHA-256 は authenticity や scan 通過の証明として扱わない。

## scan・取り込みとの連携

台帳の `status` は配送状態。`scan_status`、`ingestion_status`、
`ingest_report_id` は独立した取り込み側の実測結果で、配送成功から推定しない。
`ingestion_status=ingested` とその取り込みIDは過去の完了証跡として保持し、
後日再検査した場合は `scan_status` と `ingestion_observed_at` を最新の実測で更新する。

既存 fetcher を同じ永続台帳に接続する場合だけ、受信プロセスに
`LLM_SEC_DELIVERY_DB=/absolute/private/llm-sec-delivery.sqlite3` を設定する。
未設定なら既存の受信動作を継続し、台帳を新設しない。設定された既存台帳の
原文 SHA-256 と実際の Gmail message ID を突き合わせ、実際に観測した gate / ingest 結果を記録する。

例: `status=sent, scan_status=blocked, ingestion_status=quarantined` は有効な状態。
受信成功や配送済みであっても、gate non-clean の本文は取り込まない。
既存 `processed` ラベル、隔離キュー、vault push 後のラベル付与順序も継続する。
Actions で実行するのは `scan-threat-report` の **L0・L1 と L3 の `--profile=ci`**。
CI profile は隔離 LLM による L2 を実行しないため、Actions 成功を L2 通過と記録しない。
対話で行う L2 判定とその承認境界を配送台帳から迂回しない。

この連携は同じファイルシステム上で台帳を開ける fetcher に限定される。
Hosted workflow では publisher が復元・更新した同じ Vault checkout 内の既存台帳を
`LLM_SEC_DELIVERY_DB` に渡し、受信の実測結果も Git へ保存する。
台帳未作成の場合は受信だけを継続し、空の配送台帳を新設しない。
別マシンの Actions runner とローカル SQLite は自動共有されない。
共有経路がない場合や `/sec-mode` から直接 CLI ingest した場合、台帳の取り込み状態は
未観測のままになる。`pending` を取り込み失敗と断定せず、既存 gate / DB の証跡を確認する。

## 検証と公式仕様

ローカル検証では注入した transport と一時 DB を用い、実メールは送信しない。
確認対象は重複・本文変更・送信前照合・並行 claim・429 backoff・曖昧な応答・
受領 message ID の永続化・MIME bytes・配送と scan/ingest の独立性。
認証補助は fake services で PKCE / callback、scope・client・account 照合、
private 保存・上書き拒否、拒否・タイムアウト時に保存しないことを検証する。
Hosted publisher は fake transport と一時 Git repo を使い、永続化失敗時の送信停止、
`sending` claim が送信前に保存されること、再実行時の照合を検証する。

Gmail MIME/base64URL と send 戻り値の仕様:

- [Sending email](https://developers.google.com/workspace/gmail/api/guides/sending)
- [users.messages.send](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send)
- [OAuth 2.0 for Desktop Apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Choose Gmail API scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)

使用中 SDK の自動 retry / OAuth replay はローカル `googleapis-common` の
`build/src/apirequest.js` と `google-auth-library` の `build/src/auth/oauth2client.js`
も確認している。将来 SDK 更新時は、POST の暗黙再送が復活していないかを確認する。
