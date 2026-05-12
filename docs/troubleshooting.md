# Troubleshooting

問題発生時に「症状」から解決策を引けるようにしたインデックスです。
新しい知見は **`## Symptom: <症状の短い記述>` を 1 セクションとして** 追記してください。
セクション順は重要度ではなく追加日順 (新しいものを上に) で構いません。

## Index

- [MCP サーバが突然切断される (例: GitHub MCP)](#symptom-mcp-サーバが突然切断される-例-github-mcp)

---

## Symptom: MCP サーバが突然切断される (例: GitHub MCP)

**観測現象**: セッション中に `mcp__github__*` 系の deferred tool が利用不可になる。
ToolSearch で検索しても "No matching deferred tools found" になる。
`mcp__github__authenticate` を実行して認証 URL が発行できても、
ブラウザで URL を踏むと `api.anthropic.com/authorize` ではなく
**Google Drive MCP のインストール画面** (`api.anthropic.com/mcp/gdrive/google/install`)
に飛ばされ、本来期待される `http://localhost:<port>/callback?code=...&state=...`
への redirect が発生しない。

**原因 (推定)**: ブラウザの `api.anthropic.com` ドメイン Cookie / セッションが
別の MCP (gdrive など) の認証フローを覚えており、OAuth authorize ハンドラが
そちらに合流してしまう。

**ワークアラウンド** (再現確認済み):

1. Safari (or 該当ブラウザ) で Claude にログインしている UI から **一度ログアウト**
2. **再ログイン**
3. その状態で改めて MCP 関連の URL / リンクを踏む

これで本来の `/callback` redirect に到達でき、Claude Code 側で
`mcp__github__complete_authentication` を呼んで再接続できる。

**代替策**: シークレットウィンドウで認証 URL を開く / `api.anthropic.com` の
Cookie を手動クリアする、も同等の効果が期待できる (Cookie が問題の根因のため)。

**Claude Code 側で取れる挙動**: PR webhook subscription が有効な場合、
新しい CodeRabbit レビューや CI 失敗は `<github-webhook-activity>` として
自動的に届くので、MCP が一時的に切れていても重要なイベントは取りこぼさない。
直接ポーリングが必要なときだけ上記ワークアラウンドで MCP を復活させる。
