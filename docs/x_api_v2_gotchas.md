# X API v2 ブックマーク実装の注意点

実装過程で踏んだ罠と確定した挙動を、次回別所で実装する人が同じ落とし穴に
ハマらないようまとめる。詳細経緯は `docs/x_bookmarks_api_research.md`。

## エンドポイント別の実態

| エンドポイント | 主な用途 | 受付クエリ | ページング | 返り値 |
|---|---|---|---|---|
| `GET /2/users/{id}/bookmarks` | 全ブックマーク本文取得 | `max_results` / `pagination_token` / `tweet.fields` / `expansions` / `*.fields` | あり (`meta.next_token`) | `data[]` + `includes` |
| `GET /2/users/{id}/bookmarks/folders` | フォルダ一覧 | `max_results` / `pagination_token` | あり | `data[].{id,name}` |
| `GET /2/users/{id}/bookmarks/folders/{folder_id}` | フォルダ内ツイートID索引 | **無し** (`id`, `folder_id` のみ受付) | **無し** (`meta` 自体返らない) | `data[].{id}` のみ |
| `GET /2/tweets?ids=...` | ID → 本文ハイドレート | `ids` (≤100) + 本文系 `expansions` | 不要 | `data[]` + `includes` |

## 「索引 → ハイドレーション」2 段構え

フォルダ別取り込みは 1 リクエストで完結しない。**必ず 2 段**:

```
Step 1: GET /bookmarks/folders/{folder_id}    → ID 配列
Step 2: GET /2/tweets?ids=id1,id2,...         → 本文・著者・メディア
```

Step 1 の段階で `skipKnownIds` で既知 ID を除外すれば、Step 2 の API コール数
(と課金) を最小化できる。

## `/2/tweets?ids=` の 100 件チャンク

- 1 リクエスト最大 100 ID。それ以上は 400 を返す。
- 100 件超のフォルダは for ループでチャンク分割。
- `includes.users` / `includes.media` はチャンクをまたいで重複し得る。
  `Map` / `Set` で `id` / `media_key` 単位の重複排除を必ず噛ませる。
- 削除済みツイートは `data[]` から欠落するだけで 200 が返る。
  `ids.length` と `data.length` が一致しない前提で書く。

## 長文ツイート (note_tweet)

- `tweet.fields=note_tweet` を付けないと 280 字で切り落とされる。
- 長文 (280 字超) は `text` ではなく `note_tweet.text` を見る。
- `text` 側は短縮形 + 末尾 `…` 形式のことがある。
- 実装では「`note_tweet` があればそちらを優先」のフォールバックロジックを書く。

## OAuth 2.0 PKCE + refresh

- scope 必須: `tweet.read users.read bookmark.read offline.access`
  → `offline.access` を抜くと `refresh_token` が発行されず、2 時間で詰む。
- `access_token` は短命 (2h)。`expires_in` + `obtained_at` で期限管理。
- 401 を受けたら `refresh_token` で 1 回だけ再試行 → 再保存。
- 手動 curl デバッグは refresh が走らないので 401 連発の原因になる。
  デバッグも auto-refresh ヘルパー経由で叩く。

## レート制限 (15 分窓 / user)

| エンドポイント | 上限 |
|---|---|
| `/bookmarks` | 180 req |
| `/bookmarks/folders` | 50 req |
| `/bookmarks/folders/{id}` | 50 req |
| `/tweets` | 300 req |

- 429 時は `Retry-After` ヘッダを尊重 (無ければ 15 秒待機)。
- 多フォルダ × ハイドレーションだと `/bookmarks/folders/{id}` 側 (50/15min)
  が先に枯渇する。フォルダ数が多い vault では実行頻度を抑える。

## 間違えがちなポイント

1. **フォルダ別エンドポイントに本文系パラメータを付ける**
   - `/bookmarks/folders/{id}?tweet.fields=...` → 400。索引専用。
2. **存在しない `/bookmarks?folder_id=...` を期待する**
   - 通常の `/bookmarks` は `folder_id` クエリを受け付けない。
3. **`/2/tweets?ids=` で 100 件超を一発で投げる**
   - チャンク分割必須。境界条件 (0 件 / 100 件ちょうど) のテストを書く。
4. **`includes` の重複排除を忘れる**
   - 同じユーザーが複数チャンクに跨ると `users[]` にダブる。`Map` で dedup。
5. **`note_tweet` を見落として 280 字で切れたまま保存**
   - `tweet.fields` に必ず `note_tweet` を含め、抽出側でも優先順位を組む。
6. **`access_token` を curl 直貼りしてデバッグ → 401 が refresh されない**
   - auto-refresh ラッパ経由で叩く。手動 curl は本質的に再現性が低い。
7. **フォルダ索引のページング (`/bookmarks/folders/{id}`) — 未検証領域**
   - 実測 (11件) では `meta` 自体返らず、別の query (`tweet.fields` 等) も
     `[id, folder_id] のみ受付` 400 で拒否される。
   - ただし **`pagination_token` 単独での挙動は未検証**。X API ドキュメントは
     ページング有りと示唆する可能性がある。
   - 現状は `meta.next_token` を検出したら警告ログを出すランタイムガードを
     入れて可視化のみ。大量フォルダで警告が出たら本格対応 (パラメータ受付の
     再 probe → 受け付けるならページングループ実装) する。
8. **削除済みツイートを考慮しない (`data.length === ids.length` 前提)**
   - 落差で配列インデックス参照が壊れる。id ベースで Map 化する。
9. **「3 件連続 known → 早期打ち切り」を 2 段フローに持ち込む**
   - 旧ページング前提の最適化。新フローでは ID 一括取得 + 事前フィルタが
     正しい (ハイドレーションだけ最小化)。
10. **`redirect_uri` / `client_id` を `/authorize` と `/token` で食い違わせる**
    - PKCE は両者完全一致が必須。`http://127.0.0.1` と `http://localhost`
      も別物として扱われる。
