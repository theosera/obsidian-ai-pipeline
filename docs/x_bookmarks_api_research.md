# X Bookmarks API: フォルダ別取得スキーマ調査

X API v2 のブックマークフォルダ関連エンドポイントの実挙動を調査した記録。
本実装（フォルダ別ブックマーク取り込み）の前提となる「索引 + ハイドレーション」
2 段構えのフローを確定させる目的で書き起こす。

## TL;DR

X API のフォルダ別ブックマーク取得は **1 リクエストで完結しない**。
以下の 2 段構えで実装する必要がある。

| 段 | エンドポイント | 役割 |
|---|---|---|
| ① 索引 | `GET /2/users/{id}/bookmarks/folders/{folder_id}` | フォルダ内のツイート ID 一覧だけを返す |
| ② ハイドレーション | `GET /2/tweets?ids=id1,id2,...` | ID から本文・著者・メディアを取得 |

## エンドポイント詳細

### ① 索引: `/2/users/{user_id}/bookmarks/folders/{folder_id}`

- **受け付けるクエリパラメータ**: なし（`id` と `folder_id` のみ、いずれもパス）
  - `tweet.fields`, `expansions`, `max_results`, `pagination_token` 等を付けると 400
- **レスポンス**:
  ```json
  {
    "data": [
      { "id": "1234567890123456789" },
      { "id": "9876543210987654321" }
    ]
  }
  ```
- **`meta` 無し** → 公式にはページング機構が無い（11 件のフォルダで実測）
  - 大量フォルダ（>100 件）での挙動は **未検証**。本実装後に要動作確認。

### ② ハイドレーション: `/2/tweets?ids=...`

- **`ids`**: カンマ区切り。**1 リクエスト最大 100 件**（X API 共通制限）
- **指定可能な expansions / fields**:
  - `tweet.fields=id,text,created_at,author_id,note_tweet,attachments,entities,referenced_tweets`
  - `expansions=author_id,attachments.media_keys`
  - `user.fields=id,name,username`
  - `media.fields=media_key,type,url,preview_image_url,variants`
- **レスポンス**:
  ```json
  {
    "data": [
      {
        "id": "...",
        "text": "...",
        "note_tweet": { "text": "<長文ツイートの本文>" },
        "author_id": "...",
        "created_at": "2025-...",
        "attachments": { "media_keys": ["3_..."] },
        "entities": { "urls": [...] },
        "referenced_tweets": [{ "type": "quoted", "id": "..." }],
        "edit_history_tweet_ids": ["..."]
      }
    ],
    "includes": {
      "users": [{ "id": "...", "name": "...", "username": "..." }],
      "media": [{ "media_key": "...", "type": "photo", "url": "https://pbs.twimg.com/..." }]
    }
  }
  ```

## 推奨実装フロー

```
1. fetchFolderTweetIds(userId, folderId): string[]
     → [] for 空フォルダ
     → 全 ID を 1 回で取得 (現状ページングは観測されていない)

2. chunk(ids, 100)

3. for each chunk:
     hydrateTweets(chunk) → { data, includes }

4. マージして既存の bookmarks DB / writer に流す
```

## 失敗の歴史 (調査メモ)

| 試行 | リクエスト | 結果 | 学び |
|---|---|---|---|
| 1 | curl 直叩き | 401 | access_token 期限切れ。auto-refresh 経由必須。 |
| 2 | `/folders/{id}` に `tweet.fields` | 400 | 「`[id, folder_id]` のみ受付」エラーで索引専用と判明 |
| 3 | `/bookmarks?folder_id=` | 400 | このクエリは存在しない |
| 4 | 索引 + `/2/tweets?ids=` の 2 段 | ✅ | 確定 |

## 参考

- 調査スクリプト: `inspect_folder_schema.ts` (実装完了後に削除予定)
- 既存実装: `x_bookmarks_api.ts` (auto-refresh / xGet ヘルパー)
