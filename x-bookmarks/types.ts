/**
 * X API v2 ブックマーク取得まわりの共有型定義。
 *
 * `api_client.ts` (フェッチ/変換) と `tokens.ts` (OAuth) の双方、および
 * `video_frames.ts` (メディア型) が参照する。低レベルの型をここに集約することで
 * api_client ↔ video_frames の循環依存を避ける (型の所有権を中立な層に置く)。
 */
import { ArticleData } from '../types';

export interface ApiBookmark extends ArticleData {
  xFolderName: string;
  xTweetId: string;
  /**
   * X Premium 長文ツイートの全文 (note_tweet.text)。
   * `text` が truncate されている場合のみセットされる。SQLite キャッシュに
   * full text を保存するため interactive.ts で参照される。
   */
  xNoteTweetText?: string;
  /**
   * 主動画の最高 bitrate ストリーミング URL (video / animated_gif があれば)。
   * 動画フレーム抽出 (X_VIDEO_FRAMES=true 時の opt-in パイプライン) で参照する。
   */
  xVideoUrl?: string;
  /** 主動画の長さ (ミリ秒)。フレーム抽出時の等間隔サンプル計算に使う。 */
  xVideoDurationMs?: number;
  /**
   * 当ブックマークが属する X folder の session_id。
   * sync phase で folder→session を解決した後に input_x_bookmarks.ts が
   * 各 ApiBookmark に注入する。.md frontmatter にも書き出される。
   */
  xSessionId?: string;
  /** session_id 紐付けに使った X 側 folder ID (frontmatter デバッグ用) */
  xFolderId?: string;
  /** ツイート作者の @ハンドル (Dataview テーブルの author 列に表示) */
  xAuthorHandle?: string;
  /** public_metrics.like_count */
  xLikes?: number;
  /** public_metrics.retweet_count */
  xRetweets?: number;
  /** public_metrics.reply_count */
  xReplies?: number;
}

export interface FetchOptions {
  maxItems?: number;
  skipKnownIds?: Set<string>;
  /**
   * 取得対象フォルダ ({id, name}) 配列。指定時はフォルダ列挙をスキップし
   * この ID のフォルダのみ本文取得する (--x-pick 経由のセレクト用)。
   * name は ApiBookmark.xFolderName に流れるので、Stage 1 で取得した
   * 表示名 (X 側 raw) をそのまま渡すこと。
   * 未指定 (undefined) は従来通り「全フォルダ」を取得。
   */
  selectedFolders?: { id: string; name: string }[];
  /**
   * `_Unfiled` (どのフォルダにも未割当のブックマーク) を取得対象に含めるか。
   * `--x-pick` で明示選択したときだけ true を渡す想定。デフォルト true (従来挙動)。
   */
  includeUnfiled?: boolean;
  /** テストから fetch をモックするための差し替え口 */
  fetchFn?: typeof fetch;
}

/** Stage 1 (一覧表示) でだけ使う、軽量な folder list 取得結果 */
export interface FolderListing {
  userId: string;
  username: string;
  folders: { id: string; name: string }[];
}

export interface StoredTokens {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  obtained_at: string;
}

export interface XUser {
  id: string;
  name?: string;
  username?: string;
}

export interface XPost {
  id: string;
  text: string;
  author_id?: string;
  created_at?: string;
  public_metrics?: {
    like_count?: number;
    reply_count?: number;
    retweet_count?: number;
    quote_count?: number;
  };
  entities?: {
    urls?: { url: string; expanded_url?: string; display_url?: string }[];
  };
  /**
   * X Premium 長文ツイート (~25,000 字) の本文。
   * これがあるツイートでは `text` は冒頭で `…` 付きで切れているため、
   * `note_tweet.text` を優先して使う。
   */
  note_tweet?: { text: string };
  /**
   * 添付メディアの media_key 一覧。実体は `BookmarksResponse.includes.media[]`
   * に展開されている (expansions=attachments.media_keys 指定時)。
   */
  attachments?: { media_keys?: string[] };
}

export interface XMediaVariant {
  bit_rate?: number;
  url: string;
  content_type?: string;
}

export interface XMediaResponse {
  media_key: string;
  type: string;
  duration_ms?: number;
  preview_image_url?: string;
  variants?: XMediaVariant[];
  alt_text?: string;
}

export interface BookmarksResponse {
  data?: XPost[];
  includes?: { users?: XUser[]; media?: XMediaResponse[] };
  meta?: { result_count?: number; next_token?: string };
}

export interface BookmarkFoldersResponse {
  data?: { id: string; name: string }[];
  meta?: { result_count?: number; next_token?: string };
}
