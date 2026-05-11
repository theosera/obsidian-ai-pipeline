/**
 * 使い捨て: フォルダ別ブックマーク API のレスポンススキーマを安全に出力する。
 * 文字列値は <str len=N> に置換、配列は先頭2件まで、URL は host のみに丸める。
 *
 * 実行:
 *   pnpm tsx --env-file=.env inspect_folder_schema.ts <FOLDER_ID>
 *
 * .env から X_CLIENT_ID / X_CLIENT_SECRET を読み込み、
 * x_tokens.json の access_token を auto-refresh して使用する。
 */
import { getValidAccessToken, xGet } from './x_bookmarks_api';

const USER_ID = '159735604';

function redact(o: unknown): unknown {
  if (Array.isArray(o)) return o.slice(0, 2).map(redact);
  if (o && typeof o === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(o)) {
      if (typeof v === 'string') {
        if (/^https?:\/\//.test(v)) {
          try {
            out[k] = `<url host=${new URL(v).host}>`;
          } catch {
            out[k] = `<str len=${v.length}>`;
          }
        } else {
          out[k] = `<str len=${v.length}>`;
        }
      } else {
        out[k] = redact(v);
      }
    }
    return out;
  }
  return o;
}

async function main() {
  const folderId = process.argv[2];
  if (!folderId) {
    console.error('Usage: tsx inspect_folder_schema.ts <FOLDER_ID>');
    process.exit(1);
  }
  const clientId = process.env.X_CLIENT_ID;
  const clientSecret = process.env.X_CLIENT_SECRET ?? '';
  if (!clientId) {
    console.error('X_CLIENT_ID is not set in .env');
    process.exit(1);
  }

  const accessToken = await getValidAccessToken(clientId, clientSecret);

  // 1) フォルダのメタデータ単独取得 (path 形式)
  const metaUrl = new URL(`https://api.x.com/2/users/${USER_ID}/bookmarks/folders/${folderId}`);
  console.log('### [A] folder meta (path form, no extra params)');
  const meta = await xGet<unknown>(metaUrl.toString(), {
    accessToken,
    clientId,
    clientSecret,
    fetchFn: fetch,
  });
  console.log(JSON.stringify(redact(meta), null, 2));

  // 2) フォルダ別ブックマーク (query 形式: folder_id をクエリで渡す)
  const listUrl = new URL(`https://api.x.com/2/users/${USER_ID}/bookmarks`);
  listUrl.searchParams.set('folder_id', folderId);
  listUrl.searchParams.set('max_results', '5');
  listUrl.searchParams.set(
    'tweet.fields',
    'id,text,created_at,author_id,note_tweet,attachments,entities,referenced_tweets'
  );
  listUrl.searchParams.set('expansions', 'author_id,attachments.media_keys');
  listUrl.searchParams.set('user.fields', 'id,name,username');
  listUrl.searchParams.set('media.fields', 'media_key,type,url,preview_image_url,variants');
  console.log('\n### [B] bookmarks?folder_id=...');
  const list = await xGet<unknown>(listUrl.toString(), {
    accessToken,
    clientId,
    clientSecret,
    fetchFn: fetch,
  });
  console.log(JSON.stringify(redact(list), null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
