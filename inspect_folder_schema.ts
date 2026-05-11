/**
 * 使い捨て: フォルダ別ブックマーク API のレスポンススキーマを安全に出力する。
 * 文字列値は <str len=N> に置換、配列は先頭2件まで、URL は host のみに丸める。
 *
 * 実行:
 *   tsx inspect_folder_schema.ts <FOLDER_ID>
 *
 * .env から X_CLIENT_ID / X_CLIENT_SECRET を読み込み、
 * x_tokens.json の access_token を auto-refresh して使用する。
 */
import 'dotenv/config';
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

  const url = new URL(`https://api.x.com/2/users/${USER_ID}/bookmarks/folders/${folderId}`);
  url.searchParams.set('max_results', '5');
  url.searchParams.set(
    'tweet.fields',
    'id,text,created_at,author_id,note_tweet,attachments,entities,referenced_tweets'
  );
  url.searchParams.set('expansions', 'author_id,attachments.media_keys');
  url.searchParams.set('user.fields', 'id,name,username');
  url.searchParams.set('media.fields', 'media_key,type,url,preview_image_url,variants');

  const res = await xGet<unknown>(url.toString(), {
    accessToken,
    clientId,
    clientSecret,
    fetchFn: fetch,
  });

  console.log(JSON.stringify(redact(res), null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
