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
  if (Array.isArray(o)) {
    const head = o.slice(0, 2).map(redact);
    return o.length > 2 ? [...head, `<...${o.length - 2} more items, total=${o.length}>`] : head;
  }
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

  const ctx = { accessToken, clientId, clientSecret, fetchFn: fetch };

  // [A] /bookmarks/folders/{id} → ツイートID一覧 (前回の結果から判明)
  const idsUrl = new URL(`https://api.x.com/2/users/${USER_ID}/bookmarks/folders/${folderId}`);
  console.log('### [A] folder → tweet IDs (no params)');
  const idsRes = await xGet<{ data?: { id: string }[]; meta?: unknown }>(idsUrl.toString(), ctx);
  console.log(JSON.stringify(redact(idsRes), null, 2));

  // [A2] meta だけ生で覗く (pagination_token などがあるか)
  console.log('\n### [A2] raw meta object (un-redacted, IDs only schema)');
  console.log(JSON.stringify({ keys: Object.keys(idsRes), meta: idsRes.meta ?? null }, null, 2));

  const tweetIds = (idsRes.data ?? []).map((d) => d.id).slice(0, 5);
  if (tweetIds.length === 0) {
    console.log('No tweet IDs returned; skipping hydration probe.');
    return;
  }

  // [C] /2/tweets?ids=... でハイドレーション
  const hydrateUrl = new URL('https://api.x.com/2/tweets');
  hydrateUrl.searchParams.set('ids', tweetIds.join(','));
  hydrateUrl.searchParams.set(
    'tweet.fields',
    'id,text,created_at,author_id,note_tweet,attachments,entities,referenced_tweets'
  );
  hydrateUrl.searchParams.set('expansions', 'author_id,attachments.media_keys');
  hydrateUrl.searchParams.set('user.fields', 'id,name,username');
  hydrateUrl.searchParams.set('media.fields', 'media_key,type,url,preview_image_url,variants');
  console.log('\n### [C] hydrate via /2/tweets?ids=...');
  const hydrated = await xGet<unknown>(hydrateUrl.toString(), ctx);
  console.log(JSON.stringify(redact(hydrated), null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
