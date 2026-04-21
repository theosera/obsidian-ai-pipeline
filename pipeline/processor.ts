import { fetchRenderedHtml } from '../fetcher';
import { extractAndConvert } from '../extractor';
import { classifyArticle } from '../classifier';
import { ClassificationResult, ProcessingResult } from '../types';
import { ApiBookmark } from '../x_bookmarks_api';
import { ParsedEntry, FailureRecord } from './types';

/**
 * ParsedEntry[] を並行処理し ProcessingResult[] に変換するワークホース。
 *
 * 各エントリで:
 *   1. preFetched があればそれを使う (X ブックマーク経由)
 *      なければ fetchRenderedHtml → extractAndConvert で ArticleData を生成
 *   2. x_bookmark policy は Classifier をバイパスし、X 専用フォルダに固定ルーティング
 *      - classify API コスト削減 (短文ツイートに LLM 推論を使わない)
 *      - X 由来記事の他ジャンル混入防止 (監査性)
 *   3. それ以外は classifyArticle で AI 2段分類
 *   4. __EXCLUDED__ 判定は failures に詰めてフィルタ
 *
 * 並行度は CONCURRENCY_LIMIT で頭打ち。5 は Playwright コンテキストの資源消費と
 * API レート制限を経験則でバランスした値。
 */

export interface ProcessorOptions {
  /** X 専用ベースフォルダ。env X_BOOKMARKS_FOLDER で上書き可能 */
  xBookmarksBaseFolder: string;
  /** 並行処理数の上限 */
  concurrencyLimit?: number;
}

const DEFAULT_CONCURRENCY_LIMIT = 5;

export async function processEntries(
  entries: ParsedEntry[],
  options: ProcessorOptions
): Promise<{ results: ProcessingResult[]; failures: FailureRecord[] }> {
  const { xBookmarksBaseFolder, concurrencyLimit = DEFAULT_CONCURRENCY_LIMIT } = options;
  const results: ProcessingResult[] = [];
  const failures: FailureRecord[] = [];
  let idCounter = 1;

  for (let i = 0; i < entries.length; i += concurrencyLimit) {
    const chunkEntries = entries.slice(i, i + concurrencyLimit);

    const mappedPromises = chunkEntries.map(async (entry, indexInChunk) => {
      const globalIndex = i + indexInChunk + 1;
      const { url, title, policy, preFetched } = entry;

      try {
        // X ブックマーク等、構造化済みソースは preFetched を使い fetch/extract を飛ばす
        const article = preFetched
          ? preFetched
          : extractAndConvert(await fetchRenderedHtml(url), url);
        const finalTitle = article.title || title;

        const classification: ClassificationResult = await buildClassification({
          policy,
          article,
          url,
          title: finalTitle,
          xBookmarksBaseFolder,
        });

        if (classification.proposedPath === '__EXCLUDED__') {
          console.log(
            `[${globalIndex}/${entries.length}] ${finalTitle.substring(0, 30)}... Skipped (Excluded by Rule)`
          );
          return {
            failure: true as const,
            url,
            title: finalTitle,
            reason: 'RuleBased Exclusion',
          };
        }

        console.log(
          `[${globalIndex}/${entries.length}] ${finalTitle.substring(0, 30)}... => ${classification.proposedPath}`
        );
        return {
          success: true as const,
          data: {
            url,
            title: finalTitle,
            policy,
            classification,
            articleContext: { ...article, url },
          },
        };
      } catch (err: any) {
        console.log(
          `[${globalIndex}/${entries.length}] ${title.substring(0, 30)}... Failed: ${err.message}`
        );
        return { failure: true as const, url, title, reason: err.message };
      }
    });

    const chunkResults = await Promise.all(mappedPromises);
    for (const res of chunkResults) {
      if (res.failure) {
        failures.push({ url: res.url, title: res.title, reason: res.reason });
      } else {
        results.push({
          id: idCounter++,
          status: 'success',
          ...res.data,
        });
      }
    }
  }

  return { results, failures };
}

/**
 * 分類結果を組み立てる。x_bookmark のときは AI 推論をスキップし、
 * 事前マッピング済みの X フォルダパスへ固定ルーティング。
 */
async function buildClassification(args: {
  policy: ParsedEntry['policy'];
  article: { textContent?: string; xFolderName?: string };
  url: string;
  title: string;
  xBookmarksBaseFolder: string;
}): Promise<ClassificationResult> {
  const { policy, article, url, title, xBookmarksBaseFolder } = args;

  if (policy === 'x_bookmark') {
    const xFolderSubPath = (article as ApiBookmark).xFolderName;
    return {
      proposedPath: xFolderSubPath ? `${xBookmarksBaseFolder}/${xFolderSubPath}` : xBookmarksBaseFolder,
      isNewFolder: false,
      confidence: 1.0,
      reasoning: xFolderSubPath
        ? `X bookmark folder → ${xFolderSubPath}`
        : 'X bookmark → 専用フォルダへ固定ルーティング',
    };
  }

  return classifyArticle(url, title, article.textContent);
}
