import { ArticleData } from '../types';
import { SitePolicy } from './policy';

/**
 * パイプラインの基本処理単位。
 *
 * 通常の OneTab URL は preFetched=undefined で、fetcher/extractor を通して
 * HTML → ArticleData に変換する。
 *
 * X ブックマークなど API 経由で既に構造化済みのソースは preFetched に
 * ArticleData (実際は ApiBookmark) を詰めておけば、後段 processor は
 * 一切 fetch せずにそのまま Classifier/Router に流す。
 */
export interface ParsedEntry {
  url: string;
  title: string;
  policy: SitePolicy | 'x_bookmark';
  preFetched?: ArticleData;
}

/**
 * parsedEntries を構築する過程で発生するスキップ・失敗の記録。
 * 最終的に `failed_onetab_YYYYMMDD.txt` としてレポートディレクトリに吐き出される。
 */
export interface FailureRecord {
  url: string;
  title: string;
  reason: string;
}
