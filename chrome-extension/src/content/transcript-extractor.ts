import type { TranscriptSegment } from '../shared/types';
import { LANGUAGE_PRIORITY } from '../shared/constants';

interface CaptionTrack {
  baseUrl: string;
  languageCode: string;
  kind?: string;
  name?: { simpleText?: string };
}

/**
 * YouTubeページから利用可能なキャプショントラックを取得する。
 * ytInitialPlayerResponse はページのscriptタグ内にJSON埋め込みされている。
 */
export function getCaptionTracks(): CaptionTrack[] {
  try {
    // YouTube ページ内の ytInitialPlayerResponse を探す
    const scripts = document.querySelectorAll('script');
    for (const script of scripts) {
      const text = script.textContent || '';
      const match = text.match(/ytInitialPlayerResponse\s*=\s*(\{.+?\});/s);
      if (match) {
        const playerResponse = JSON.parse(match[1]);
        return extractTracksFromResponse(playerResponse);
      }
    }

    // フォールバック: window.__INITIAL_DATA__ 等から取得を試行
    const ytDataMatch = document.body.innerHTML.match(
      /"captions"\s*:\s*(\{"playerCaptionsTracklistRenderer".+?\})\s*,\s*"/s
    );
    if (ytDataMatch) {
      const captionsData = JSON.parse(ytDataMatch[1]);
      return captionsData.playerCaptionsTracklistRenderer?.captionTracks || [];
    }
  } catch (e) {
    console.error('[YT Transcript] キャプショントラック取得失敗:', e);
  }
  return [];
}

function extractTracksFromResponse(playerResponse: Record<string, unknown>): CaptionTrack[] {
  try {
    const captions = playerResponse.captions as Record<string, unknown> | undefined;
    if (!captions) return [];
    const renderer = captions.playerCaptionsTracklistRenderer as Record<string, unknown> | undefined;
    if (!renderer) return [];
    return (renderer.captionTracks as CaptionTrack[]) || [];
  } catch {
    return [];
  }
}

/**
 * 利用可能な言語コードのリストを返す。
 */
export function getAvailableLanguages(tracks: CaptionTrack[]): string[] {
  return [...new Set(tracks.map(t => t.languageCode))];
}

/**
 * 優先順位に従ってベストなキャプショントラックを選択する。
 * 優先順: 手動日本語 > 自動生成日本語 > 手動英語 > 自動生成英語 > 最初のトラック
 */
export function selectBestTrack(tracks: CaptionTrack[]): CaptionTrack | null {
  if (tracks.length === 0) return null;

  // 手動キャプション（kind !== 'asr'）を優先
  const manualTracks = tracks.filter(t => t.kind !== 'asr');
  const autoTracks = tracks.filter(t => t.kind === 'asr');

  for (const lang of LANGUAGE_PRIORITY) {
    const manual = manualTracks.find(t => t.languageCode === lang);
    if (manual) return manual;
  }

  for (const lang of LANGUAGE_PRIORITY) {
    const auto = autoTracks.find(t => t.languageCode === lang);
    if (auto) return auto;
  }

  // いずれにも一致しない場合は最初のトラック
  return manualTracks[0] || autoTracks[0] || tracks[0];
}

/**
 * キャプショントラックのURLからXMLトランスクリプトをフェッチ・パースする。
 */
export async function fetchTranscript(track: CaptionTrack): Promise<TranscriptSegment[]> {
  const response = await fetch(track.baseUrl);
  if (!response.ok) {
    throw new Error(`トランスクリプト取得失敗: ${response.status} ${response.statusText}`);
  }

  const xmlText = await response.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, 'text/xml');

  const textElements = doc.querySelectorAll('text');
  const segments: TranscriptSegment[] = [];

  for (const el of textElements) {
    const start = parseFloat(el.getAttribute('start') || '0');
    const duration = parseFloat(el.getAttribute('dur') || '0');
    // HTMLエンティティのデコード
    const text = decodeHTMLEntities(el.textContent || '');

    if (text.trim()) {
      segments.push({ text: text.trim(), start, duration });
    }
  }

  return segments;
}

/**
 * セグメント配列をプレーンテキストに結合する。
 */
export function segmentsToFullText(segments: TranscriptSegment[]): string {
  return segments.map(s => s.text).join(' ');
}

function decodeHTMLEntities(text: string): string {
  const textarea = document.createElement('textarea');
  textarea.innerHTML = text;
  return textarea.value;
}
