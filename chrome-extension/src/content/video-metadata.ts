import type { VideoMetadata } from '../shared/types';

/**
 * YouTube動画ページからメタデータを抽出する。
 * og:タグ、microdata、ytInitialDataから取得。
 */
export function extractVideoMetadata(): VideoMetadata {
  const pageUrl = window.location.href;
  const rawVideoId = new URL(pageUrl).searchParams.get('v') || '';
  const videoId = /^[a-zA-Z0-9_-]{11}$/.test(rawVideoId) ? rawVideoId : '';

  const title = getMetaContent('og:title')
    || document.title.replace(/ - YouTube$/, '')
    || '';

  const channel = getChannelName();
  const publishedDate = getPublishedDate();
  const description = getMetaContent('og:description') || '';
  const duration = getDuration();

  return {
    videoId,
    title,
    channel,
    publishedDate,
    url: videoId ? `https://www.youtube.com/watch?v=${videoId}` : pageUrl,
    description,
    duration,
    language: '',
  };
}

function getMetaContent(property: string): string {
  const meta = document.querySelector(`meta[property="${property}"]`)
    || document.querySelector(`meta[name="${property}"]`);
  return meta?.getAttribute('content') || '';
}

function getChannelName(): string {
  // YouTube LD+JSON microdata
  const ldJson = document.querySelector('script[type="application/ld+json"]');
  if (ldJson?.textContent) {
    try {
      const data = JSON.parse(ldJson.textContent);
      if (Array.isArray(data)) {
        for (const item of data) {
          if (item['@type'] === 'VideoObject' && item.author?.name) {
            return item.author.name;
          }
        }
      } else if (data['@type'] === 'VideoObject' && data.author?.name) {
        return data.author.name;
      }
    } catch { /* ignore parse errors */ }
  }

  // フォールバック: DOMから取得
  const channelEl = document.querySelector(
    'ytd-channel-name yt-formatted-string a, #channel-name a, #owner-name a'
  );
  return channelEl?.textContent?.trim() || '';
}

function getPublishedDate(): string {
  // LD+JSON microdata
  const ldJson = document.querySelector('script[type="application/ld+json"]');
  if (ldJson?.textContent) {
    try {
      const data = JSON.parse(ldJson.textContent);
      const extract = (obj: Record<string, unknown>): string => {
        if (obj['@type'] === 'VideoObject') {
          const date = (obj.uploadDate || obj.datePublished) as string | undefined;
          if (date) {
            try {
              return new Date(date).toISOString().split('T')[0];
            } catch { /* ignore */ }
          }
        }
        return '';
      };

      if (Array.isArray(data)) {
        for (const item of data) {
          const result = extract(item);
          if (result) return result;
        }
      } else {
        const result = extract(data);
        if (result) return result;
      }
    } catch { /* ignore */ }
  }

  // フォールバック: meta datePublished
  const dateMeta = getMetaContent('datePublished');
  if (dateMeta) {
    try {
      return new Date(dateMeta).toISOString().split('T')[0];
    } catch { /* ignore */ }
  }

  // 最終フォールバック: 今日の日付
  return new Date().toISOString().split('T')[0];
}

function getDuration(): string {
  // LD+JSON
  const ldJson = document.querySelector('script[type="application/ld+json"]');
  if (ldJson?.textContent) {
    try {
      const data = JSON.parse(ldJson.textContent);
      const extract = (obj: Record<string, unknown>): string => {
        if (obj['@type'] === 'VideoObject' && obj.duration) {
          return parseDuration(obj.duration as string);
        }
        return '';
      };

      if (Array.isArray(data)) {
        for (const item of data) {
          const result = extract(item);
          if (result) return result;
        }
      } else {
        const result = extract(data);
        if (result) return result;
      }
    } catch { /* ignore */ }
  }

  // フォールバック: DOM
  const durationEl = document.querySelector('.ytp-time-duration');
  return durationEl?.textContent?.trim() || '';
}

/** ISO 8601 duration (PT1H2M3S) を "1:02:03" 形式に変換 */
function parseDuration(iso: string): string {
  const match = iso.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return iso;

  const hours = parseInt(match[1] || '0', 10);
  const minutes = parseInt(match[2] || '0', 10);
  const seconds = parseInt(match[3] || '0', 10);

  if (hours > 0) {
    return `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  }
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}
