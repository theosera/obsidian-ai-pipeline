/**
 * SSRF guard for X media download URLs.
 *
 * Video / GIF variant URLs come straight from the X API response and are
 * fetched directly by `video_frames.ts::downloadVideo`. Without a host check, a
 * manipulated or compromised variant URL could aim the downloader at an
 * internal service or a cloud metadata endpoint (169.254.169.254). We allow
 * only X's media CDN (twimg.com) over https — a positive allowlist, so any IP
 * literal / private host / metadata endpoint fails by construction.
 */

const ALLOWED_HOST_EXACT = 'twimg.com';
const ALLOWED_HOST_SUFFIX = '.twimg.com';

/**
 * True iff `rawUrl` is an https URL whose host is `twimg.com` or a subdomain
 * (e.g. `video.twimg.com`). The leading-dot suffix check rejects look-alikes
 * such as `evil-twimg.com` and `video.twimg.com.attacker.tld`.
 */
export function isAllowedMediaUrl(rawUrl: string): boolean {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  const host = url.hostname.toLowerCase();
  return host === ALLOWED_HOST_EXACT || host.endsWith(ALLOWED_HOST_SUFFIX);
}
