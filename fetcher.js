import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

let browserContext = null;

const CACHE_DIR = path.resolve(process.cwd(), '.html_cache');
if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function getCacheKey(url) {
  return crypto.createHash('md5').update(url).digest('hex') + '.html';
}

let initPromise = null;

export async function initBrowser() {
  if (browserContext) return;
  if (initPromise) return initPromise;
  
  initPromise = (async () => {
    const userDataDir = path.resolve(process.cwd(), '.chromium-data');
    if (!fs.existsSync(userDataDir)) {
      fs.mkdirSync(userDataDir, { recursive: true });
    }
    browserContext = await chromium.launchPersistentContext(userDataDir, { 
      headless: true, // User can manually run headed once to login
    });
  })();
  return initPromise;
}

export async function closeBrowser() {
  if (browserContext) {
    await browserContext.close();
    browserContext = null;
  }
}

/**
 * Fetches the rendered HTML of a given URL.
 * @param {string} url - The URL to fetch
 * @returns {Promise<string>} The rendered HTML string
 */
export async function fetchRenderedHtml(url) {
  const cachePath = path.join(CACHE_DIR, getCacheKey(url));
  if (fs.existsSync(cachePath)) {
    return fs.readFileSync(cachePath, 'utf8');
  }

  if (!browserContext) await initBrowser();
  const page = await browserContext.newPage();
  
  try {
    // Wait for the network to be idle to ensure JS has rendered the page
    await page.goto(url, { waitUntil: 'load', timeout: 30000 });
    
    let needsExtraWait = false;
    
    // Explicit wait for network idle if needed (fallback)
    try {
      await page.waitForLoadState('networkidle', { timeout: 10000 });
    } catch (e) {
      console.warn(`[Fetcher] Networkidle timeout for ${url}, proceeding with extra wait...`);
      needsExtraWait = true;
    }

    // A small buffer for late-rendering elements only if network didn't idle perfectly
    if (needsExtraWait) {
      await page.waitForTimeout(1000); 
    }
    const html = await page.content();
    
    // Save to local cache
    fs.writeFileSync(cachePath, html, 'utf8');
    
    return html;
  } catch (error) {
    console.error(`[Fetcher] Failed to fetch ${url}:`, error);
    throw error;
  } finally {
    await page.close();
  }
}
