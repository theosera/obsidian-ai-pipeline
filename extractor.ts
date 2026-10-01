import { Readability } from '@mozilla/readability';
import { JSDOM } from 'jsdom';
import TurndownService from 'turndown';
import { ArticleData } from './types';

const turndownService = new TurndownService({
  headingStyle: 'atx',
  codeBlockStyle: 'fenced'
});

export function extractAndConvert(html: string, url: string): ArticleData & { length?: number; byline?: string } {
  const dom = new JSDOM(html, { url });
  const document = dom.window.document;
  
  let publishedDate: string | null = null;
  const publishedMeta = document.querySelector('meta[property="article:published_time"], meta[name="pubdate"], meta[property="og:pubdate"], meta[property="article:published"]');
  if (publishedMeta) {
    publishedDate = publishedMeta.getAttribute('content');
  } else {
    const timeEl = document.querySelector('time[datetime]');
    if (timeEl) {
      publishedDate = timeEl.getAttribute('datetime');
    }
  }

  let formattedDate: string | undefined = undefined;
  if (publishedDate) {
    try {
      const d = new Date(publishedDate);
      if (!isNaN(d.getTime())) {
        formattedDate = d.toISOString().split('T')[0];
      }
    } catch {}
  }

  const elementsToRemove = document.querySelectorAll('script, style, noscript, svg, nav, footer, iframe');
  elementsToRemove.forEach(el => el.remove());

  const reader = new Readability(document);
  const article = reader.parse();

  if (!article || article.content == null) {
    throw new Error('Readability failed to parse the article.');
  }

  const markdownContent = turndownService.turndown(article.content);

  // @mozilla/readability >= 0.6 types every field as `T | null | undefined`;
  // ArticleData uses optional fields, so fold null into undefined here.
  return {
    title: article.title ?? undefined,
    date: formattedDate,
    content: markdownContent,
    textContent: article.textContent ?? undefined,
    byline: article.byline ?? undefined,
    siteName: article.siteName ?? undefined,
    length: article.length ?? undefined,
    excerpt: article.excerpt ?? undefined,
    url: url
  };
}
