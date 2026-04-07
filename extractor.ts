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
    } catch(e){}
  }

  const elementsToRemove = document.querySelectorAll('script, style, noscript, svg, nav, footer, iframe');
  elementsToRemove.forEach(el => el.remove());

  const reader = new Readability(document);
  const article = reader.parse();

  if (!article) {
    throw new Error('Readability failed to parse the article.');
  }

  const markdownContent = turndownService.turndown(article.content);

  return {
    title: article.title,
    date: formattedDate,
    content: markdownContent,
    textContent: article.textContent,
    byline: article.byline,
    siteName: article.siteName,
    length: article.length,
    excerpt: article.excerpt,
    url: url
  };
}
