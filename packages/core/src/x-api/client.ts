import type { EnvConfig } from "../config/env.js";
import type { XBookmarkPage, XFolder, XTokenSet, XUser } from "../types/shared.js";

const BOOKMARK_FIELDS = {
  tweetFields: "created_at,author_id,public_metrics",
  expansions: "author_id",
  userFields: "username,name",
  maxResults: "100"
};

export class XApiClient {
  constructor(private readonly config: EnvConfig, private tokens: XTokenSet) {}

  setTokens(tokens: XTokenSet): void {
    this.tokens = tokens;
  }

  private async request<T>(pathname: string, query?: URLSearchParams): Promise<T> {
    const url = new URL(`${this.config.xApiBaseUrl}${pathname}`);
    if (query) {
      url.search = query.toString();
    }

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.tokens.access_token}`
      }
    });

    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`X API request failed (${response.status}) ${pathname}: ${detail}`);
    }

    return (await response.json()) as T;
  }

  async getMe(): Promise<XUser> {
    const payload = await this.request<{ data: XUser }>("/2/users/me");
    return payload.data;
  }

  async getBookmarkFolders(userId: string): Promise<XFolder[]> {
    const folders: XFolder[] = [];
    let token: string | undefined;
    const seenTokens = new Set<string>();
    const maxPages = 1000;
    let pageCount = 0;

    do {
      if (pageCount >= maxPages) {
        throw new Error(`Bookmark folder pagination exceeded limit (${maxPages}).`);
      }
      pageCount += 1;
      const query = new URLSearchParams({
        max_results: BOOKMARK_FIELDS.maxResults
      });
      if (token) {
        query.set("pagination_token", token);
      }

      const payload = await this.request<{ data?: XFolder[]; meta?: { next_token?: string } }>(
        `/2/users/${userId}/bookmarks/folders`,
        query
      );
      folders.push(...(payload.data ?? []));
      const nextToken = payload.meta?.next_token;
      if (nextToken && seenTokens.has(nextToken)) {
        throw new Error("Bookmark folder pagination repeated a next_token. Stopping to avoid loop.");
      }
      if (nextToken) {
        seenTokens.add(nextToken);
      }
      token = nextToken;
    } while (token);

    return folders;
  }

  async getBookmarksAll(userId: string): Promise<XBookmarkPage[]> {
    return this.getPaginated(`/2/users/${userId}/bookmarks`);
  }

  async getBookmarksByFolder(userId: string, folderId: string): Promise<XBookmarkPage[]> {
    return this.getPaginated(`/2/users/${userId}/bookmarks/folders/${folderId}`);
  }

  private async getPaginated(pathname: string): Promise<XBookmarkPage[]> {
    const pages: XBookmarkPage[] = [];
    let token: string | undefined;

    do {
      const query = new URLSearchParams({
        max_results: BOOKMARK_FIELDS.maxResults,
        "tweet.fields": BOOKMARK_FIELDS.tweetFields,
        expansions: BOOKMARK_FIELDS.expansions,
        "user.fields": BOOKMARK_FIELDS.userFields
      });
      if (token) {
        query.set("pagination_token", token);
      }

      const page = await this.request<XBookmarkPage>(pathname, query);
      pages.push(page);
      token = page.meta?.next_token;
    } while (token);

    return pages;
  }
}
