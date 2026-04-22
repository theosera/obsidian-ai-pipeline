export type MatchType = "prefix" | "suffix";

export interface XTokenSet {
  access_token: string;
  refresh_token?: string;
  expires_at?: string;
  scope?: string;
  token_type?: string;
}

export interface XUser {
  id: string;
  name: string;
  username: string;
}

export interface XAuthor {
  id: string;
  name: string;
  username: string;
}

export interface XPublicMetrics {
  like_count: number;
  reply_count: number;
  retweet_count: number;
  quote_count: number;
}

export interface XUrlEntity {
  url: string;
  expanded_url?: string;
  display_url?: string;
  start?: number;
  end?: number;
}

export interface XPostEntities {
  urls?: XUrlEntity[];
}

export interface XPost {
  id: string;
  text: string;
  author_id: string;
  created_at: string;
  public_metrics: XPublicMetrics;
  entities?: XPostEntities;
}

export interface XFolder {
  id: string;
  name: string;
}

export interface XBookmarkPage {
  data: XPost[];
  includes?: { users?: XAuthor[] };
  meta?: {
    result_count?: number;
    next_token?: string;
  };
}

export interface FolderGroupingProposal {
  parent_folder: string;
  match_type: MatchType;
  token: string;
  children: string[];
  reason: string[];
  confidence: number;
}

export interface SkippedCandidate {
  token: string;
  match_type: MatchType;
  folders: string[];
  reason: string;
}

export interface FolderGroupingAnalysis {
  generated_at: string;
  source_root: string;
  analyzed_folder_count: number;
  proposals: FolderGroupingProposal[];
  skipped: SkippedCandidate[];
}

export interface FolderMapping {
  version: number;
  generated_at: string;
  source_root: string;
  groups: Array<{
    parent_folder: string;
    match_type: MatchType;
    token: string;
    children: string[];
  }>;
}
