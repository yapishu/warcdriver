export type User = {
  id: string;
  username: string;
  email?: string;
  displayName: string;
  isAdmin: boolean;
  createdAt: string;
};

export type ArchiveScope = "single_page" | "linked_pages" | "same_subdomain" | "prefix" | "explicit_urls" | "substack";
export type Visibility = "private" | "public";
export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "canceled";

export type ArchiveJob = {
  id: string;
  url: string;
  scope: ArchiveScope;
  depth: number;
  maxPages: number;
  visibility: Visibility;
  status: JobStatus;
  statusMessage?: string;
  error?: string;
  captureId?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
};

export type JobLog = {
  at: string;
  level: string;
  message: string;
};

export type ArchiveJobDetail = ArchiveJob & {
  logs: JobLog[];
  items?: Item[];
};

export type Site = {
  id: string;
  host: string;
  title?: string;
  summary?: string;
  itemCount: number;
  createdAt: string;
  updatedAt: string;
};

export type SiteIndexEntry = {
  status: "succeeded" | "failed";
  url: string;
  error?: string;
  item?: Item;
};

export type SiteIndex = {
  site: Site;
  pages: SiteIndexEntry[];
  total: number;
  limit: number;
  offset: number;
  canManage: boolean;
  visibility: Visibility;
};

export type SubstackUpdateResult = {
  newPosts: number;
  totalPosts: number;
  job?: ArchiveJob;
};

export type Item = {
  id: string;
  siteId: string;
  captureId: string;
  url: string;
  canonicalUrl?: string;
  title: string;
  summary?: string;
  tags?: string[];
  replayable: boolean;
  depth: number;
  statusCode?: number;
  contentType?: string;
  createdAt: string;
};

export type ItemDetail = Item & {
  markdown?: string;
  warcDownloadUrl?: string;
  replayUrl?: string;
};

export type WarcMetadata = {
  captureId: string;
  startUrl: string;
  title?: string;
  visibility: Visibility;
  createdAt: string;
};

export type Settings = {
  openRouterModel: string;
  openRouterApiKeyConfigured?: boolean;
  enrichmentEnabled: boolean;
  filterLists: string[];
  userAgent?: string;
  captureHeadless: boolean;
  capturePageDelay: number;
  capturePageRetries: number;
  captureUseSitemap: boolean;
};

export type CookieProfileSourceType = "raw_header" | "netscape" | "json";

export type CookieProfile = {
  id: string;
  name: string;
  sourceType: CookieProfileSourceType;
  host?: string;
  createdAt: string;
};
