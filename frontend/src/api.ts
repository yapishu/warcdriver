import type {
  ArchiveJob,
  ArchiveJobDetail,
  ArchiveScope,
  CookieProfile,
  CookieProfileSourceType,
  Item,
  ItemDetail,
  Settings,
  Site,
  User,
  Visibility,
  WarcMetadata
} from "./types";

type RequestOptions = Omit<RequestInit, "body"> & { body?: unknown };

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new ApiError(response.status, data?.error || response.statusText);
  return data as T;
}

export type CreateJobPayload = {
  url: string;
  scope: ArchiveScope;
  depth: number;
  maxPages: number;
  visibility?: Visibility;
  prefix?: string;
  pathExcludeRx?: string;
  cookieProfileId?: string;
  enrich?: boolean;
};

export type CreateCookieProfilePayload = {
  name: string;
  sourceType: CookieProfileSourceType;
  host?: string;
  cookieHeader?: string;
  content?: string;
};

export type CreateUserPayload = {
  username: string;
  email?: string;
  displayName?: string;
  password: string;
  isAdmin?: boolean;
};

export type UpdateUserPayload = {
  username?: string;
  email?: string;
  displayName?: string;
  password?: string;
  isAdmin?: boolean;
};

export const api = {
  login: (username: string, password: string) =>
    request<{ user: User }>("/api/auth/login", { method: "POST", body: { username, password } }),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),
  me: () => request<{ user: User }>("/api/me"),
  users: () => request<{ users: User[] }>("/api/users"),
  createUser: (body: CreateUserPayload) => request<User>("/api/users", { method: "POST", body }),
  updateUser: (id: string, body: UpdateUserPayload) =>
    request<User>(`/api/users/${id}`, { method: "PUT", body }),
  deleteUser: (id: string) => request<void>(`/api/users/${id}`, { method: "DELETE" }),
  createJob: (body: CreateJobPayload) =>
    request<ArchiveJob>("/api/archive-jobs", { method: "POST", body }),
  jobs: (limit = 50) => request<{ jobs: ArchiveJob[] }>(`/api/archive-jobs?limit=${limit}`),
  job: (id: string) => request<ArchiveJobDetail>(`/api/archive-jobs/${id}`),
  cancelJob: (id: string) => request<ArchiveJob>(`/api/archive-jobs/${id}/cancel`, { method: "POST" }),
  deleteJob: (id: string) => request<void>(`/api/archive-jobs/${id}`, { method: "DELETE" }),
  sites: () => request<{ sites: Site[] }>("/api/sites?limit=200"),
  site: (id: string) => request<{ site: Site; items: Item[] }>(`/api/sites/${id}`),
  deleteSite: (id: string) => request<void>(`/api/sites/${id}`, { method: "DELETE" }),
  items: (params: { siteId?: string; q?: string; limit?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.siteId) query.set("siteId", params.siteId);
    if (params.q) query.set("q", params.q);
    query.set("limit", String(params.limit || 100));
    return request<{ items: Item[] }>(`/api/items?${query}`);
  },
  item: (id: string) => request<ItemDetail>(`/api/items/${id}`),
  recaptureItem: (id: string) => request<ArchiveJob>(`/api/items/${id}/recapture`, { method: "POST" }),
  deleteItem: (id: string) => request<void>(`/api/items/${id}`, { method: "DELETE" }),
  warcMetadata: (id: string) => request<WarcMetadata>(`/api/warcs/${id}/metadata`),
  updateWarcVisibility: (id: string, visibility: Visibility) =>
    request<WarcMetadata>(`/api/warcs/${id}/visibility`, { method: "PUT", body: { visibility } }),
  settings: () => request<Settings>("/api/settings"),
  updateSettings: (body: Partial<Settings> & { openRouterApiKey?: string }) =>
    request<Settings>("/api/settings", { method: "PUT", body }),
  testOpenRouter: () => request<{ ok: boolean; message: string }>("/api/settings/openrouter/test", { method: "POST" }),
  cookieProfiles: () => request<{ profiles: CookieProfile[] }>("/api/cookie-profiles"),
  createCookieProfile: (body: CreateCookieProfilePayload) =>
    request<CookieProfile>("/api/cookie-profiles", { method: "POST", body }),
  deleteCookieProfile: (id: string) => request<void>(`/api/cookie-profiles/${id}`, { method: "DELETE" })
};
