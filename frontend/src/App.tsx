import {
  Archive,
  BookOpen,
  CheckCircle2,
  Clock3,
  Cookie,
  Database,
  Download,
  Eye,
  EyeOff,
  FileText,
  Globe2,
  KeyRound,
  Library,
  ListFilter,
  Loader2,
  LogOut,
  Maximize2,
  Moon,
  RefreshCw,
  Search,
  Settings,
  Shield,
  Sparkles,
  Sun,
  Tags,
  Trash2,
  XCircle
} from "lucide-react";
import React, { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";
import { api, ApiError, type CreateJobPayload } from "./api";
import type {
  ArchiveJob,
  ArchiveJobDetail,
  ArchiveScope,
  CookieProfile,
  Item,
  ItemDetail,
  Settings as SettingsType,
  Site,
  User,
  Visibility
} from "./types";

type Route =
  | { name: "dashboard" }
  | { name: "jobs" }
  | { name: "job"; id: string }
  | { name: "sites" }
  | { name: "site"; id: string }
  | { name: "items" }
  | { name: "item"; id: string }
  | { name: "users" }
  | { name: "settings" }
  | { name: "viewer"; id: string };

type LoadState<T> =
  | { state: "loading" }
  | { state: "error"; error: string }
  | { state: "ready"; data: T };

type ConfirmButtonProps = {
  className?: string;
  title: string;
  detail: string;
  confirmLabel?: string;
  children: ReactNode;
  onConfirm: () => Promise<void> | void;
};

const routeLinks = [
  { route: "dashboard", label: "Overview", icon: Library },
  { route: "jobs", label: "Queue", icon: Clock3 },
  { route: "sites", label: "Sites", icon: Globe2 },
  { route: "items", label: "Index", icon: BookOpen },
  { route: "users", label: "Users", icon: Shield, adminOnly: true },
  { route: "settings", label: "Settings", icon: Settings }
];

const replayDarkModeKey = "warcdriver.replayDarkMode";
const replayChromeHiddenKey = "warcdriver.replayChromeHidden";
const cookieProfilesChangedEvent = "warcdriver:cookie-profiles-changed";

const replayFrameDarkCSS = `
  :root {
    color-scheme: dark;
    --sl-color-neutral-0: #121513;
    --sl-color-neutral-50: #171b18;
    --sl-color-neutral-100: #1d231f;
    --sl-color-neutral-200: #2a332e;
    --sl-color-neutral-300: #3b4741;
    --sl-color-neutral-600: #b1bcb5;
    --sl-color-neutral-900: #f0eadc;
    --sl-color-primary-500: #2ea48f;
    --sl-color-primary-600: #32b59f;
  }

  html,
  body {
    background: #0d100f !important;
    color: #eee7da !important;
  }
`;

const replayAppDarkCSS = `
  :host {
    color-scheme: dark;
    background: #0d100f;
    color: #eee7da;
  }

  .navbar {
    background: #121613 !important;
    border-bottom-color: #2b332f !important;
    color: #eee7da !important;
  }

  .navbar a,
  .navbar span,
  .navbar-item {
    color: #eee7da !important;
  }

  .navbar-burger span {
    background-color: #eee7da !important;
  }

  wr-item {
    background: #0d100f;
  }
`;

const replayItemDarkCSS = `
  :host {
    color-scheme: dark;
    background: #0d100f;
    color: #eee7da;
    --sl-color-neutral-0: #121513;
    --sl-color-neutral-50: #171b18;
    --sl-color-neutral-100: #1d231f;
    --sl-color-neutral-200: #2a332e;
    --sl-color-neutral-300: #3b4741;
    --sl-color-neutral-600: #b1bcb5;
    --sl-color-neutral-900: #f0eadc;
    --sl-color-primary-500: #2ea48f;
    --sl-color-primary-600: #32b59f;
  }

  .replay-bar {
    background: #121613 !important;
    border-bottom-color: #2b332f !important;
    color: #eee7da !important;
  }

  .breadbar {
    background: #171b18 !important;
    color: #d7ded9 !important;
  }

  input#url,
  .input {
    background: #0c0f0e !important;
    border-color: #3a443f !important;
    color: #f1eadf !important;
  }

  input#url::placeholder {
    color: #7f8a84 !important;
  }

  #datetime {
    background: #0c0f0e !important;
    color: #b5c0ba !important;
  }

  #datetime::before {
    background: linear-gradient(90deg, rgba(12, 15, 14, 0), #0c0f0e 50%, #0c0f0e) !important;
  }

  .button,
  button,
  sl-button::part(base) {
    background: #171b18 !important;
    border-color: #3a443f !important;
    color: #eee7da !important;
  }

  .button:hover,
  button:hover {
    background: #202720 !important;
  }

  #contents,
  #contents.is-light,
  .panel,
  .tabs,
  .menu,
  .dropdown-content {
    background: #101411 !important;
    color: #eee7da !important;
  }

  .tabs a,
  .timestamp-dropdown-btn,
  .dropdown-item,
  .menu-head {
    color: #d7ded9 !important;
  }

  .timestamp-count-badge {
    background: #0f766e !important;
    color: #f7fff9 !important;
  }

  .gutter.gutter-horizontal {
    background-color: #3a443f !important;
  }
`;

const replayCollDarkCSS = `
  :host {
    color-scheme: dark;
    background: #0b0d0c;
    color: #eee7da;
  }

  .iframe-container {
    background: #0b0d0c !important;
  }

  .intro-panel.panel {
    background: #121613 !important;
    color: #eee7da !important;
    border-color: #2b332f !important;
  }

  .iframe-main.modal-bg {
    background-color: rgba(7, 9, 8, 0.72) !important;
  }
`;

const replayAppChromeHiddenCSS = `
  .navbar {
    display: none !important;
  }

  wr-item {
    min-height: 0 !important;
  }
`;

const replayItemChromeHiddenCSS = `
  .replay-bar,
  .breadbar {
    display: none !important;
  }

  #tabContents {
    min-height: 0 !important;
    height: 100% !important;
  }
`;

function storedReplayDarkMode() {
  try {
    return window.localStorage.getItem(replayDarkModeKey) === "1";
  } catch {
    return false;
  }
}

function writeReplayDarkMode(enabled: boolean) {
  try {
    window.localStorage.setItem(replayDarkModeKey, enabled ? "1" : "0");
  } catch {
    // Local storage is best effort; the visible toggle still works for this tab.
  }
}

function storedReplayChromeHidden() {
  try {
    return window.localStorage.getItem(replayChromeHiddenKey) === "1";
  } catch {
    return false;
  }
}

function writeReplayChromeHidden(enabled: boolean) {
  try {
    window.localStorage.setItem(replayChromeHiddenKey, enabled ? "1" : "0");
  } catch {
    // Local storage is best effort; the visible toggle still works for this tab.
  }
}

function notifyCookieProfilesChanged() {
  window.dispatchEvent(new Event(cookieProfilesChangedEvent));
}

function scopeLabel(scope: ArchiveScope | string) {
  const labels: Record<string, string> = {
    single_page: "Single page",
    linked_pages: "Linked pages",
    same_subdomain: "Subdomain",
    prefix: "Prefix",
    explicit_urls: "Explicit URLs"
  };
  return labels[scope] || scope.replace(/_/g, " ");
}

function depthLabel(depth: number) {
  return depth < 0 ? "All" : String(depth);
}

function maxPagesLabel(maxPages: number) {
  return maxPages < 1 ? "Unlimited" : String(maxPages);
}

function replayHostLabel(rawURL: string) {
  try {
    return new URL(rawURL).hostname;
  } catch {
    return rawURL || "Archived page";
  }
}

function upsertScopedStyle(root: Document | ShadowRoot | null | undefined, id: string, cssText: string) {
  if (!root) return;
  const parent: HTMLElement | ShadowRoot | null = "head" in root ? root.head : root;
  if (!parent) return;
  let style = parent.querySelector<HTMLStyleElement>(`#${id}`);
  if (!cssText) {
    style?.remove();
    return;
  }
  if (!style) {
    style = parent.ownerDocument.createElement("style");
    style.id = id;
    parent.appendChild(style);
  }
  style.textContent = cssText;
}

function syncReplayBrowserChrome(darkMode: boolean, chromeHidden: boolean) {
  const embed = document.querySelector("replay-web-page") as (HTMLElement & { shadowRoot?: ShadowRoot }) | null;
  const outerFrame = embed?.shadowRoot?.querySelector("iframe") as HTMLIFrameElement | null;
  const frameDoc = outerFrame?.contentDocument;
  if (!frameDoc) return;

  upsertScopedStyle(frameDoc, "warcdriver-replay-frame-theme", darkMode ? replayFrameDarkCSS : "");

  const app = frameDoc.querySelector("replay-app-main") as (HTMLElement & { shadowRoot?: ShadowRoot }) | null;
  upsertScopedStyle(app?.shadowRoot, "warcdriver-replay-app-theme", darkMode ? replayAppDarkCSS : "");
  upsertScopedStyle(app?.shadowRoot, "warcdriver-replay-app-hidden-chrome", chromeHidden ? replayAppChromeHiddenCSS : "");

  const item = app?.shadowRoot?.querySelector("wr-item") as (HTMLElement & { shadowRoot?: ShadowRoot }) | null;
  upsertScopedStyle(item?.shadowRoot, "warcdriver-replay-item-theme", darkMode ? replayItemDarkCSS : "");
  upsertScopedStyle(item?.shadowRoot, "warcdriver-replay-item-hidden-chrome", chromeHidden ? replayItemChromeHiddenCSS : "");

  const collection = item?.shadowRoot?.querySelector("wr-coll-replay") as (HTMLElement & { shadowRoot?: ShadowRoot }) | null;
  upsertScopedStyle(collection?.shadowRoot, "warcdriver-replay-coll-theme", darkMode ? replayCollDarkCSS : "");
}

export function App() {
  const [boot, setBoot] = useState<LoadState<User>>({ state: "loading" });
  const [route, setRoute] = useState<Route>(parseRoute());

  useEffect(() => {
    if (route.name === "viewer") {
      setBoot({ state: "error", error: "viewer" });
      return;
    }
    api
      .me()
      .then(({ user }) => setBoot({ state: "ready", data: user }))
      .catch(() => setBoot({ state: "error", error: "login" }));
  }, [route.name]);

  useEffect(() => {
    const onHash = () => setRoute(parseRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const onLogin = (user: User) => setBoot({ state: "ready", data: user });
  const onLogout = async () => {
    await api.logout();
    setBoot({ state: "error", error: "login" });
  };

  if (route.name === "viewer") return <ReplayPage id={route.id} />;
  if (boot.state === "loading") return <BootScreen />;
  if (boot.state !== "ready") return <LoginScreen onLogin={onLogin} />;

  return (
    <Frame user={boot.data} route={route} onLogout={onLogout}>
      <Page route={route} />
    </Frame>
  );
}

function parseRoute(): Route {
  const pathParts = window.location.pathname.split("/").filter(Boolean);
  if (pathParts[0] === "viewer" && pathParts[1]) return { name: "viewer", id: pathParts[1] };
  const parts = window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "jobs" && parts[1]) return { name: "job", id: parts[1] };
  if (parts[0] === "jobs") return { name: "jobs" };
  if (parts[0] === "sites" && parts[1]) return { name: "site", id: parts[1] };
  if (parts[0] === "sites") return { name: "sites" };
  if (parts[0] === "items" && parts[1]) return { name: "item", id: parts[1] };
  if (parts[0] === "items") return { name: "items" };
  if (parts[0] === "users") return { name: "users" };
  if (parts[0] === "settings") return { name: "settings" };
  if (parts[0] === "viewer" && parts[1]) return { name: "viewer", id: parts[1] };
  return { name: "dashboard" };
}

function href(route: string) {
  return `#/${route}`;
}

function viewerHref(captureID: string, targetURL?: string) {
  const path = `/viewer/${captureID}`;
  if (!targetURL) return path;
  return `${path}?url=${encodeURIComponent(targetURL)}`;
}

function warcDownloadHref(captureID: string) {
  return `/api/warcs/${captureID}/download`;
}

function BootScreen() {
  return (
    <main className="boot-screen">
      <div className="sigil">
        <Archive size={28} />
      </div>
      <Loader2 className="spin" size={20} />
    </main>
  );
}

function LoginScreen({ onLogin }: { onLogin: (user: User) => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const { user } = await api.login(String(form.get("username")), String(form.get("password")));
      onLogin(user);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-screen">
      <section className="login-card">
        <div className="login-mark">
          <Archive size={30} />
        </div>
        <div>
          <h1>WARCdriver</h1>
          <p>Private web archive</p>
        </div>
        <form onSubmit={submit} className="login-form">
          <label>
            Username
            <input name="username" type="text" autoComplete="username" required />
          </label>
          <label>
            Password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          {error && <div className="form-error">{error}</div>}
          <button className="primary-button" disabled={busy}>
            {busy ? <Loader2 className="spin" size={16} /> : <KeyRound size={16} />}
            Login
          </button>
        </form>
      </section>
    </main>
  );
}

function Frame({
  user,
  route,
  onLogout,
  children
}: {
  user: User;
  route: Route;
  onLogout: () => void;
  children: ReactNode;
}) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="wordmark" href={href("dashboard")}>
          <span className="wordmark-icon">
            <Archive size={19} />
          </span>
          <span>WARCdriver</span>
        </a>
        <nav className="side-nav">
          {routeLinks.filter((link) => !link.adminOnly || user.isAdmin).map((link) => {
            const Icon = link.icon;
            const active =
              route.name === link.route ||
              (link.route === "jobs" && route.name === "job") ||
              (link.route === "sites" && route.name === "site") ||
              (link.route === "items" && route.name === "item");
            return (
              <a key={link.route} className={active ? "active" : ""} href={href(link.route)}>
                <Icon size={17} />
                {link.label}
              </a>
            );
          })}
        </nav>
        <div className="sidebar-card">
          <div className="mini-label">Signed in</div>
          <strong>{user.displayName || user.username}</strong>
          <span>{user.email || `@${user.username}`}</span>
        </div>
        <button className="ghost-button sidebar-logout" onClick={onLogout}>
          <LogOut size={16} />
          Logout
        </button>
      </aside>
      <div className="workspace">
        <CaptureDock />
        <main className="page">{children}</main>
      </div>
    </div>
  );
}

function CaptureDock() {
  const [profiles, setProfiles] = useState<CookieProfile[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [scope, setScope] = useState<ArchiveScope>("single_page");
  const [depth, setDepth] = useState(0);
  const [unlimitedPages, setUnlimitedPages] = useState(false);
  const [maxPages, setMaxPages] = useState("100");
  const [lastLimitedMaxPages, setLastLimitedMaxPages] = useState("100");

  useEffect(() => {
    const refreshProfiles = () =>
      api.cookieProfiles()
      .then((profileData) => setProfiles(profileData.profiles))
      .catch(() => undefined);
    refreshProfiles();
    window.addEventListener(cookieProfilesChangedEvent, refreshProfiles);
    return () => window.removeEventListener(cookieProfilesChangedEvent, refreshProfiles);
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    setBusy(true);
    setMessage("");
    const form = new FormData(formEl);
    const payload: CreateJobPayload = {
      url: String(form.get("url")),
      scope,
      depth,
      maxPages: unlimitedPages ? 0 : Number(maxPages || lastLimitedMaxPages || 100),
      visibility: String(form.get("visibility") || "private") as Visibility,
      enrich: form.get("enrich") === "on"
    };
    const prefix = String(form.get("prefix") || "").trim();
    const pathExcludeRx = String(form.get("pathExcludeRx") || "").trim();
    const cookieProfileId = String(form.get("cookieProfileId") || "").trim();
    if (prefix) payload.prefix = prefix;
    if (pathExcludeRx) payload.pathExcludeRx = pathExcludeRx;
    if (cookieProfileId) payload.cookieProfileId = cookieProfileId;
    try {
      const job = await api.createJob(payload);
      window.location.hash = `/jobs/${job.id}`;
      formEl.reset();
      setScope("single_page");
      setDepth(0);
      setUnlimitedPages(false);
      setMaxPages("100");
      setLastLimitedMaxPages("100");
    } catch (err) {
      setMessage(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function updateScope(next: ArchiveScope) {
    setScope(next);
    if (next === "single_page" || next === "explicit_urls") {
      setDepth(0);
      updateUnlimitedPages(false);
    } else if (next === "same_subdomain" || next === "prefix") {
      setDepth(-1);
      updateUnlimitedPages(true);
    } else if (depth < 1) {
      setDepth(1);
      updateUnlimitedPages(false);
    }
  }

  function updateUnlimitedPages(next: boolean) {
    setUnlimitedPages(next);
    if (next) {
      setLastLimitedMaxPages(maxPages || lastLimitedMaxPages || "100");
      setMaxPages("");
    } else {
      setMaxPages(lastLimitedMaxPages || "100");
    }
  }

  function updateMaxPages(raw: string) {
    const next = raw.replace(/\D/g, "");
    setMaxPages(next);
    if (next) {
      setLastLimitedMaxPages(next);
    }
  }

  function updateDepth(raw: string) {
    const next = Math.max(0, Math.min(5, Number(raw) || 0));
    setDepth(next);
    if (next > 0 && scope === "single_page") {
      setScope("linked_pages");
    }
  }

  return (
    <header className="capture-dock">
      <form onSubmit={submit} className="capture-form">
        <div className="capture-main-row">
          <label className="url-field">
            URL
            <input name="url" type="url" placeholder="https://publication.substack.com/p/article" required />
          </label>
          <button className="primary-button capture-button" disabled={busy}>
            {busy ? <Loader2 className="spin" size={16} /> : <Archive size={16} />}
            Capture
          </button>
        </div>
        <div className="capture-options-row">
          <label className="scope-field">
            Scope
            <select name="scope" value={scope} onChange={(event) => updateScope(event.target.value as ArchiveScope)}>
              <option value="single_page">Single page</option>
              <option value="linked_pages">Linked pages</option>
              <option value="same_subdomain">Subdomain</option>
              <option value="prefix">URL prefix</option>
              <option value="explicit_urls">Explicit URLs</option>
            </select>
          </label>
          <label className="small-field">
            Depth
            {scope === "same_subdomain" || scope === "prefix" ? (
              <span className="static-input">All</span>
            ) : (
              <input
                name="depth"
                type="number"
                min={scope === "linked_pages" ? "1" : "0"}
                max="5"
                value={depth}
                disabled={scope === "single_page" || scope === "explicit_urls"}
                onChange={(event) => updateDepth(event.target.value)}
              />
            )}
          </label>
          <label className={`small-field max-pages-field${unlimitedPages ? " is-disabled" : ""}`}>
            Max pages
            <input
              name="maxPages"
              type="number"
              min="1"
              max="1000"
              value={maxPages}
              placeholder={unlimitedPages ? "Unlimited" : "100"}
              disabled={unlimitedPages}
              onChange={(event) => updateMaxPages(event.target.value)}
            />
          </label>
          <label className="check-field unlimited-field">
            <input
              name="unlimitedPages"
              type="checkbox"
              checked={unlimitedPages}
              onChange={(event) => updateUnlimitedPages(event.target.checked)}
            />
            Unlimited
          </label>
          <label className="cookie-field">
            Cookies
            <select name="cookieProfileId" defaultValue="">
              <option value="">None</option>
              {profiles.map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.name}
                </option>
              ))}
            </select>
          </label>
          <label className="visibility-field">
            Visibility
            <select name="visibility" defaultValue="private">
              <option value="private">Private</option>
              <option value="public">Public</option>
            </select>
          </label>
          {scope === "prefix" ? (
            <label
              className="prefix-field"
              title="Crawl only page URLs that start with this URL. Empty uses the seed URL as the prefix."
            >
              Prefix URL
              <input name="prefix" type="url" placeholder="defaults to seed URL prefix" />
            </label>
          ) : null}
          <label className="path-filter-field">
            Path exclude regex
            <input
              name="pathExcludeRx"
              type="text"
              placeholder="exclude paths, e.g. ^/p/[^/]+/comment(?:/|$)"
              spellCheck={false}
              title="Reject candidate page URLs whose path matches this regex after scope matching."
            />
          </label>
          <label className="check-field">
            <input name="enrich" type="checkbox" defaultChecked />
            Enrich
          </label>
        </div>
      </form>
      {message && <div className="dock-error">{message}</div>}
    </header>
  );
}

function Page({ route }: { route: Route }) {
  if (route.name === "jobs") return <JobsPage />;
  if (route.name === "job") return <JobPage id={route.id} />;
  if (route.name === "sites") return <SitesPage />;
  if (route.name === "site") return <SitePage id={route.id} />;
  if (route.name === "items") return <ItemsPage />;
  if (route.name === "item") return <ItemPage id={route.id} />;
  if (route.name === "users") return <UsersPage />;
  if (route.name === "settings") return <SettingsPage />;
  if (route.name === "viewer") return <ReplayPage id={route.id} />;
  return <DashboardPage />;
}

function DashboardPage() {
  const load = useLoader(async () => {
    const [jobs, sites, items] = await Promise.all([api.jobs(12), api.sites(), api.items({ limit: 8 })]);
    return { jobs: jobs.jobs, sites: sites.sites, items: items.items };
  }, []);

  return (
    <Resource load={load}>
      {({ jobs, sites, items }) => {
        const running = jobs.filter((job) => job.status === "running" || job.status === "queued").length;
        const failed = jobs.filter((job) => job.status === "failed").length;
        const captures = jobs.filter((job) => job.status === "succeeded").length;
        return (
          <>
            <PageHeader
              eyebrow="Archive"
              title="Overview"
              aside={<a className="text-link" href={href("items")}>Open index</a>}
            />
            <section className="metric-grid">
              <Metric icon={<Database size={18} />} label="Captured" value={String(captures)} tone="green" />
              <Metric icon={<Clock3 size={18} />} label="Queued / running" value={String(running)} tone="amber" />
              <Metric icon={<Globe2 size={18} />} label="Sites" value={String(sites.length)} tone="blue" />
              <Metric icon={<XCircle size={18} />} label="Failed" value={String(failed)} tone="red" />
            </section>
            <section className="overview-panels">
              <Panel title="Recent jobs" action={<a href={href("jobs")}>All jobs</a>}>
                <JobList jobs={jobs} compact />
              </Panel>
              <Panel title="Fresh index" action={<a href={href("items")}>All items</a>}>
                <ItemStack items={items} />
              </Panel>
            </section>
          </>
        );
      }}
    </Resource>
  );
}

function JobsPage() {
  const load = useLoader(() => api.jobs(200).then((data) => data.jobs), []);
  return (
    <Resource load={load}>
      {(jobs) => (
        <>
          <PageHeader eyebrow="Queue" title="Archive jobs" />
          <PaginatedJobPanel jobs={jobs} />
        </>
      )}
    </Resource>
  );
}

function JobPage({ id }: { id: string }) {
  const [refresh, setRefresh] = useState(0);
  const load = useLoader(() => api.job(id), [id, refresh], 4000);
  async function cancelJob() {
    await api.cancelJob(id);
  }
  async function deleteJob() {
    await api.deleteJob(id);
    window.location.hash = "/jobs";
  }
  return (
    <Resource load={load}>
      {(job) => (
        <>
          <PageHeader
            eyebrow="Job"
            title="Capture job"
            subtitle={job.url}
            aside={
              <div className="action-row">
                <StatusPill status={job.status} />
                {job.captureId && (
                  <VisibilityToggle
                    captureId={job.captureId}
                    visibility={job.visibility}
                    onChanged={() => setRefresh((value) => value + 1)}
                  />
                )}
                {job.captureId && job.items?.some((item) => item.replayable) && (
                  <a
                    className="view-button"
                    href={viewerHref(job.captureId, preferredReplayURL(job))}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <Maximize2 size={16} />
                    View archive
                  </a>
                )}
                {(job.status === "queued" || job.status === "running") && (
                  <button className="icon-button" type="button" onClick={cancelJob}>
                    <XCircle size={16} />
                    Cancel
                  </button>
                )}
                {job.status !== "queued" && job.status !== "running" && (
                  <ConfirmButton
                    className="danger-button"
                    title="Delete job"
                    detail="This removes the job record and any indexed capture data connected to it."
                    confirmLabel="Delete"
                    onConfirm={deleteJob}
                  >
                    <Trash2 size={16} />
                    Delete
                  </ConfirmButton>
                )}
              </div>
            }
          />
          <section className="metric-grid">
            <Metric icon={<Clock3 size={18} />} label="Depth" value={depthLabel(job.depth)} tone="blue" />
            <Metric icon={<FileText size={18} />} label="Items" value={String(job.items?.length || 0)} tone="green" />
            <Metric icon={<ListFilter size={18} />} label="Scope" value={scopeLabel(job.scope)} tone="neutral" />
            <Metric icon={<Sparkles size={18} />} label="Max pages" value={maxPagesLabel(job.maxPages)} tone="amber" />
          </section>
          {job.error && <div className="callout danger">{job.error}</div>}
          {job.status === "succeeded" && (job.items?.length || 0) > 0 && !job.items?.some((item) => item.replayable) && (
            <div className="callout">This WACZ contains indexed page text, but Browsertrix did not write replayable top-level document responses for these routes.</div>
          )}
          <section className="split-grid">
            <Panel title="Captured pages">
              <ItemTable items={job.items || []} />
            </Panel>
            <Panel title="Run log">
              <LogStack job={job} />
            </Panel>
          </section>
        </>
      )}
    </Resource>
  );
}

function VisibilityToggle({
  captureId,
  visibility,
  onChanged
}: {
  captureId: string;
  visibility: Visibility;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function change(next: Visibility) {
    setBusy(true);
    setError("");
    try {
      await api.updateWarcVisibility(captureId, next);
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="visibility-toggle">
      <select
        aria-label="Archive visibility"
        value={visibility}
        disabled={busy}
        onChange={(event) => change(event.target.value as Visibility)}
      >
        <option value="private">Private</option>
        <option value="public">Public</option>
      </select>
      {error && <span>{error}</span>}
    </div>
  );
}

function preferredReplayURL(job: ArchiveJobDetail) {
  const items = job.items || [];
  const seedURL = normalizeClientURL(job.url);
  return (
    items.find((item) => item.replayable && normalizeClientURL(item.url) === seedURL)?.url ||
    items.find((item) => item.replayable && normalizeClientURL(stripTrailingSlash(item.url)) === normalizeClientURL(stripTrailingSlash(job.url)))?.url ||
    items.find((item) => item.replayable && item.depth === 0)?.url ||
    items.find((item) => item.replayable)?.url ||
    job.url
  );
}

function normalizeClientURL(raw: string) {
  try {
    const url = new URL(raw);
    url.hash = "";
    if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
      url.port = "";
    }
    url.hostname = url.hostname.toLowerCase();
    return url.toString();
  } catch {
    return raw;
  }
}

function stripTrailingSlash(raw: string) {
  try {
    const url = new URL(raw);
    if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, "");
    return url.toString();
  } catch {
    return raw.replace(/\/+$/, "");
  }
}

function SitesPage() {
  const load = useLoader(() => api.sites().then((data) => data.sites), []);
  return (
    <Resource load={load}>
      {(sites) => (
        <>
          <PageHeader eyebrow="Catalog" title="Sites" />
          <PaginatedSiteGrid sites={sites} />
        </>
      )}
    </Resource>
  );
}

function SitePage({ id }: { id: string }) {
  const load = useLoader(() => api.site(id), [id]);
  async function deleteSite() {
    await api.deleteSite(id);
    window.location.hash = "/sites";
  }
  return (
    <Resource load={load}>
      {({ site, items }) => (
        <>
          <PageHeader
            eyebrow={site.host}
            title={site.title || site.host}
            aside={
              <div className="action-row">
                <span>{site.itemCount} items</span>
                <ConfirmButton
                  className="danger-button"
                  title="Delete site"
                  detail="This removes the site, its captures, and indexed pages from the catalog."
                  confirmLabel="Delete"
                  onConfirm={deleteSite}
                >
                  <Trash2 size={16} />
                  Delete
                </ConfirmButton>
              </div>
            }
          />
          <PaginatedItemPanel title="Pages" items={items} />
        </>
      )}
    </Resource>
  );
}

function ItemsPage() {
  const [query, setQuery] = useState("");
  const load = useLoader(() => api.items({ q: query, limit: 200 }).then((data) => data.items), [query]);
  return (
    <>
      <PageHeader
        eyebrow="Index"
        title="Items"
        aside={
          <label className="search-box">
            <Search size={16} />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search title, URL, summary" />
          </label>
        }
      />
      <Resource load={load}>
        {(items) => <PaginatedItemPanel title="Indexed captures" items={items} />}
      </Resource>
    </>
  );
}

function ItemPage({ id }: { id: string }) {
  const load = useLoader(() => api.item(id), [id]);
  const [showMarkdown, setShowMarkdown] = useState(false);
  async function deleteItem() {
    await api.deleteItem(id);
    window.location.hash = "/items";
  }
  return (
    <Resource load={load}>
      {(item) => (
        <>
          <PageHeader
            eyebrow={new URL(item.url).hostname}
            title={item.title || item.url}
            aside={
              <div className="action-row">
                {item.warcDownloadUrl && (
                  <a className="icon-button" href={item.warcDownloadUrl}>
                    <Download size={16} />
                    WARC
                  </a>
                )}
                {item.replayUrl && (
                  <a className="view-button" href={item.replayUrl} target="_blank" rel="noreferrer">
                    <Maximize2 size={16} />
                    View
                  </a>
                )}
                <RecaptureButton itemID={item.id} />
                <ConfirmButton
                  className="danger-button"
                  title="Delete item"
                  detail="This removes the indexed page from the catalog."
                  confirmLabel="Delete"
                  onConfirm={deleteItem}
                >
                  <Trash2 size={16} />
                  Delete
                </ConfirmButton>
              </div>
            }
          />
          <section className="split-grid item-detail-grid">
            <Panel title="Summary">
              <p className="summary-copy">{item.summary || localSummary(item.markdown || "")}</p>
              <TagRow tags={item.tags || []} />
            </Panel>
            <Panel title="Metadata">
              <dl className="metadata-list">
                <div><dt>Status</dt><dd>{item.statusCode || "n/a"}</dd></div>
                <div><dt>Replay</dt><dd>{item.replayable ? "available" : "indexed text only"}</dd></div>
                <div><dt>Depth</dt><dd>{item.depth}</dd></div>
                <div><dt>Type</dt><dd>{item.contentType || "unknown"}</dd></div>
                <div><dt>Captured</dt><dd>{formatDate(item.createdAt)}</dd></div>
              </dl>
            </Panel>
          </section>
          <Panel
            title="Markdown"
            action={
              <button className="tiny-button" type="button" onClick={() => setShowMarkdown((value) => !value)}>
                {showMarkdown ? "Hide" : "Show"}
              </button>
            }
          >
            {showMarkdown ? <pre className="markdown-pane">{item.markdown || ""}</pre> : <div className="muted-block">Markdown is hidden by default.</div>}
          </Panel>
        </>
      )}
    </Resource>
  );
}

function SettingsPage() {
  const [refresh, setRefresh] = useState(0);
  const load = useLoader(async () => {
    const [settings, profiles] = await Promise.all([api.settings(), api.cookieProfiles()]);
    return { settings, profiles: profiles.profiles };
  }, [refresh]);

  return (
    <Resource load={load}>
      {({ settings, profiles }) => (
        <>
          <PageHeader eyebrow="Service" title="Settings" />
          <section className="settings-stack">
            <SettingsForm settings={settings} onSaved={() => setRefresh((v) => v + 1)} />
            <CookieProfiles profiles={profiles} onChanged={() => setRefresh((v) => v + 1)} />
          </section>
        </>
      )}
    </Resource>
  );
}

function UsersPage() {
  const [refresh, setRefresh] = useState(0);
  const load = useLoader(() => api.users().then((data) => data.users), [refresh]);
  return (
    <Resource load={load}>
      {(users) => (
        <>
          <PageHeader eyebrow="Admin" title="Users" />
          <section className="settings-stack">
            <CreateUserPanel onChanged={() => setRefresh((v) => v + 1)} />
            <UsersPanel users={users} onChanged={() => setRefresh((v) => v + 1)} />
          </section>
        </>
      )}
    </Resource>
  );
}

function CreateUserPanel({ onChanged }: { onChanged: () => void }) {
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    try {
      await api.createUser({
        username: String(form.get("username") || ""),
        email: valueOrUndefined(form.get("email")),
        displayName: valueOrUndefined(form.get("displayName")),
        password: String(form.get("password") || ""),
        isAdmin: form.get("isAdmin") === "on"
      });
      formEl.reset();
      onChanged();
    } catch (err) {
      setMessage(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Panel title="Create user" action={<KeyRound size={16} />}>
      <form className="settings-form user-form" onSubmit={submit}>
        <div className="form-pair">
          <label>
            Username
            <input name="username" autoComplete="off" required />
          </label>
          <label>
            Password
            <input name="password" type="password" autoComplete="new-password" minLength={8} required />
          </label>
        </div>
        <div className="form-pair">
          <label>
            Email
            <input name="email" type="email" autoComplete="off" />
          </label>
          <label>
            Display name
            <input name="displayName" autoComplete="off" />
          </label>
        </div>
        <label className="check-line">
          <input name="isAdmin" type="checkbox" />
          Admin
        </label>
        {message && <div className="form-error">{message}</div>}
        <button className="primary-button" disabled={busy}>
          {busy ? <Loader2 className="spin" size={16} /> : <KeyRound size={16} />}
          Create
        </button>
      </form>
    </Panel>
  );
}

function UsersPanel({ users, onChanged }: { users: User[]; onChanged: () => void }) {
  if (!users.length) return <Panel title="Accounts"><Empty icon={<Shield size={22} />} label="No users" /></Panel>;
  return (
    <Panel title="Accounts">
      <div className="user-list">
        {users.map((user) => (
          <UserRow key={user.id} user={user} onChanged={onChanged} />
        ))}
      </div>
    </Panel>
  );
}

function UserRow({ user, onChanged }: { user: User; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") || "").trim();
    try {
      await api.updateUser(user.id, {
        username: String(form.get("username") || ""),
        email: valueOrUndefined(form.get("email")),
        displayName: valueOrUndefined(form.get("displayName")),
        password: password || undefined,
        isAdmin: form.get("isAdmin") === "on"
      });
      setEditing(false);
      onChanged();
    } catch (err) {
      setMessage(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    await api.deleteUser(user.id);
    onChanged();
  }
  return (
    <div className="user-row">
      <div className="user-row-head">
        <div>
          <strong>{user.displayName || user.username}</strong>
          <span>@{user.username}{user.email ? ` · ${user.email}` : ""}</span>
        </div>
        <div className="action-row">
          {user.isAdmin && <span className="muted-pill">Admin</span>}
          <button className="tiny-button" type="button" onClick={() => setEditing((value) => !value)}>
            {editing ? "Close" : "Edit"}
          </button>
          <ConfirmButton
            className="tiny-button"
            title="Delete user"
            detail={`Delete ${user.username}? Their existing private captures remain private but lose an active owner.`}
            confirmLabel="Delete"
            onConfirm={remove}
          >
            Delete
          </ConfirmButton>
        </div>
      </div>
      {editing && (
        <form className="settings-form inline-user-form" onSubmit={submit}>
          <div className="form-pair">
            <label>
              Username
              <input name="username" defaultValue={user.username} required />
            </label>
            <label>
              New password
              <input name="password" type="password" autoComplete="new-password" minLength={8} placeholder="leave blank" />
            </label>
          </div>
          <div className="form-pair">
            <label>
              Email
              <input name="email" type="email" defaultValue={user.email || ""} />
            </label>
            <label>
              Display name
              <input name="displayName" defaultValue={user.displayName} />
            </label>
          </div>
          <label className="check-line">
            <input name="isAdmin" type="checkbox" defaultChecked={user.isAdmin} />
            Admin
          </label>
          {message && <div className="form-error">{message}</div>}
          <button className="primary-button" disabled={busy}>
            {busy ? <Loader2 className="spin" size={16} /> : <Settings size={16} />}
            Save user
          </button>
        </form>
      )}
    </div>
  );
}

function ReplayPage({ id }: { id: string }) {
  const source = `${window.location.origin}${warcDownloadHref(id)}`;
  const initialURL = new URLSearchParams(window.location.search).get("url") || "";
  const [targetURL, setTargetURL] = useState(initialURL);
  const [error, setError] = useState("");
  const [darkMode, setDarkMode] = useState(storedReplayDarkMode);
  const [chromeHidden, setChromeHidden] = useState(storedReplayChromeHidden);

  useEffect(() => {
    if (!("serviceWorker" in navigator)) return;
    navigator.serviceWorker
      .register("/api/warcs/sw.js", { scope: "/api/warcs/" })
      .then(() => navigator.serviceWorker.ready)
      .catch((err) => console.error("warc replay service worker registration failed", err));
  }, []);

  useEffect(() => {
    if (targetURL) return;
    let alive = true;
    api
      .warcMetadata(id)
      .then((metadata) => {
        if (alive) setTargetURL(metadata.startUrl);
      })
      .catch((err) => {
        if (alive) setError(errorMessage(err));
      });
    return () => {
      alive = false;
    };
  }, [id, targetURL]);

  useEffect(() => {
    writeReplayDarkMode(darkMode);
    writeReplayChromeHidden(chromeHidden);
    syncReplayBrowserChrome(darkMode, chromeHidden);
    const interval = window.setInterval(() => syncReplayBrowserChrome(darkMode, chromeHidden), 500);
    const stop = window.setTimeout(() => window.clearInterval(interval), 7000);
    return () => {
      window.clearInterval(interval);
      window.clearTimeout(stop);
    };
  }, [chromeHidden, darkMode, id, targetURL]);

  return (
    <main className={`warc-viewer-page ${darkMode ? "viewer-dark" : ""} ${chromeHidden ? "viewer-chrome-hidden" : ""}`}>
      <header className="warc-viewer-toolbar">
        <div className="viewer-address">
          <Globe2 size={15} />
          <span>{targetURL ? replayHostLabel(targetURL) : "Loading archive"}</span>
        </div>
        <button
          aria-pressed={darkMode}
          className="viewer-theme-toggle"
          title={darkMode ? "Use light browser chrome" : "Use dark browser chrome"}
          type="button"
          onClick={() => setDarkMode((value) => !value)}
        >
          {darkMode ? <Sun size={15} /> : <Moon size={15} />}
          <span>{darkMode ? "Light" : "Dark"}</span>
        </button>
        <button
          aria-pressed={chromeHidden}
          className="viewer-theme-toggle"
          title="Hide browser chrome"
          type="button"
          onClick={() => setChromeHidden(true)}
        >
          <EyeOff size={15} />
          <span>Hide</span>
        </button>
      </header>
      <div className="warc-viewer-stage">
        {targetURL ? (
          React.createElement("replay-web-page", {
            replayBase: "/api/warcs/",
            source,
            url: targetURL,
            embed: "default"
          })
        ) : (
          <div className="warc-viewer-loading">{error || "Loading archived page..."}</div>
        )}
      </div>
      {chromeHidden && (
        <button className="viewer-chrome-restore" type="button" title="Show browser chrome" onClick={() => setChromeHidden(false)}>
          <Eye size={16} />
          <span>Show</span>
        </button>
      )}
    </main>
  );
}

function SettingsForm({ settings, onSaved }: { settings: SettingsType; onSaved: () => void }) {
  const [message, setMessage] = useState("");
  const [editingModel, setEditingModel] = useState(false);
  const [editingApiKey, setEditingApiKey] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    const filterLists = String(form.get("filterLists") || "")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const apiKey = String(form.get("openrouterKeyOverride") || "").trim();
    const model = String(form.get("openrouterModelOverride") || "").trim();
    const payload: Partial<SettingsType> & { openRouterApiKey?: string } = {
      enrichmentEnabled: form.get("enrichmentEnabled") === "on",
      filterLists,
      userAgent: String(form.get("userAgent") || "").trim(),
      captureHeadless: form.get("captureHeadless") === "on",
      capturePageDelay: Number(form.get("capturePageDelay") || settings.capturePageDelay),
      capturePageRetries: Number(form.get("capturePageRetries") || settings.capturePageRetries),
      captureUseSitemap: form.get("captureUseSitemap") === "on"
    };
    if (editingModel && model) payload.openRouterModel = model;
    if (editingApiKey && apiKey) payload.openRouterApiKey = apiKey;
    await api.updateSettings(payload);
    setMessage("Saved");
    setEditingModel(false);
    setEditingApiKey(false);
    onSaved();
  }
  async function testOpenRouter() {
    const result = await api.testOpenRouter();
    setMessage(result.message);
  }
  return (
    <Panel title="OpenRouter and filters" action={<Shield size={16} />}>
      <form className="settings-form" onSubmit={submit}>
        <div className="secret-panel">
          <div>
            <span className="field-label">Model</span>
            <strong>{settings.openRouterModel}</strong>
            <p>Used for automatic summaries and tags.</p>
          </div>
          <button className="icon-button" type="button" onClick={() => setEditingModel((value) => !value)}>
            {editingModel ? "Close" : "Edit"}
          </button>
        </div>
        {editingModel && (
          <label>
            New model
            <input
              name="openrouterModelOverride"
              type="text"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              placeholder={settings.openRouterModel}
            />
          </label>
        )}
        <div className="secret-panel">
          <div>
            <span className="field-label">API key</span>
            <strong>{settings.openRouterApiKeyConfigured ? "Configured" : "Not configured"}</strong>
            <p>{settings.openRouterApiKeyConfigured ? "Stored in settings or provided by the service environment." : "Set OPENROUTER_API_KEY or add one here."}</p>
          </div>
          <button className="icon-button" type="button" onClick={() => setEditingApiKey((value) => !value)}>
            {editingApiKey ? "Close" : "Edit"}
          </button>
        </div>
        {editingApiKey && (
          <label>
            New API key
            <input
              name="openrouterKeyOverride"
              type="text"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              placeholder="sk-or-..."
            />
          </label>
        )}
        <label className="check-line">
          <input name="enrichmentEnabled" type="checkbox" defaultChecked={settings.enrichmentEnabled} />
          Automatic enrichment
        </label>
        <label>
          Filter lists
          <textarea name="filterLists" rows={5} defaultValue={settings.filterLists.join("\n")} />
        </label>
        <label>
          Capture user agent
          <textarea
            name="userAgent"
            rows={3}
            defaultValue={settings.userAgent || ""}
            placeholder="Optional browser user agent override"
          />
        </label>
        <div className="trick-grid">
          <label className="check-line">
            <input name="captureHeadless" type="checkbox" defaultChecked={settings.captureHeadless} />
            Headless browser
          </label>
          <label className="check-line">
            <input name="captureUseSitemap" type="checkbox" defaultChecked={settings.captureUseSitemap} />
            Sitemap discovery
          </label>
          <label>
            Page delay
            <input name="capturePageDelay" type="number" min="1" max="120" defaultValue={settings.capturePageDelay} />
          </label>
          <label>
            Page retries
            <input name="capturePageRetries" type="number" min="0" max="5" defaultValue={settings.capturePageRetries} />
          </label>
        </div>
        {message && <div className="callout">{message}</div>}
        <div className="action-row">
          <button className="primary-button">
            <Settings size={16} />
            Save
          </button>
          <button className="icon-button" type="button" onClick={testOpenRouter}>
            <RefreshCw size={16} />
            Test
          </button>
        </div>
      </form>
    </Panel>
  );
}

function CookieProfiles({ profiles, onChanged }: { profiles: CookieProfile[]; onChanged: () => void }) {
  const [sourceType, setSourceType] = useState<CookieProfile["sourceType"]>("json");
  const contentLabel = sourceType === "netscape" ? "Netscape cookies.txt" : "Cookie-Editor JSON";
  const contentPlaceholder =
    sourceType === "netscape"
      ? "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tTRUE\t1893456000\tsession\t..."
      : `[
  {
    "domain": ".example.com",
    "name": "session",
    "value": "..."
  }
]`;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    await api.createCookieProfile({
      name: String(form.get("name")),
      sourceType,
      host: valueOrUndefined(form.get("host")),
      cookieHeader: sourceType === "raw_header" ? valueOrUndefined(form.get("cookieHeader")) : undefined,
      content: sourceType === "raw_header" ? undefined : valueOrUndefined(form.get("content"))
    });
    formEl.reset();
    setSourceType("json");
    onChanged();
    notifyCookieProfilesChanged();
  }
  async function remove(id: string) {
    await api.deleteCookieProfile(id);
    onChanged();
    notifyCookieProfilesChanged();
  }
  return (
    <Panel title="Cookie profiles" action={<Cookie size={16} />}>
      <div className="secret-panel cookie-helper">
        <div>
          <span className="field-label">Recommended import</span>
          <strong>Use <a href="https://cookie-editor.com/" target="_blank">Cookie-Editor</a></strong>
          <p>Install Cookie-Editor, open the authenticated tab, export all cookies as JSON, and paste the export below. WARCdriver imports the full selected export into a temporary Browsertrix profile before capture.</p>
        </div>
      </div>
      <form className="settings-form" onSubmit={submit}>
        <div className="form-pair">
          <label>
            Name
            <input name="name" required />
          </label>
          <label>
            Source
            <select
              name="sourceType"
              value={sourceType}
              onChange={(event) => setSourceType(event.target.value as CookieProfile["sourceType"])}
            >
              <option value="json">JSON</option>
              <option value="netscape">Netscape</option>
              <option value="raw_header">Raw header</option>
            </select>
          </label>
        </div>
        <label>
          Host label
          <input name="host" placeholder="optional example.com label" />
        </label>
        {sourceType === "raw_header" ? (
          <label>
            Cookie header
            <input name="cookieHeader" placeholder="session=...; other=value" required />
          </label>
        ) : (
          <label>
            {contentLabel}
            <textarea name="content" rows={8} placeholder={contentPlaceholder} required />
          </label>
        )}
        <button className="primary-button">
          <Cookie size={16} />
          Add profile
        </button>
      </form>
      <div className="profile-list">
        {profiles.map((profile) => (
          <div className="profile-row" key={profile.id}>
            <div>
              <strong>{profile.name}</strong>
              <span>{profile.sourceType} {profile.host ? `· ${profile.host}` : ""}</span>
            </div>
            <button className="tiny-button" onClick={() => remove(profile.id)}>Delete</button>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function useLoader<T>(loader: () => Promise<T>, deps: unknown[], pollMs?: number): LoadState<T> {
  const [load, setLoad] = useState<LoadState<T>>({ state: "loading" });
  const stableLoader = useCallback(loader, deps);

  useEffect(() => {
    let alive = true;
    const run = () => {
      stableLoader()
        .then((data) => alive && setLoad({ state: "ready", data }))
        .catch((err) => alive && setLoad({ state: "error", error: errorMessage(err) }));
    };
    setLoad({ state: "loading" });
    run();
    if (!pollMs) return () => { alive = false; };
    const timer = window.setInterval(run, pollMs);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [stableLoader, pollMs]);

  return load;
}

function Resource<T>({
  load,
  children
}: {
  load: LoadState<T>;
  children: (data: T) => ReactNode;
}) {
  if (load.state === "loading") {
    return <div className="loading-panel"><Loader2 className="spin" size={20} /> Loading</div>;
  }
  if (load.state === "error") {
    return <div className="callout danger">{load.error}</div>;
  }
  return <>{children(load.data)}</>;
}

function PageHeader({ eyebrow, title, subtitle, aside }: { eyebrow: string; title: string; subtitle?: string; aside?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      {aside && <div className="page-header-aside">{aside}</div>}
    </header>
  );
}

function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <h2>{title}</h2>
        {action && <div>{action}</div>}
      </header>
      {children}
    </section>
  );
}

function Metric({ icon, label, value, tone }: { icon: ReactNode; label: string; value: string; tone: string }) {
  return (
    <div className={`metric-card tone-${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function ConfirmButton({
  className = "icon-button",
  title,
  detail,
  confirmLabel = "Confirm",
  children,
  onConfirm
}: ConfirmButtonProps) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function confirm() {
    setBusy(true);
    setError("");
    try {
      await onConfirm();
      setOpen(false);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button className={className} type="button" onClick={() => setOpen(true)}>
        {children}
      </button>
      {open && (
        <div className="modal-layer" role="presentation" onMouseDown={() => setOpen(false)}>
          <section
            className="confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="confirm-mark">
              <Trash2 size={18} />
            </div>
            <div className="confirm-copy">
              <h2 id="confirm-title">{title}</h2>
              <p>{detail}</p>
              {error && <div className="form-error">{error}</div>}
            </div>
            <div className="confirm-actions">
              <button className="icon-button" type="button" onClick={() => setOpen(false)} disabled={busy}>
                Cancel
              </button>
              <button className="danger-button" type="button" onClick={confirm} disabled={busy}>
                {busy ? <Loader2 className="spin" size={16} /> : <Trash2 size={16} />}
                {confirmLabel}
              </button>
            </div>
          </section>
        </div>
      )}
    </>
  );
}

function RecaptureButton({ itemID, compact = false }: { itemID: string; compact?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function recapture() {
    setBusy(true);
    setError("");
    try {
      const job = await api.recaptureItem(itemID);
      window.location.hash = `/jobs/${job.id}`;
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      className={compact ? "icon-button compact-action" : "icon-button"}
      type="button"
      onClick={recapture}
      disabled={busy}
      title={error || "Queue a replacement capture for this page"}
      aria-label="Recapture item"
    >
      <RefreshCw className={busy ? "spin" : undefined} size={compact ? 14 : 16} />
      {compact ? "Retry" : "Recapture"}
    </button>
  );
}

type PageSize = 10 | 20 | 50 | "all";

function usePaginatedRows<T>(rows: T[], initialSize: PageSize = 20) {
  const [pageSize, setPageSize] = useState<PageSize>(initialSize);
  const [page, setPage] = useState(0);
  const numericSize = pageSize === "all" ? Math.max(rows.length, 1) : pageSize;
  const pageCount = Math.max(1, Math.ceil(rows.length / numericSize));
  const safePage = Math.min(page, pageCount - 1);
  const start = pageSize === "all" ? 0 : safePage * numericSize;
  const visible = pageSize === "all" ? rows : rows.slice(start, start + numericSize);
  const setSize = (next: PageSize) => {
    setPageSize(next);
    setPage(0);
  };
  return { visible, pageSize, setPageSize: setSize, page: safePage, setPage, pageCount, total: rows.length };
}

function PaginationControls({
  total,
  pageSize,
  setPageSize,
  page,
  setPage,
  pageCount
}: {
  total: number;
  pageSize: PageSize;
  setPageSize: (size: PageSize) => void;
  page: number;
  setPage: (page: number) => void;
  pageCount: number;
}) {
  return (
    <div className="pager">
      <span>{total} total</span>
      <select
        aria-label="Rows per page"
        value={String(pageSize)}
        onChange={(event) => setPageSize(event.target.value === "all" ? "all" : Number(event.target.value) as PageSize)}
      >
        <option value="10">10</option>
        <option value="20">20</option>
        <option value="50">50</option>
        <option value="all">All</option>
      </select>
      <button className="tiny-button" type="button" disabled={page <= 0 || pageSize === "all"} onClick={() => setPage(Math.max(0, page - 1))}>
        Prev
      </button>
      <span>{pageSize === "all" ? "All" : `${page + 1}/${pageCount}`}</span>
      <button className="tiny-button" type="button" disabled={page >= pageCount - 1 || pageSize === "all"} onClick={() => setPage(Math.min(pageCount - 1, page + 1))}>
        Next
      </button>
    </div>
  );
}

function PaginatedJobPanel({ jobs }: { jobs: ArchiveJob[] }) {
  const pager = usePaginatedRows(jobs, 20);
  return (
    <Panel title="Jobs" action={<PaginationControls {...pager} />}>
      <JobList jobs={pager.visible} />
    </Panel>
  );
}

function PaginatedItemPanel({ title, items }: { title: string; items: Item[] }) {
  const pager = usePaginatedRows(items, 20);
  return (
    <Panel title={title} action={<PaginationControls {...pager} />}>
      <ItemTable items={pager.visible} />
    </Panel>
  );
}

function PaginatedSiteGrid({ sites }: { sites: Site[] }) {
  const pager = usePaginatedRows(sites, 20);
  return (
    <>
      <div className="list-toolbar">
        <PaginationControls {...pager} />
      </div>
      <div className="site-grid">
        {pager.visible.map((site) => (
          <a className="site-card" href={href(`sites/${site.id}`)} key={site.id}>
            <div className="site-card-top">
              <Globe2 size={18} />
              <span>{site.itemCount} items</span>
            </div>
            <h2>{site.title || site.host}</h2>
            <p>{site.host}</p>
            <time>{formatDate(site.updatedAt)}</time>
          </a>
        ))}
      </div>
    </>
  );
}

function JobList({ jobs, compact = false }: { jobs: ArchiveJob[]; compact?: boolean }) {
  if (!jobs.length) return <Empty icon={<Clock3 size={22} />} label="No jobs yet" />;
  return (
    <div className={compact ? "table-wrap compact" : "table-wrap"}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>URL</th>
            <th>Depth</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <tr key={job.id}>
              <td><StatusPill status={job.status} /></td>
              <td className="url-cell">{job.url}</td>
              <td>{depthLabel(job.depth)}</td>
              <td>{formatDate(job.createdAt)}</td>
              <td><a className="row-link" href={href(`jobs/${job.id}`)}>Open</a></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ItemTable({ items }: { items: Item[] }) {
  if (!items.length) return <Empty icon={<FileText size={22} />} label="No indexed items" />;
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Title</th>
            <th>URL</th>
            <th>Depth</th>
            <th>Tags</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <strong>{item.title || "Untitled"}</strong>
                {item.summary && <span className="subline">{item.summary}</span>}
              </td>
              <td className="url-cell">{item.url}</td>
              <td>{item.depth}</td>
              <td><TagRow tags={item.tags || []} tight /></td>
              <td>
                <div className="row-actions">
                  {item.replayable ? (
                    <a className="view-button compact-view" href={viewerHref(item.captureId, item.url)} target="_blank" rel="noreferrer">
                      <Maximize2 size={14} />
                      View
                    </a>
                  ) : (
                    <span className="muted-pill">Indexed</span>
                  )}
                  <a className="row-link" href={href(`items/${item.id}`)}>Details</a>
                  <RecaptureButton itemID={item.id} compact />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ItemStack({ items }: { items: Item[] }) {
  if (!items.length) return <Empty icon={<BookOpen size={22} />} label="No items indexed" />;
  return (
    <div className="item-stack">
      {items.map((item) => (
        <div className="stack-row" key={item.id}>
          <a className="stack-main" href={href(`items/${item.id}`)}>
            <FileText size={16} />
            <div>
              <strong>{item.title || item.url}</strong>
              <span>{item.summary || item.url}</span>
            </div>
          </a>
          {item.replayable ? (
            <a className="view-button compact-view" href={viewerHref(item.captureId, item.url)} target="_blank" rel="noreferrer">
              <Maximize2 size={14} />
              View
            </a>
          ) : (
            <span className="muted-pill">Indexed</span>
          )}
        </div>
      ))}
    </div>
  );
}

function LogStack({ job }: { job: ArchiveJobDetail }) {
  if (!job.logs.length) return <Empty icon={<Clock3 size={22} />} label="No log lines" />;
  return (
    <div className="log-stack">
      {job.logs.map((line, index) => (
        <div className="log-row" key={`${line.at}-${index}`}>
          <time>{formatTime(line.at)}</time>
          <span className={`log-level level-${line.level}`}>{line.level}</span>
          <p>{line.message}</p>
        </div>
      ))}
    </div>
  );
}

function StatusPill({ status }: { status: ArchiveJob["status"] }) {
  const Icon =
    status === "succeeded" ? CheckCircle2 : status === "failed" || status === "canceled" ? XCircle : status === "running" ? Loader2 : Clock3;
  return (
    <span className={`status-pill status-${status}`}>
      <Icon className={status === "running" ? "spin" : ""} size={14} />
      {status}
    </span>
  );
}

function TagRow({ tags, tight = false }: { tags: string[]; tight?: boolean }) {
  if (!tags.length) return <span className="muted">none</span>;
  return (
    <div className={tight ? "tag-row tight" : "tag-row"}>
      {tags.map((tag) => (
        <span className="tag" key={tag}>
          <Tags size={tight ? 11 : 12} />
          {tag}
        </span>
      ))}
    </div>
  );
}

function Empty({ icon, label }: { icon: ReactNode; label: string }) {
  return (
    <div className="empty-state">
      {icon}
      <span>{label}</span>
    </div>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function errorMessage(err: unknown) {
  if (err instanceof ApiError || err instanceof Error) return err.message;
  return "Something went wrong";
}

function valueOrUndefined(value: FormDataEntryValue | null) {
  const text = String(value || "").trim();
  return text || undefined;
}

function localSummary(markdown: string) {
  const text = markdown.replace(/\s+/g, " ").trim();
  if (text.length <= 220) return text;
  return `${text.slice(0, 220)}...`;
}
