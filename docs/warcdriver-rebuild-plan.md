# WARCdriver rebuild plan

## Summary

WARCdriver should become a personal web archive service for webhook-driven captures and browsable replay. The target runtime is a Go service plus a Browsertrix worker in Docker Compose, with SQLite for metadata and local files for WARC/WACZ/content artifacts.

The immediate acceptance target is archiving a subscribed Substack publication: submit a URL, authenticate with supplied cookies or a mounted browser profile where possible, crawl the same subdomain at a configurable depth, avoid ads/trackers, write compliant WARC output, enrich the captured content with OpenRouter, and browse/replay everything from the local catalog.

The Urbit app in `desk/` is intentionally out of scope for this rebuild.

## Current repo assessment

- `app/` is now a Go service with OpenAPI-backed archive jobs, auth, SQLite state, catalog UI, replay, filter-list support, cookie profile storage, Browsertrix orchestration, and LLM enrichment.
- The old `/archive` and `/crawl` prototype endpoints and custom CDP recorder have been removed.
- Browsertrix handles crawl scope/depth, browser execution, ad blocking, and WACZ/WARC writing.
- `app/warcdrive` is a local build artifact and should be ignored, not treated as source.

## Target architecture

- One Go service serves the API, authenticated catalog UI, static frontend assets, raw WARC/WACZ downloads, replay entrypoints, and OpenRouter enrichment.
- Browsertrix Crawler is the only capture engine. WARCdriver orchestrates jobs, writes Browsertrix configs, imports Browsertrix WARC/WACZ output, and serves the catalog/replay UI.
- SQLite stores users, sessions, API tokens, settings, cookie profiles, jobs, sites, captures, captured items/pages, job logs, and LLM enrichment metadata.
- Local files under `DATA_DIR` store Browsertrix jobs/runs, WACZ/WARC files, markdown extracts, filter-list cache, and other durable artifacts.
- `openapi.yaml` is the API source of truth; generated Go code defines request/response models and route contracts.

## API and auth

- Browser UI auth uses secure HTTP-only session cookies and accounts stored in SQLite.
- Webhook/API automation uses per-user API tokens stored hashed in SQLite.
- Initial API surface:
  - `POST /api/auth/login`
  - `POST /api/auth/logout`
  - `GET /api/me`
  - `POST /api/archive-jobs`
  - `GET /api/archive-jobs`
  - `GET /api/archive-jobs/{id}`
  - `GET /api/sites`
  - `GET /api/sites/{id}`
  - `GET /api/items`
  - `GET /api/items/{id}`
  - `GET /api/warcs/{id}/download`
  - `GET /viewer/{captureId}` for the embedded WARC replay page.
  - settings, OpenRouter test, cookie-profile, and API-token endpoints.

## Capture requirements

- New captures use Browsertrix. See `docs/capture-engine-research-2026.md` for the June 2026 capture engine decision record.

- Default scope is single page. This keeps accidental captures small; users can opt into broader traversal.
- Default crawl depth is `1` when a crawl scope is selected.
- Crawl scope modes: exact same hostname/subdomain, URL prefix, explicit URLs. For Substack, same-subdomain means `publication.substack.com`, not all of `substack.com`.
- Deduplicate by canonicalized URL: strip fragments, normalize host/scheme casing, and avoid repeated pages.
- For each captured page:
  - wait for page load and a bounded network-idle period,
  - scroll to trigger lazy resources,
  - capture network request/response records,
  - capture redirects,
  - record title, canonical URL, readable markdown/text, status, content type, and resource counts,
  - store item metadata in SQLite.
- WARC output should improve toward WARC 1.1 compliance: valid record headers, request/response pairs, content lengths, timestamps, digests, redirect records, and per-record gzip.

## Cookies and authenticated capture

- Support imported cookie profiles as the reliable default:
  - Netscape `cookies.txt`
  - JSON cookie export
  - raw `Cookie` header scoped to a host
- Recommended manual export path: Cookie-Editor. It is open-source, supports major browsers, and can export cookies in JSON/Netscape/header formats. WARCdriver should document this instead of maintaining a local cookie-export extension.
- Browsertrix `profile.tar.gz` files are the reliable authenticated-capture path.
- Imported JSON/Netscape/raw cookie profiles are stored for metadata/future integrations but are not injected into Browsertrix captures yet.
- Mounted Chromium/Brave host profiles are not part of the compose stack; they were too brittle because profiles can be locked, version-sensitive, or OS-keychain encrypted.
- Compose should run the long-lived service containers as the host UID/GID through `PUID`/`PGID`.

## Filtering

- Use uBlock/EasyList-style lists to avoid capturing ads and trackers.
- Default lists: EasyList and EasyPrivacy.
- Allow additional list URLs and per-site allowlist overrides.
- Prefer a maintained Go filter engine that supports Adblock/uBlock-compatible static filter syntax.
- Apply blocking through Browsertrix ad-block support when filter lists are loaded.
- Store blocked-request counts and representative URLs per capture/job for debugging.

## OpenRouter enrichment

- After successful capture, extract markdown/readable text and call the configured OpenRouter model automatically unless disabled.
- Store tags, collection/category, one-sentence summary, model, prompt version, raw response, and enrichment status.
- LLM failure must not fail the WARC capture; enrichment is retryable from API/UI.
- Default prompt should optimize for personal archive indexing, not long summaries.

## Catalog frontend

- Serve a restrained authenticated frontend from the Go service.
- Initial views:
  - dashboard with recent jobs/captures,
  - site list grouped by host,
  - site detail with captured pages/articles and summaries,
  - item detail with metadata, markdown, replay link, WARC download, tags,
  - settings for OpenRouter, filters, cookie profiles, and API tokens.
- The catalog should make Substack captures navigable by publication/subdomain and preserve replay links for every captured URL.

## Replay

- Provide WACZ/WARC download links.
- Embed ReplayWeb.page for browser-based replay.

## Stretch goal: browser extension

- A browser extension could capture from the already-authenticated local browser instead of relying only on server-side Chrome.
- Useful modes:
  - button-click capture of the current tab, page contents, and browser-observed resources,
  - extension-driven navigation that follows server-supplied crawl orders and reports each page back,
  - local WARC/WACZ composition with upload to WARCdriver,
  - server-side WARC composition from extension-submitted DOM, response metadata, and blobs.
- This is feasible enough to keep in mind, but it should not block the core server-side capture path.

## Current capture findings

- A June 19, 2026 Substack test capture of `https://eventsinukraine.substack.com/p/infowars` replayed correctly, but the archived main document itself was `HTTP 403 Forbidden` from Cloudflare/Substack and contained the native `Something has gone terribly wrong :(` page. Treat this as an anti-bot/auth/profile issue, not a replay viewer issue.
- The sibling repo `../ft_1000_companies_scraper` is a useful reference for anti-bot symptoms: Scrapy failed with 403 even after copied headers/cookies, while browser-shaped `fetch()`/requests with navigation-like headers worked. For WARCdriver, prefer Browsertrix captures with coherent browser profile state over framework-shaped HTTP clients.
- Chrome 132 removed the old headless implementation from the main Chrome binary; current Chrome still supports the newer full-browser headless mode. `chrome-headless-shell` remains available for old-headless behavior, but it is less useful for authenticated capture because it is not the full user browser.
- Obscura and Lightpanda should be treated as experimental optional future backends, not the default capture backend. Both need WARC-specific validation before they can replace Browsertrix.

## Test plan

- Unit tests:
  - URL normalization,
  - crawl scope and depth behavior,
  - deduplication,
  - cookie parsing,
  - auth sessions and token checks,
  - filter decisions,
  - OpenRouter response parsing.
- Integration tests with local fixture sites:
  - static assets,
  - redirects,
  - lazy-loaded assets,
  - authenticated page using cookies,
  - same-subdomain crawl depths `0`, `1`, and `2`,
  - blocked ad/tracker requests.
- WARC validation tests with standard WARC readers where practical.
- API tests against the OpenAPI-generated contract.
- Frontend smoke tests for login, job creation, catalog navigation, settings, and replay launch.

## Deployment assumptions

- Compose services: `warcdriver` and `browsertrix-worker`.
- Reverse proxy/TLS is handled outside the app.
- The Go service exposes one HTTP port for both API and UI.
- `DATA_DIR` contains SQLite DB, Browsertrix jobs/runs, WACZ/WARC files, markdown extracts, filter cache, and static runtime files.
- OpenRouter key/model are configurable in DB/settings and may also be seeded by env vars.
