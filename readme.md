# WARCdriver

WARCdriver is a self-hosted personal web archive. It accepts authenticated capture jobs, runs Browsertrix Crawler, stores WACZ/WARC files and markdown extracts, indexes captured pages in SQLite, and serves a catalog UI with embedded replay.

## Run

```bash
export PUID="$(id -u)"
export PGID="$(id -g)"
export WARC_ADMIN_USERNAME="reid"
export WARC_ADMIN_PASSWORD="choose-a-real-password"
docker compose up -d --build
```

Open `http://localhost:8808/` and log in with the bootstrap admin account.

## Captures

The capture form creates Browsertrix jobs. Useful fields:

- `URL`: seed URL.
- `Scope`: `single_page`, `linked_pages`, `same_subdomain`, `prefix`, or `explicit_urls`. Prefix scope crawls only page URLs that start with the seed URL or optional prefix URL.
- `Depth`: link traversal depth. Broad scopes use `All`.
- `Max pages`: set to `0` or check `Unlimited` for no page-count cap.
- `Path exclude regex`: a regular expression matched against candidate URL paths after scope matching, before pages are queued. For Substack, use `^/p/[^/]+/comments?(?:/|$)` to reject both `/comments` indexes and `/comment/<id>` permalinks. Another example is `^/(login|cart)(?:/|$)`.
- `Cookies`: optional saved cookie profile.
- `Visibility`: `Private` is owner/admin only; `Public` can be replayed by anyone with the viewer link.
- `Enrich`: sends markdown to OpenRouter for English summaries and tags when configured.

Public captures use unauthenticated viewer and WACZ metadata/download routes. Private captures require login and owner/admin access.

## Cookies

Use Settings -> Cookie profiles to store cookies for authenticated captures. Supported import formats:

- Cookie-Editor JSON export.
- Netscape `cookies.txt`.
- Raw `Cookie` header.

Recommended flow:

1. Install Cookie-Editor in your browser.
2. Open the authenticated site.
3. Export cookies as JSON.
4. Add a WARCdriver cookie profile with source `JSON` and an optional host label.
5. Select that profile when capturing.

Cookie profiles are stored in SQLite under `DATA_DIR`. WACZ/WARC output is not scrubbed after capture, so authenticated captures may contain sensitive request or response data.

## API

The API is defined in `openapi.yaml`; generated Go bindings live in `app/internal/api/openapi.gen.go`.

Example job:

```bash
curl -X POST http://localhost:8808/api/archive-jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $WARC_API_TOKEN" \
  -d '{
    "url": "https://example.com/",
    "scope": "single_page",
    "maxPages": 100,
    "visibility": "private"
  }'
```

Admin users can manage accounts at `/api/users` and from the Users screen. There is no public registration.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `PUID` | `1000` | Host UID used by compose services. |
| `PGID` | `1000` | Host GID used by compose services. |
| `DATA_DIR` | `/data` | Data directory for SQLite, WACZ/WARC files, markdown, filters, and Browsertrix queues. |
| `ADDR` | `:8808` | HTTP listen address for the Go service. |
| `ARCHIVE_WORKERS` | `1` | Number of archive job workers in the Go service. |
| `WARC_ADMIN_USERNAME` | `admin` | Username for the first bootstrapped admin. |
| `WARC_ADMIN_EMAIL` | empty | Optional email for the first admin. |
| `WARC_ADMIN_NAME` | username | Display name for the first admin. |
| `WARC_ADMIN_PASSWORD` | generated | Password for the first admin. Generated and logged if unset. |
| `WARC_API_TOKEN` | empty | Optional bootstrap bearer token, stored hashed. |
| `OPENROUTER_API_KEY` | empty | API key for summary/tag enrichment. |
| `OPENROUTER_MODEL` | `openrouter/auto` | Model used for enrichment. |
| `COOKIE_SECURE` | `auto` | Session cookie Secure flag: `auto`, `true`, or `false`. |
| `CAPTURE_USER_AGENT` | empty | Optional Browsertrix user-agent override. |
| `CAPTURE_HEADLESS` | `false` | Browsertrix browser mode default. `false` uses headed mode under Xvfb. |
| `CAPTURE_PAGE_DELAY` | `3` | Seconds Browsertrix waits between pages. |
| `CAPTURE_PAGE_RETRIES` | `3` | Retry count for failed pages, including HTTP 429 responses. Seed-page 429 retries use exponential backoff starting at 30 seconds. |
| `CAPTURE_USE_SITEMAP` | `true` | Enables sitemap discovery for broad uncapped crawls. |
| `BROWSERTRIX_QUEUE_DIR` | `/data/browsertrix/jobs` | Sidecar job queue directory. |
| `BROWSERTRIX_RUNS_DIR` | `/data/browsertrix/runs` | Browsertrix output directory. |
| `BROWSERTRIX_POLL_INTERVAL` | `1` | Sidecar queue polling interval in seconds. |
| `BROWSERTRIX_CANCEL_GRACE_SECONDS` | `30` | Grace period before a canceled Browsertrix process is terminated. |

Compose exposes `warcdriver` on port `8808`, runs both main containers with `PUID:PGID`, and initializes `./data` ownership before startup.

## Data Layout

`DATA_DIR` contains:

- `warcdriver.sqlite3`
- `browsertrix/jobs/*`
- `browsertrix/runs/collections/*/*.wacz`
- `markdown/<capture-id>/*.md`
- `filters/*`

## Development

Frontend:

```bash
cd frontend
nvm use
npm install
npm run build
```

Backend:

```bash
cd app
go test ./...
go build ./...
```

Regenerate API bindings after editing `openapi.yaml`:

```bash
cd app
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1 \
  -config oapi-codegen.yaml ../openapi.yaml
```

For local non-Docker builds, copy `frontend/dist` to `app/frontend/dist` before `go test` or `go build`.
