# WARCdriver

WARCdriver is a personal web archive service. It accepts authenticated archive jobs, drives Browsertrix Crawler for high-fidelity WARC/WACZ capture, indexes captured pages in SQLite, and serves a small authenticated catalog UI with embedded replay.

The current Go service lives in `app/`. The Urbit desk in `desk/` is not part of this rebuild.

## Run

```bash
export PUID="$(id -u)"
export PGID="$(id -g)"
export WARC_ADMIN_USERNAME="reid"
export WARC_ADMIN_PASSWORD="choose-a-real-password"
docker compose up -d --build
```

Open `http://localhost:8808/` and log in with the admin account.

If `WARC_ADMIN_PASSWORD` is not set on first boot, WARCdriver creates `admin` with a generated password and prints it to the container logs. `WARC_ADMIN_EMAIL` is optional.

## API

The API is defined in `openapi.yaml`; generated Go route/types code is in `app/internal/api/openapi.gen.go`.

Create an archive job:

```bash
curl -X POST http://localhost:8808/api/archive-jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $WARC_API_TOKEN" \
  -d '{"url":"https://example.com/","scope":"single_page","depth":0,"maxPages":100}'
```

The old `/archive` and `/crawl` prototype endpoints have been removed. Use `/api/archive-jobs`.

Capture scopes:

- `single_page` captures the seed page and embedded resources only.
- `linked_pages` follows discovered links across any host up to `depth`, bounded by `maxPages`.
- `same_subdomain` crawls the seed host/subdomain with unlimited depth, bounded by `maxPages`.
- `prefix` crawls URLs under the requested prefix with unlimited depth, bounded by `maxPages`.
- `explicit_urls` captures the provided URL list as individual pages.

## Auth

- Browser auth uses SQLite users plus HTTP-only session cookies.
- Automation auth uses bearer tokens stored hashed in SQLite.
- A bootstrap API token can be seeded on first boot with `WARC_API_TOKEN`.
- `COOKIE_SECURE=auto` is the default. Local plain HTTP works, and TLS deployments get secure session cookies when the proxy forwards `X-Forwarded-Proto: https` or `Forwarded: proto=https`.

## Capture engine

Browsertrix is the only capture engine. Compose starts a `browsertrix-worker` sidecar that watches `./data/browsertrix/jobs`, runs Browsertrix without needing the Docker socket, and writes WACZ/WARC output under `./data/browsertrix/runs`.

## Cookies and profiles

Cookie profiles can be created from the UI or API using:

- raw `Cookie` header,
- Netscape `cookies.txt`,
- JSON cookie exports.

When a cookie profile is selected for a capture, WARCdriver converts matching cookies into a temporary Browsertrix Chromium profile for that job. The profile is generated under `DATA_DIR/browsertrix/jobs/<job-id>/`, is not mounted from your host browser, and is removed after the capture attempt returns.

Cookie profiles are stored credential material in SQLite and should be protected with the rest of `DATA_DIR`. WACZ/WARC artifacts are not scrubbed after capture because that can break WACZ indexes and replay integrity; do not share authenticated captures unless you are comfortable with the archive containing request/response metadata from that session.

Use [Cookie-Editor](https://cookie-editor.com/) for manual export:

1. Install Cookie-Editor in Brave/Chrome/Firefox.
2. Open the authenticated site in that browser.
3. Click Cookie-Editor and export/copy cookies as JSON.
4. In WARCdriver, open Settings, add a cookie profile, select `JSON`, set the host to the target host such as `eventsinukraine.substack.com`, and paste the export into Content.
5. Select that cookie profile when creating a capture.

Cookie-Editor is open-source and supports the major browsers. Its JSON export preserves cookie attributes.

## Browser backends

The backend is Browsertrix Crawler. Chrome 132 removed the old headless implementation from the main Chrome binary, but Browsertrix uses maintained browser automation underneath and packages the crawl output as WACZ/WARC.

Obscura and Lightpanda are worth tracking as optional future backends because both advertise modern browser automation surfaces. They should not replace Browsertrix as the default until their crawl fidelity and WARC/WACZ output are proven against real authenticated sites.

## Browser fingerprint

Set `CAPTURE_USER_AGENT` or edit Settings if you want to force a specific user agent string for Browsertrix captures.

## Filtering and enrichment

- EasyList and EasyPrivacy are downloaded, cached under `DATA_DIR/filters`, and compiled with the AdGuard URL filter engine.
- Browsertrix captures run with ad blocking enabled when filter lists are loaded.
- OpenRouter enrichment runs after capture when an API key is configured. It stores a one-sentence summary and tags for catalog indexing.

## Data

`DATA_DIR` defaults to `/data` in the container and is mounted from `./data`.

Stored artifacts:

- `warcdriver.sqlite3`
- `browsertrix/jobs/*`
- `browsertrix/runs/collections/*/*.wacz`
- `markdown/<capture-id>/*.md`
- `filters/*`

## Development

```bash
cd app
go test ./...
go build ./...
```

Frontend source is in `frontend/` and targets Node 24:

```bash
cd frontend
nvm use
npm install
npm run build
```

The production build is embedded by copying `frontend/dist` to `app/frontend/dist`. Docker does this automatically.

Regenerate OpenAPI bindings after editing `openapi.yaml`:

```bash
cd app
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1 \
  -config oapi-codegen.yaml ../openapi.yaml
```

The rebuild plan and remaining work are tracked in `docs/warcdriver-rebuild-plan.md`.
