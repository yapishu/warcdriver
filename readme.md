# %warc

A personal web archiver for Urbit. Save snapshots of web pages as standards-compliant WARC 1.1 files and upload them to S3.

## Background

The original version of this app was a Go backend (`app/`) that used Chrome DevTools Protocol via chromedp to capture full-fidelity page archives, including a BFS crawler for same-domain link discovery. The Go server produced individually gzipped WARC records and handled page rendering, subresource capture, and WARC serialization server-side.

The current version is a pure Urbit app — a Gall agent with an in-browser WARC writer. Instead of requiring a headless Chrome instance, the archiving happens entirely in the browser: the agent proxies HTTP fetches through Iris, the browser assembles the WARC file (with gzip compression via DecompressionStream/CompressionStream), and uploads the result to S3 with SigV4 signing.

## How it works

1. **Enter a URL** in the Archive tab. The frontend discovers subresources (stylesheets, scripts, images, fonts, CSS `url()` references) by parsing the HTML and crawling linked stylesheets.

2. **The agent fetches** each URL via `%iris` (Urbit's HTTP client vane) and returns the responses to the browser.

3. **The browser builds** a WARC 1.1 file containing a `warcinfo` record, a `request`/`response` pair for each resource, and rewrites the HTML to use `data:` URIs for self-contained replay. The WARC is individually gzipped per record.

4. **Upload to S3** using SigV4 request signing computed in-browser. The WARC file is stored with `public-read` ACL for easy sharing.

5. **Bookmark it.** The URL, title, tags, and S3 path are saved to the agent's state. The WARC viewer tab can decompress and render archived pages inline.

## Architecture

### Urbit agent (`desk/`)

```
app/warc.hoon       Gall agent: Eyre HTTP binding, bookmark CRUD, Iris fetch proxy
sur/warc.hoon       Types: bookmark, bookmark-id, action
site/warc.js        Frontend: WARC writer, S3 upload (SigV4), subresource discovery
site/index.html     Three tabs: Archive, Bookmarks, Settings
site/style.css      Dark theme
```

### Go backend (legacy, `app/`)

```
main.go             HTTP server with /archive and /crawl endpoints, Chrome allocator
archive.go          Full page capture via Chrome DevTools Protocol
crawl.go            BFS crawler for same-domain link discovery
warc.go             WARC 1.1 writer with individual gzip compression
```

The Go version requires a running Chrome/Chromium instance and produces higher-fidelity captures (full DOM snapshots including JS-rendered content). The Urbit version trades some capture fidelity for zero external dependencies — everything runs in your browser and your ship.

## State

The agent stores:
- `bookmarks=(map bookmark-id bookmark)` — saved archives with URL, title, tags, S3 path
- `fetches=(map @ta fetch-batch)` — in-flight Iris fetch batches

## API

Served via Eyre at `/apps/warc/`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/bookmarks` | List all bookmarks |
| POST | `/api/action` | Save, delete, add/remove tags |
| POST | `/api/fetch` | Proxy-fetch a list of URLs via Iris |
| GET | `/api/fetch/:batch-id` | Poll fetch batch results |

## S3 Configuration

Enter your S3 endpoint, bucket, access key, and secret key in the Settings tab. Credentials are stored in browser localStorage (not on the ship). WARC files are uploaded with `public-read` ACL.
