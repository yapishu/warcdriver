## WARCdriver

Save snapshots of web pages as [WARC](https://en.wikipedia.org/wiki/WARC_(file_format)) archives using a headless Chrome browser. Captures the full page with all subresources (CSS, JS, images, fonts) so archived pages render faithfully when replayed.

WARC files are viewable with tools like [ReplayWeb.page](https://replayweb.page/), [pywb](https://pywb.readthedocs.io/), or the [Wayback Machine](https://web.archive.org/).

### Usage

```bash
docker compose up -d
```

Archive specific URLs into a single WARC:

```bash
curl -X POST \
  -d '{"urls": ["https://example.com/article"]}' \
  http://localhost:8808/archive
```

Crawl a site (same-domain links only, up to a page limit):

```bash
curl -X POST \
  -d '{"url": "https://example.com/", "maxPages": 50}' \
  http://localhost:8808/crawl
```

Optionally restrict crawling to a URL prefix:

```bash
curl -X POST \
  -d '{"url": "https://example.com/blog/", "maxPages": 20, "prefix": "https://example.com/blog/"}' \
  http://localhost:8808/crawl
```

WARC files are saved to `./data/` (mounted from the container).

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `/data` | Directory for WARC output |
| `CHROME_HOST` | `chrome` | Hostname of the Chrome DevTools instance |
| `CHROME_PORT` | `9222` | Chrome DevTools Protocol port |
