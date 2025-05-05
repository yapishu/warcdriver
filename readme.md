## WARCdriver

this is an app for creating [WARC]() archives of URLs using a headless chrome browser. you can POST a list of URLs to archive in a single WARC, or submit a site to be crawled into a single WARC (same-domain only, until it hits the page limit you set, 100 by default).

To use:

```bash
docker compose up -d

curl  -X POST \
  -d '{"urls": ["https://www.webrtc-developers.com/coturn-the-fragile-colossus/", "https://ahmet.im/blog/controller-pitfalls/"]}' \
  http://localhost:8808/archive

curl -X POST \
  -d '{"url": "https://gwern.net/", "maxPages": 200}' \
  http://localhost:8808/crawl
```