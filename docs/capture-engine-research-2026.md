# Capture engine research, June 2026

## Decision

The custom `chromedp` WARC recorder has been removed. It was not the right foundation for high-fidelity modern web archiving.

The capture path is Webrecorder's Browsertrix Crawler, with WARCdriver acting as the authenticated catalog, API, job orchestrator, replay host, import/export layer, and OpenRouter enrichment service.

For authenticated pages that specifically need the user's live browser state, support importing WARC/WACZ files created by ArchiveWeb.page. Do not build a custom browser extension yet.

## Why

WARCdriver's home-grown CDP implementation keeps running into the problems Browsertrix already exists to solve:

- page load settling and dynamic behavior timing,
- lazy resources,
- large batches of JS/CSS/image response bodies,
- crawl scope/depth,
- WARC/WACZ output,
- dedupe,
- ad/tracker blocking,
- login profiles,
- replay-oriented metadata,
- graceful cancellation and valid partial WARC output.

The failures seen against Substack are not just a timeout bug. The current stack is driving a remote Chrome through `chromedp`, overriding headers/client hints manually, installing cookies manually, and then trying to reconstruct a standards-compliant browser archive from raw event streams. That path is too fragile.

## Current best option: Browsertrix Crawler

Browsertrix Crawler is a current Webrecorder project for browser-based web archiving. As of this research pass, the GitHub repository lists Browsertrix Crawler v1.13.1 as the latest release on June 16, 2026.

Relevant capabilities:

- single Docker container crawler,
- Puppeteer-driven Brave Browser,
- capture through Chrome DevTools Protocol,
- WARC and WACZ output,
- YAML config and CLI config,
- per-seed depth and scope,
- `page`, `prefix`, `host`, `domain`, `custom`, and extra-hop scoping,
- page-load timeout and wait-until controls,
- post-load delay controls,
- browser behaviors such as autoscroll,
- ad blocking via `--blockAds`,
- screenshots,
- extracted text in pages metadata or WARC records,
- browser profile creation and reuse,
- dedupe within a crawl and across crawls with a Redis-compatible index,
- QA comparison between original crawl and replay,
- graceful SIGINT/SIGTERM handling that tries to finish records and keep WARC output valid.

Sources:

- https://crawler.docs.browsertrix.com/
- https://github.com/webrecorder/browsertrix-crawler
- https://crawler.docs.browsertrix.com/user-guide/common-options/
- https://crawler.docs.browsertrix.com/user-guide/crawl-scope/
- https://crawler.docs.browsertrix.com/user-guide/browser-profiles/
- https://crawler.docs.browsertrix.com/user-guide/dedupe/

## Replay direction

Prefer WACZ as WARCdriver's internal replay artifact when possible, while still exposing raw WARC downloads.

ReplayWeb.page's docs recommend WACZ for performance because WACZ bundles WARCs with indexes and metadata, so replay can load on demand instead of scanning an entire WARC on first open.

WARCdriver should keep the embedded replay UI it already has, but should ingest Browsertrix WACZ/WARC output instead of relying on its own custom WARC writer for the main capture path.

Sources:

- https://replayweb.page/docs/user-guide/
- https://archiveweb.page/en/download/

## Chrome headless status

Modern Chrome still supports headless mode. The obsolete `--headless=old` implementation was removed from the Chrome binary in Chrome 132. Current Chrome runs the new full-browser headless mode with `--headless` or `--headless=new`.

So the issue is not that "new Chrome removed headless." The issue is that high-fidelity capture needs a mature crawler and recorder around the browser, not ad hoc CDP plumbing.

Source:

- https://developer.chrome.com/blog/removing-headless-old-from-chrome

## Anti-bot and stealth survey

There are modern anti-detection automation projects, but none are a drop-in WARC-quality archive engine:

- Rebrowser patches patch Puppeteer/Playwright behavior around CDP detection, especially `Runtime.enable`.
- Patchright is a patched Playwright family intended to reduce automation fingerprints.
- Nodriver is the successor line to undetected-chromedriver and avoids Selenium/WebDriver, but it is scraping-oriented, not archiving-oriented.
- Camoufox is an anti-detect browser project, but its 2026 public docs warn that newer releases are experimental.
- Obscura advertises a Rust/V8 CDP-compatible headless browser with stealth, cookies, Fetch interception, and Playwright/Puppeteer compatibility. It is interesting as an experiment, but it is not a proven WARC capture engine.
- Lightpanda is a Zig headless browser for automation with CDP compatibility, but it has no graphical rendering engine and is beta/coverage-oriented. It is not a replay-fidelity archive choice today.

These are worth keeping as optional research tracks for hostile targets, but the primary path should not be rebuilt around them before Browsertrix is integrated.

Sources:

- https://rebrowser.net/docs/patches-for-puppeteer-and-playwright
- https://github.com/rebrowser/rebrowser-patches
- https://github.com/Kaliiiiiiiiii-Vinyzu/patchright
- https://github.com/ultrafunkamsterdam/nodriver
- https://camoufox.com/
- https://github.com/h4ckf0r0day/obscura
- https://github.com/lightpanda-io/browser

## Recommended WARCdriver architecture change

WARCdriver should become a control plane and library frontend:

1. User submits a capture from UI/webhook.
2. WARCdriver creates a durable job row and writes a Browsertrix config for that job.
3. A capture worker runs Browsertrix Crawler with that config.
4. Browsertrix writes WACZ/WARC, pages metadata, logs, screenshots, and optional extracted text under `DATA_DIR`.
5. WARCdriver imports the output into SQLite:
   - sites,
   - pages/items,
   - canonical URLs,
   - status/content type,
   - title,
   - text/markdown,
   - replay entrypoints,
   - WARC/WACZ file paths,
   - resource counts,
   - blocked counts where available.
6. WARCdriver serves catalog, replay, WARC/WACZ download, CRUD, and OpenRouter enrichment.

## Compose direction

Do not give WARCdriver access to the host Docker socket by default.

Use a dedicated capture worker image/service instead:

- either a small WARCdriver worker image that includes Browsertrix Crawler and exposes an internal job API,
- or a Browsertrix-derived worker image with a tiny local wrapper that accepts a config path/job id and runs one crawl at a time.

Browsertrix owns its browser process. WARCdriver no longer runs a separate Chrome/CDP service.

Run worker containers with host UID/GID and keep user browser profile imports read-only. Browsertrix's native `profile.tar.gz` flow is the preferred authenticated profile format.

## Substack/authenticated content path

For Substack, use this order:

1. Browsertrix login profile created interactively with its embedded browser, then reused for server captures.
2. Cookie-Editor JSON/Netscape import installed into the Browsertrix/browser profile if direct profile creation is inconvenient.
3. ArchiveWeb.page WACZ import for pages that only succeed from the user's live local browser.

The copied Brave profile path is best-effort only. Host browser profiles may be locked, version-sensitive, or OS-keychain encrypted. It is not reliable enough to be the main auth story.

## Immediate implementation plan

1. Keep Browsertrix as the only capture engine; do not reintroduce a CDP engine switch.
2. Add a worker contract:
   - job id,
   - seed URL,
   - scope,
   - depth,
   - max pages,
   - profile path,
   - cookie profile path,
   - ad-block on/off,
   - output directory.
3. Add a Browsertrix config writer.
4. Add a Browsertrix worker image/service.
5. Add output importer for Browsertrix WACZ/WARC metadata.
6. Wire job cancel to graceful SIGINT/SIGTERM first, then hard kill only after a timeout.
7. Use Browsertrix/local fixture crawls for integration tests instead of a custom CDP fallback.

## What not to do next

- Do not reintroduce the custom `chromedp` WARC recorder.
- Do not build a bespoke browser extension before the Browsertrix/ArchiveWeb.page import path is working.
- Do not rely on mounting a live Brave/Chrome profile as the main cookie solution.
- Do not switch to Obscura, Lightpanda, Patchright, Camoufox, or Nodriver until WARC-specific capture/replay fidelity is validated.
