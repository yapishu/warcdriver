package main

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestCaptureArchiveWithBrowsertrixImportsWorkerResult(t *testing.T) {
	app := &App{dataDir: t.TempDir()}
	jobID := "browsertrix-test-job"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		jobDir := app.browsertrixJobDir(jobID)
		for {
			if fileExists(filepath.Join(jobDir, "queued")) {
				break
			}
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
		_ = os.Rename(filepath.Join(jobDir, "queued"), filepath.Join(jobDir, "running"))
		_ = os.WriteFile(filepath.Join(jobDir, "cookie-profile.tar.gz"), []byte("secret profile"), 0o600)
		_ = os.WriteFile(filepath.Join(jobDir, "browsertrix.log"), []byte(`{"timestamp":"2026-06-19T00:00:00Z","logLevel":"info","context":"general","message":"Crawling done","details":{}}`+"\n"), 0o644)

		collectionDir := filepath.Join(app.dataDir, "browsertrix", "runs", "collections", jobID)
		pagesDir := filepath.Join(collectionDir, "pages")
		_ = os.MkdirAll(pagesDir, 0o755)
		pages := `{"format":"json-pages-1.0","id":"pages","title":"Seed Pages","hasText":"true"}` + "\n" +
			`{"id":"p1","url":"https://example.com/","title":"Example Domain","mime":"text/html","status":200,"seed":true,"depth":0,"text":"Example text"}` + "\n"
		_ = os.WriteFile(filepath.Join(pagesDir, "pages.jsonl"), []byte(pages), 0o644)
		extraPages := `{"format":"json-pages-1.0","id":"pages","title":"Non-Seed Pages","hasText":"true"}` + "\n" +
			`{"id":"p2","url":"https://example.com/linked","title":"Linked Page","mime":"text/html","status":200,"depth":1,"text":"Linked text"}` + "\n" +
			`{"id":"p3","url":"https://example.com/rate-limited","title":"","mime":"text/plain","status":429,"depth":1,"text":""}` + "\n"
		_ = os.WriteFile(filepath.Join(pagesDir, "extraPages.jsonl"), []byte(extraPages), 0o644)
		_ = os.WriteFile(filepath.Join(collectionDir, jobID+".wacz"), []byte("fake-wacz"), 0o644)
		_ = os.Remove(filepath.Join(jobDir, "running"))
		_ = os.WriteFile(filepath.Join(jobDir, "done.json"), []byte(`{"status":"succeeded","exitCode":0}`), 0o644)
	}()

	var logs []string
	result, err := app.captureArchiveWithBrowsertrix(ctx, BrowsertrixCaptureOptions{
		JobID:    jobID,
		StartURL: "https://example.com/",
		Scope:    "single_page",
		Depth:    0,
		MaxPages: 1,
		Cookies: []browserCookieData{
			{Name: "session", Value: "secret", URL: "https://example.com/"},
		},
		OnLog: func(level, message string) {
			logs = append(logs, level+": "+message)
		},
	})
	if err != nil {
		t.Fatalf("captureArchiveWithBrowsertrix returned error: %v", err)
	}
	if result.WARCPath != filepath.Join(app.dataDir, "browsertrix", "runs", "collections", jobID, jobID+".wacz") {
		t.Fatalf("unexpected archive path: %s", result.WARCPath)
	}
	if len(result.Pages) != 2 {
		t.Fatalf("expected 2 indexed pages, got %d: %+v", len(result.Pages), result.Pages)
	}
	if result.Pages[0].Title != "Example Domain" || result.Pages[0].Markdown == "" {
		t.Fatalf("unexpected page import: %+v", result.Pages[0])
	}
	if result.Pages[1].Title != "Linked Page" || result.Pages[1].Depth != 1 {
		t.Fatalf("unexpected linked page import: %+v", result.Pages[1])
	}
	for _, page := range result.Pages {
		if strings.Contains(page.URL, "rate-limited") {
			t.Fatalf("failed extra page should not be indexed: %+v", page)
		}
	}
	if len(logs) == 0 {
		t.Fatal("expected Browsertrix logs to be streamed")
	}
	if fileExists(filepath.Join(app.browsertrixJobDir(jobID), "cookies.json")) {
		t.Fatal("cookies.json should be removed after capture")
	}
	if fileExists(filepath.Join(app.browsertrixJobDir(jobID), "cookie-profile.tar.gz")) {
		t.Fatal("cookie-profile.tar.gz should be removed after capture")
	}
}

func TestCaptureArchiveWithBrowsertrixPreservesUnlimitedSubdomainDepth(t *testing.T) {
	app := &App{dataDir: t.TempDir()}
	jobID := "browsertrix-unlimited-depth"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	configCh := make(chan map[string]any, 1)

	go func() {
		jobDir := app.browsertrixJobDir(jobID)
		for {
			if fileExists(filepath.Join(jobDir, "queued")) {
				break
			}
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
		b, err := os.ReadFile(filepath.Join(jobDir, "config.json"))
		if err == nil {
			var cfg map[string]any
			if json.Unmarshal(b, &cfg) == nil {
				configCh <- cfg
			}
		}
		_ = os.Rename(filepath.Join(jobDir, "queued"), filepath.Join(jobDir, "running"))

		collectionDir := app.browsertrixCollectionDir(jobID)
		pagesDir := filepath.Join(collectionDir, "pages")
		_ = os.MkdirAll(pagesDir, 0o755)
		pages := `{"format":"json-pages-1.0","id":"pages","title":"Seed Pages","hasText":"true"}` + "\n" +
			`{"id":"p1","url":"https://example.com/","title":"Example Domain","mime":"text/html","status":200,"seed":true,"depth":0,"text":"Example text"}` + "\n"
		_ = os.WriteFile(filepath.Join(pagesDir, "pages.jsonl"), []byte(pages), 0o644)
		_ = os.WriteFile(filepath.Join(collectionDir, jobID+".wacz"), []byte("fake-wacz"), 0o644)
		_ = os.Remove(filepath.Join(jobDir, "running"))
		_ = os.WriteFile(filepath.Join(jobDir, "done.json"), []byte(`{"status":"succeeded","exitCode":0}`), 0o644)
	}()

	_, err := app.captureArchiveWithBrowsertrix(ctx, BrowsertrixCaptureOptions{
		JobID:    jobID,
		StartURL: "https://example.com/",
		Scope:    "same_subdomain",
		Depth:    -1,
		MaxPages: 5,
	})
	if err != nil {
		t.Fatalf("captureArchiveWithBrowsertrix returned error: %v", err)
	}
	select {
	case cfg := <-configCh:
		if cfg["depth"] != float64(-1) || cfg["scopeType"] != "host" {
			t.Fatalf("depth/scopeType = %v/%v, want -1/host", cfg["depth"], cfg["scopeType"])
		}
	default:
		t.Fatal("worker did not observe Browsertrix config")
	}
}

func TestParseBrowsertrixLogLineBlockedRequest(t *testing.T) {
	line := `{"timestamp":"2026-06-19T00:00:00Z","logLevel":"warn","context":"recorder","message":"Request failed","details":{"url":"https://browser-intake-datadoghq.com/api/v2/rum?application_id=abc&session=def","page":"https://eventsinukraine.substack.com/p/infowars","type":"Fetch","errorText":"net::ERR_BLOCKED_BY_CLIENT.Inspector"}}`
	level, msg := parseBrowsertrixLogLine(line)
	if level != "debug" {
		t.Fatalf("level = %q, want debug", level)
	}
	if !strings.Contains(msg, "blocked request [Fetch] https://browser-intake-datadoghq.com") {
		t.Fatalf("unexpected message: %q", msg)
	}
	if strings.Contains(msg, "eventsinukraine.substack.com/p/infowars") {
		t.Fatalf("blocked subresource log should not read like the page failed: %q", msg)
	}
}

func TestParseBrowsertrixLogLineFailedRequest(t *testing.T) {
	line := `{"timestamp":"2026-06-19T00:00:00Z","logLevel":"warn","context":"recorder","message":"Request failed","details":{"url":"https://cdn.example.com/image.png","page":"https://example.com/post","type":"Image","errorText":"net::ERR_CONNECTION_RESET"}}`
	level, msg := parseBrowsertrixLogLine(line)
	if level != "warn" {
		t.Fatalf("level = %q, want warn", level)
	}
	if !strings.Contains(msg, "request failed [Image] https://cdn.example.com/image.png: net::ERR_CONNECTION_RESET on https://example.com/post") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestBrowsertrixConfigLinkedPagesUsesAnyScope(t *testing.T) {
	cfg, err := browsertrixConfig(BrowsertrixCaptureOptions{
		JobID:    "linked-pages",
		StartURL: "https://example.com/",
		Scope:    "linked_pages",
		Depth:    2,
		MaxPages: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg["scopeType"] != "any" || cfg["depth"] != 2 {
		t.Fatalf("scopeType/depth = %v/%v, want any/2", cfg["scopeType"], cfg["depth"])
	}
	if cfg["headless"] != false {
		t.Fatalf("headless = %v, want false by default", cfg["headless"])
	}
	if cfg["failOnInvalidStatus"] != false || cfg["maxPageRetries"] != 0 || cfg["pageExtraDelay"] != 3 {
		t.Fatalf("retry/delay config = failOnInvalidStatus:%v maxPageRetries:%v pageExtraDelay:%v", cfg["failOnInvalidStatus"], cfg["maxPageRetries"], cfg["pageExtraDelay"])
	}
	selectLinks, ok := cfg["selectLinks"].([]string)
	if !ok || len(selectLinks) != 1 || !strings.Contains(selectLinks[0], `:not([href^="javascript:"])`) {
		t.Fatalf("selectLinks should skip fake anchor URLs: %v", cfg["selectLinks"])
	}
	exclude, ok := cfg["scopeExcludeRx"].(string)
	if !ok || !strings.Contains(exclude, "webp") || !strings.Contains(exclude, "pdf") {
		t.Fatalf("missing static asset page exclusion regex: %v", cfg["scopeExcludeRx"])
	}
	if strings.Contains(exclude, "(?i)") {
		t.Fatalf("Browsertrix uses JavaScript regexes; inline flags are invalid: %s", exclude)
	}
	if _, err := regexp.Compile(exclude); err != nil {
		t.Fatalf("scopeExcludeRx should compile: %v", err)
	}
}

func TestBrowsertrixConfigHonorsHeadlessSetting(t *testing.T) {
	cfg, err := browsertrixConfig(BrowsertrixCaptureOptions{
		JobID:    "headless",
		StartURL: "https://example.com/",
		Scope:    "single_page",
		MaxPages: 1,
		Headless: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg["headless"] != true {
		t.Fatalf("headless = %v, want true", cfg["headless"])
	}
}

func TestBrowsertrixConfigPathExcludeRegex(t *testing.T) {
	cfg, err := browsertrixConfig(BrowsertrixCaptureOptions{
		JobID:         "path-exclude",
		StartURL:      "https://eventsinukraine.substack.com/",
		Scope:         "same_subdomain",
		Depth:         -1,
		PathExcludeRx: `^/p/[^/]+/comment(?:[/?#]|$)`,
	})
	if err != nil {
		t.Fatal(err)
	}
	exclude, ok := cfg["scopeExcludeRx"].(string)
	if !ok || !strings.Contains(exclude, `^https?://[^/?#]+/p/[^/]+/comment`) {
		t.Fatalf("scopeExcludeRx does not include translated path filter: %v", cfg["scopeExcludeRx"])
	}
	rx, err := regexp.Compile(exclude)
	if err != nil {
		t.Fatalf("scopeExcludeRx should compile: %v", err)
	}
	if !rx.MatchString("https://eventsinukraine.substack.com/p/ukraine-saves-dubai/comment/228026416") {
		t.Fatalf("scopeExcludeRx should match comment route: %s", exclude)
	}
	if rx.MatchString("https://eventsinukraine.substack.com/p/ukraine-saves-dubai") {
		t.Fatalf("scopeExcludeRx should not match article route: %s", exclude)
	}
}

func TestBrowsertrixConfigSubdomainAllowsUnlimitedDepth(t *testing.T) {
	cfg, err := browsertrixConfig(BrowsertrixCaptureOptions{
		JobID:      "subdomain",
		StartURL:   "https://example.com/",
		Scope:      "same_subdomain",
		Depth:      -1,
		MaxPages:   0,
		UseSitemap: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg["scopeType"] != "host" || cfg["depth"] != -1 {
		t.Fatalf("scopeType/depth = %v/%v, want host/-1", cfg["scopeType"], cfg["depth"])
	}
	if cfg["useSitemap"] != true {
		t.Fatalf("same_subdomain should enable sitemap discovery: %v", cfg["useSitemap"])
	}
	if cfg["failOnInvalidStatus"] != false || cfg["maxPageRetries"] != 0 || cfg["pageExtraDelay"] != 3 {
		t.Fatalf("subdomain retry/delay config = failOnInvalidStatus:%v maxPageRetries:%v pageExtraDelay:%v", cfg["failOnInvalidStatus"], cfg["maxPageRetries"], cfg["pageExtraDelay"])
	}
	if _, ok := cfg["pageLimit"]; ok {
		t.Fatalf("pageLimit should be omitted for unlimited captures: %v", cfg["pageLimit"])
	}
	if _, ok := cfg["maxPageLimit"]; ok {
		t.Fatalf("maxPageLimit should be omitted for unlimited captures: %v", cfg["maxPageLimit"])
	}
}

func TestReadBrowsertrixCapturedPagesMarksReplayabilityFromCDX(t *testing.T) {
	collectionDir := t.TempDir()
	pagesDir := filepath.Join(collectionDir, "pages")
	if err := os.MkdirAll(filepath.Join(collectionDir, "indexes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pagesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pages := `{"format":"json-pages-1.0","id":"pages","title":"Seed Pages","hasText":"true"}` + "\n" +
		`{"id":"p1","url":"https://example.com/","title":"Example","mime":"text/html","status":200,"seed":true,"depth":0,"text":"Home"}` + "\n"
	extra := `{"format":"json-pages-1.0","id":"pages","title":"Non-Seed Pages","hasText":"true"}` + "\n" +
		`{"id":"p2","url":"https://example.com/archive","title":"Archive","mime":"text/html","status":200,"depth":1,"text":"Archive text"}` + "\n"
	if err := os.WriteFile(filepath.Join(pagesDir, "pages.jsonl"), []byte(pages), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pagesDir, "extraPages.jsonl"), []byte(extra), 0o644); err != nil {
		t.Fatal(err)
	}
	cdx, err := os.Create(filepath.Join(collectionDir, "indexes", "index.cdx.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(cdx)
	_, _ = gz.Write([]byte(`com,example)/ 20260619000000 {"url":"https://example.com/","mime":"text/html","status":"200","filename":"test.warc.gz"}` + "\n"))
	_, _ = gz.Write([]byte(`urn:pageinfo:https://example.com/archive 20260619000001 {"url":"urn:pageinfo:https://example.com/archive","mime":"application/json","filename":"test.warc.gz"}` + "\n"))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cdx.Close(); err != nil {
		t.Fatal(err)
	}

	captured, err := readBrowsertrixCapturedPages(collectionDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 {
		t.Fatalf("captured pages = %d, want 2", len(captured))
	}
	if !captured[0].Replayable {
		t.Fatalf("seed should be replayable: %+v", captured[0])
	}
	if captured[1].Replayable {
		t.Fatalf("pageinfo-only page should not be replayable: %+v", captured[1])
	}
}

func TestReadBrowsertrixReplayableURLsFromWACZ(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.wacz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	cdxFile, err := zw.Create("indexes/index.cdx.gz")
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(cdxFile)
	_, _ = gz.Write([]byte(`com,example)/ 20260619000000 {"url":"https://example.com/","mime":"text/html","status":"200","filename":"test.warc.gz"}` + "\n"))
	_, _ = gz.Write([]byte(`com,example)/missing 20260619000001 {"url":"https://example.com/missing","mime":"text/html","status":"404","filename":"test.warc.gz"}` + "\n"))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	replayable, err := readBrowsertrixReplayableURLsFromWACZ(path)
	if err != nil {
		t.Fatal(err)
	}
	if !replayable[normalizeURL("https://example.com/")] {
		t.Fatal("expected html 200 page to be replayable")
	}
	if replayable[normalizeURL("https://example.com/missing")] {
		t.Fatal("expected 404 page to not be replayable")
	}
}

func TestParseBrowsertrixLogLineIncludesGeneralErrorDetail(t *testing.T) {
	line := `{"timestamp":"2026-06-19T00:00:00Z","logLevel":"error","context":"general","message":"Failed to create seed","details":{"error":"SyntaxError: Invalid regular expression"}}`
	level, msg := parseBrowsertrixLogLine(line)
	if level != "error" {
		t.Fatalf("level = %q, want error", level)
	}
	if !strings.Contains(msg, "Failed to create seed: SyntaxError: Invalid regular expression") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestParseBrowsertrixLogLineDeemphasizesFakeLinks(t *testing.T) {
	line := `{"timestamp":"2026-06-19T00:00:00Z","logLevel":"warn","context":"general","message":"Invalid Page - URL must start with http:// or https://","details":{"url":"javascript:void(0)","page":"https://example.com/post"}}`
	level, msg := parseBrowsertrixLogLine(line)
	if level != "debug" {
		t.Fatalf("level = %q, want debug", level)
	}
	if !strings.Contains(msg, "skipped non-page link javascript:void(0) on https://example.com/post") {
		t.Fatalf("unexpected message: %q", msg)
	}
}
