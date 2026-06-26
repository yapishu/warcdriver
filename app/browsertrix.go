package main

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	browsertrixClaimTimeout       = 90 * time.Second
	browsertrixFontBehaviorPath   = "/app/warcdriver-behaviors"
	browsertrixFontBehaviorMaxMS  = 8_000
	browsertrixFontBehaviorScroll = 30
)

type BrowsertrixCaptureOptions struct {
	JobID         string
	StartURL      string
	ExplicitURLs  []string
	Scope         string
	Depth         int
	MaxPages      int
	Prefix        string
	PathExcludeRx string
	UserAgent     string
	ProfilePath   string
	Cookies       []browserCookieData
	BlockAds      bool
	Headless      bool
	PageDelay     int
	PageRetries   int
	UseSitemap    bool
	OnLog         func(level, message string)
}

type browsertrixDone struct {
	Status     string `json:"status"`
	ExitCode   int    `json:"exitCode"`
	StartedAt  string `json:"startedAt,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
}

type browsertrixPage struct {
	Format string `json:"format"`
	URL    string `json:"url"`
	Title  string `json:"title"`
	Mime   string `json:"mime"`
	Status int    `json:"status"`
	Seed   bool   `json:"seed"`
	Depth  int    `json:"depth"`
	Text   string `json:"text"`
}

type browsertrixLogEntry struct {
	Timestamp string          `json:"timestamp"`
	LogLevel  string          `json:"logLevel"`
	Context   string          `json:"context"`
	Message   string          `json:"message"`
	Details   json.RawMessage `json:"details"`
}

type browsertrixCDXRecord struct {
	URL    string `json:"url"`
	Mime   string `json:"mime"`
	Status string `json:"status"`
	Method string `json:"method"`
}

func (a *App) captureArchiveWithBrowsertrix(ctx context.Context, opts BrowsertrixCaptureOptions) (*CaptureResult, error) {
	if opts.JobID == "" {
		return nil, fmt.Errorf("missing Browsertrix job id")
	}
	if opts.Depth < 0 && opts.Scope != "same_subdomain" && opts.Scope != "prefix" {
		opts.Depth = 0
	}
	if opts.Scope == "" {
		opts.Scope = "single_page"
	}

	jobDir := a.browsertrixJobDir(opts.JobID)
	collectionDir := a.browsertrixCollectionDir(opts.JobID)
	defer cleanupBrowsertrixJobSecrets(jobDir)
	if err := os.RemoveAll(jobDir); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(collectionDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, err
	}
	effectiveProfilePath := ""
	if len(opts.Cookies) > 0 {
		if err := atomicWriteFile(filepath.Join(jobDir, "cookies.json"), mustJSON(opts.Cookies), 0o600); err != nil {
			return nil, err
		}
		effectiveProfilePath = filepath.Join(jobDir, "cookie-profile.tar.gz")
		logLineFunc(opts.OnLog, "info", fmt.Sprintf("cookie profile prepared for Browsertrix with %d cookies", len(opts.Cookies)))
	}
	configOpts := opts
	configOpts.ProfilePath = effectiveProfilePath
	config, err := browsertrixConfig(configOpts)
	if err != nil {
		return nil, err
	}
	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(filepath.Join(jobDir, "config.json"), configBytes, 0o644); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(filepath.Join(jobDir, "request.json"), mustJSON(browsertrixRequestSummary(opts)), 0o644); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(filepath.Join(jobDir, "queued"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o644); err != nil {
		return nil, err
	}

	logLineFunc(opts.OnLog, "info", "Browsertrix job queued for sidecar worker")
	waitCtx := ctx
	cancel := func() {}
	if opts.MaxPages > 0 {
		waitCtx, cancel = context.WithTimeout(ctx, captureTimeout(opts.MaxPages)+2*time.Minute)
	}
	defer cancel()

	var logOffset int64
	claimDeadline := time.Now().Add(browsertrixClaimTimeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		logOffset = streamBrowsertrixLog(filepath.Join(jobDir, "browsertrix.log"), logOffset, opts.OnLog)

		done, doneErr := readBrowsertrixDone(filepath.Join(jobDir, "done.json"))
		if doneErr == nil {
			logOffset = streamBrowsertrixLog(filepath.Join(jobDir, "browsertrix.log"), logOffset, opts.OnLog)
			if done.ExitCode != 0 || done.Status != StatusSucceeded {
				return nil, fmt.Errorf("Browsertrix failed with exit code %d", done.ExitCode)
			}
			return a.importBrowsertrixResult(opts.JobID)
		}
		if doneErr != nil && !errors.Is(doneErr, os.ErrNotExist) {
			return nil, doneErr
		}

		if _, err := os.Stat(filepath.Join(jobDir, "running")); err == nil {
			claimDeadline = time.Time{}
		} else if !claimDeadline.IsZero() && time.Now().After(claimDeadline) {
			return nil, fmt.Errorf("Browsertrix worker did not claim job within %s; is browsertrix-worker running?", browsertrixClaimTimeout)
		}

		select {
		case <-waitCtx.Done():
			_ = atomicWriteFile(filepath.Join(jobDir, "cancel"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o644)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func browsertrixConfig(opts BrowsertrixCaptureOptions) (map[string]any, error) {
	seeds := browsertrixSeeds(opts)
	if len(seeds) == 0 {
		return nil, fmt.Errorf("no Browsertrix seeds")
	}
	scopeType, include := browsertrixScope(opts)
	depth := opts.Depth
	if opts.Scope == "single_page" || opts.Scope == "explicit_urls" {
		depth = 0
	}

	config := map[string]any{
		"seeds":               seeds,
		"collection":          opts.JobID,
		"headless":            opts.Headless,
		"generateWACZ":        true,
		"combineWARC":         true,
		"overwrite":           true,
		"text":                []string{"to-pages"},
		"workers":             1,
		"scopeType":           scopeType,
		"depth":               depth,
		"pageLoadTimeout":     90,
		"serviceWorker":       "disabled",
		"waitUntil":           []string{"load", "networkidle2"},
		"netIdleWait":         2,
		"postLoadDelay":       1,
		"pageExtraDelay":      browsertrixPageExtraDelay(opts),
		"maxPageRetries":      browsertrixMaxPageRetries(opts),
		"failOnFailedSeed":    true,
		"failOnInvalidStatus": false,
		"behaviors":           []string{"autoplay", "autofetch", "autoscroll", "siteSpecific"},
		"customBehaviors":     []string{browsertrixFontBehaviorPath},
		"blockAds":            opts.BlockAds,
		"saveState":           "partial",
		"logging":             []string{"stats"},
		"logLevel":            []string{"info", "warn", "error"},
		"selectLinks":         browsertrixLinkSelectors(),
		"clickSelector":       browsertrixClickSelector(),
		"warcPrefix":          opts.JobID,
		"title":               firstNonEmpty(hostFromURL(opts.StartURL), opts.StartURL),
	}
	if opts.MaxPages > 0 {
		config["pageLimit"] = opts.MaxPages
		config["maxPageLimit"] = opts.MaxPages
	}
	if opts.Scope == "same_subdomain" && opts.UseSitemap && (opts.MaxPages == 0 || opts.MaxPages >= 50) {
		config["useSitemap"] = true
	}
	if include != "" {
		config["scopeIncludeRx"] = include
	}
	if exclude := browsertrixScopeExcludeRx(opts); exclude != "" {
		config["scopeExcludeRx"] = exclude
	}
	if strings.TrimSpace(opts.UserAgent) != "" {
		config["userAgent"] = strings.TrimSpace(opts.UserAgent)
	}
	if strings.TrimSpace(opts.ProfilePath) != "" {
		config["profile"] = strings.TrimSpace(opts.ProfilePath)
	}
	return config, nil
}

func browsertrixRequestSummary(opts BrowsertrixCaptureOptions) map[string]any {
	return map[string]any{
		"jobId":                 opts.JobID,
		"startUrl":              opts.StartURL,
		"explicitUrls":          opts.ExplicitURLs,
		"scope":                 opts.Scope,
		"depth":                 opts.Depth,
		"maxPages":              opts.MaxPages,
		"prefix":                opts.Prefix,
		"pathExcludeRx":         opts.PathExcludeRx,
		"userAgentSet":          strings.TrimSpace(opts.UserAgent) != "",
		"cookieCount":           len(opts.Cookies),
		"blockAds":              opts.BlockAds,
		"headless":              opts.Headless,
		"pageDelay":             browsertrixPageExtraDelay(opts),
		"pageRetries":           browsertrixMaxPageRetries(opts),
		"useSitemap":            opts.UseSitemap,
		"fontLoader":            true,
		"fontLoaderMaxMS":       browsertrixFontBehaviorMaxMS,
		"fontLoaderScrollSteps": browsertrixFontBehaviorScroll,
	}
}

func browsertrixSeeds(opts BrowsertrixCaptureOptions) []map[string]any {
	seedURLs := []string{opts.StartURL}
	if opts.Scope == "explicit_urls" {
		seedURLs = append(seedURLs, opts.ExplicitURLs...)
	}
	seen := map[string]bool{}
	var seeds []map[string]any
	for _, raw := range seedURLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		normalized := normalizeURL(raw)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		seed := map[string]any{"url": raw}
		if opts.Scope == "explicit_urls" {
			seed["scopeType"] = "page"
			seed["depth"] = 0
		}
		seeds = append(seeds, seed)
	}
	return seeds
}

func browsertrixScope(opts BrowsertrixCaptureOptions) (scopeType, include string) {
	switch opts.Scope {
	case "same_subdomain":
		return "host", ""
	case "linked_pages":
		return "any", ""
	case "prefix":
		if strings.TrimSpace(opts.Prefix) != "" {
			return "custom", "^" + regexp.QuoteMeta(strings.TrimSpace(opts.Prefix))
		}
		return "prefix", ""
	case "explicit_urls", "single_page":
		return "page", ""
	default:
		return "page", ""
	}
}

func browsertrixScopeExcludeRx(opts BrowsertrixCaptureOptions) string {
	return browsertrixPathExcludeRx(opts.PathExcludeRx)
}

func browsertrixPathExcludeRx(pathRx string) string {
	pathRx = strings.TrimSpace(pathRx)
	if pathRx == "" {
		return ""
	}
	if strings.HasPrefix(pathRx, "^") {
		return `^https?://[^/?#]+` + strings.TrimPrefix(pathRx, "^")
	}
	return `^https?://[^/?#]+[^?#]*` + pathRx
}

func browsertrixLinkSelectors() []string {
	return []string{
		`a[href]:not([href^="#"]):not([href^="javascript:"]):not([href^="mailto:"]):not([href^="tel:"])->href`,
	}
}

func browsertrixClickSelector() string {
	return `a[href]:not([href^="#"]):not([href^="javascript:"])`
}

func browsertrixPageExtraDelay(opts BrowsertrixCaptureOptions) int {
	if opts.PageDelay > 0 {
		if opts.PageDelay > 120 {
			return 120
		}
		return opts.PageDelay
	}
	return 3
}

func browsertrixMaxPageRetries(opts BrowsertrixCaptureOptions) int {
	if opts.PageRetries >= 0 {
		if opts.PageRetries > 5 {
			return 5
		}
		return opts.PageRetries
	}
	return 1
}

func (a *App) importBrowsertrixResult(jobID string) (*CaptureResult, error) {
	collectionDir := a.browsertrixCollectionDir(jobID)
	pages, err := readBrowsertrixCapturedPages(collectionDir)
	if err != nil {
		return nil, err
	}
	archivePath, err := findBrowsertrixArchive(collectionDir, jobID)
	if err != nil {
		return nil, err
	}
	return &CaptureResult{WARCPath: archivePath, Pages: pages}, nil
}

func readBrowsertrixCapturedPages(collectionDir string) ([]CapturedPage, error) {
	pagesDir := filepath.Join(collectionDir, "pages")
	pages, err := readBrowsertrixPages(filepath.Join(pagesDir, "pages.jsonl"), true)
	if err != nil {
		return nil, err
	}
	extraPages, err := readBrowsertrixPages(filepath.Join(pagesDir, "extraPages.jsonl"), false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	replayable, err := readBrowsertrixReplayableURLs(collectionDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]CapturedPage, 0, len(pages)+len(extraPages))
	for _, page := range append(pages, extraPages...) {
		key := normalizeURL(page.URL)
		if seen[key] {
			continue
		}
		seen[key] = true
		if replayable == nil {
			page.Replayable = true
		} else {
			page.Replayable = browsertrixReplayableURLMatch(replayable, key)
		}
		out = append(out, page)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Browsertrix output contained no pages")
	}
	return out, nil
}

func readBrowsertrixReplayableURLs(collectionDir string) (map[string]bool, error) {
	f, err := os.Open(filepath.Join(collectionDir, "indexes", "index.cdx.gz"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readBrowsertrixReplayableURLsFromGzip(f)
}

func readBrowsertrixReplayableURLsFromWACZ(path string) (map[string]bool, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	for _, file := range zr.File {
		if file.Name != "indexes/index.cdx.gz" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return readBrowsertrixReplayableURLsFromGzip(rc)
	}
	return nil, os.ErrNotExist
}

func readBrowsertrixReplayableURLsFromGzip(r io.Reader) (map[string]bool, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	replayable := map[string]bool{}
	scanner := bufio.NewScanner(gz)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue
		}
		var rec browsertrixCDXRecord
		if err := json.Unmarshal([]byte(parts[2]), &rec); err != nil {
			continue
		}
		if browsertrixCDXRecordReplayable(rec) {
			replayable[normalizeURL(rec.URL)] = true
		}
	}
	return replayable, scanner.Err()
}

func browsertrixReplayableURLMatch(replayable map[string]bool, normalizedURL string) bool {
	if replayable[normalizedURL] {
		return true
	}
	alt := browsertrixTrailingSlashVariant(normalizedURL)
	return alt != "" && replayable[alt]
}

func browsertrixTrailingSlashVariant(normalizedURL string) string {
	parsed, err := parseURL(normalizedURL)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	if parsed.Path == "" {
		parsed.Path = "/"
		return parsed.String()
	}
	if parsed.Path == "/" {
		parsed.Path = ""
		return parsed.String()
	}
	if strings.HasSuffix(parsed.Path, "/") {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	} else {
		parsed.Path += "/"
	}
	return parsed.String()
}

func browsertrixCDXRecordReplayable(rec browsertrixCDXRecord) bool {
	rawURL := strings.TrimSpace(rec.URL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return false
	}
	method := strings.ToUpper(strings.TrimSpace(rec.Method))
	if method != "" && method != "GET" {
		return false
	}
	status, err := strconv.Atoi(strings.TrimSpace(rec.Status))
	if err != nil || status < 200 || status >= 400 {
		return false
	}
	mime := strings.ToLower(strings.TrimSpace(rec.Mime))
	return mime != "warc/revisit"
}

func readBrowsertrixPages(path string, includeFailures bool) ([]CapturedPage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pages []CapturedPage
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var page browsertrixPage
		if err := json.Unmarshal([]byte(line), &page); err != nil {
			continue
		}
		if page.URL == "" || page.Format != "" {
			continue
		}
		if !includeFailures && !browsertrixPageIndexable(page) {
			continue
		}
		title := firstNonEmpty(page.Title, page.URL)
		pages = append(pages, CapturedPage{
			URL:          page.URL,
			FinalURL:     page.URL,
			CanonicalURL: page.URL,
			Title:        title,
			Markdown:     browsertrixMarkdown(title, page.Text),
			Depth:        page.Depth,
			StatusCode:   page.Status,
			ContentType:  page.Mime,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pages, nil
}

func browsertrixPageIndexable(page browsertrixPage) bool {
	if page.Status >= 400 {
		return false
	}
	mime := strings.ToLower(strings.TrimSpace(page.Mime))
	if mime != "" && !strings.Contains(mime, "html") {
		return false
	}
	return strings.TrimSpace(page.Title) != "" || strings.TrimSpace(page.Text) != ""
}

func browsertrixMarkdown(title, text string) string {
	text = strings.TrimSpace(text)
	title = strings.TrimSpace(title)
	if title == "" {
		return text
	}
	if text == "" {
		return "# " + title + "\n"
	}
	return "# " + title + "\n\n" + text + "\n"
}

func findBrowsertrixArchive(collectionDir, jobID string) (string, error) {
	preferredWACZ := filepath.Join(collectionDir, jobID+".wacz")
	if fileExists(preferredWACZ) {
		return preferredWACZ, nil
	}
	matches, err := filepath.Glob(filepath.Join(collectionDir, "*.wacz"))
	if err != nil {
		return "", err
	}
	if len(matches) > 0 {
		return matches[0], nil
	}
	preferredWARC := filepath.Join(collectionDir, jobID+"_0.warc.gz")
	if fileExists(preferredWARC) {
		return preferredWARC, nil
	}
	matches, err = filepath.Glob(filepath.Join(collectionDir, "*.warc.gz"))
	if err != nil {
		return "", err
	}
	if len(matches) > 0 {
		return matches[0], nil
	}
	return "", fmt.Errorf("Browsertrix output archive not found in %s", collectionDir)
}

func streamBrowsertrixLog(path string, offset int64, onLog func(level, message string)) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			offset += int64(len(line))
			level, msg := parseBrowsertrixLogLine(line)
			if msg != "" {
				logLineFunc(onLog, level, msg)
			}
		}
		if err != nil {
			break
		}
	}
	return offset
}

func parseBrowsertrixLogLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	var entry browsertrixLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return "info", line
	}
	level := firstNonEmpty(entry.LogLevel, "info")
	msg := entry.Message
	if msg == "" {
		return level, ""
	}
	if entry.Context == "crawlStatus" {
		var details struct {
			Crawled int `json:"crawled"`
			Total   int `json:"total"`
			Pending int `json:"pending"`
			Failed  int `json:"failed"`
			Limit   struct {
				Max int  `json:"max"`
				Hit bool `json:"hit"`
			} `json:"limit"`
		}
		if err := json.Unmarshal(entry.Details, &details); err == nil {
			return level, fmt.Sprintf("Browsertrix crawl: %d/%d crawled, %d pending, %d failed", details.Crawled, details.Total, details.Pending, details.Failed)
		}
	}
	if requestLevel, requestMsg := browsertrixRequestFailureLog(entry, level); requestMsg != "" {
		return requestLevel, requestMsg
	}
	var details struct {
		Error string `json:"error"`
		Page  string `json:"page"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(entry.Details, &details); err == nil {
		if strings.HasPrefix(msg, "Invalid Page") && isBrowsertrixNonPageURL(details.URL) {
			out := "Browsertrix skipped non-page link " + details.URL
			if details.Page != "" {
				out += " on " + shortLogURL(details.Page)
			}
			return "debug", out
		}
		if details.Error != "" {
			msg += ": " + details.Error
		}
		if details.URL != "" {
			msg += " " + shortLogURL(details.URL)
		}
		if details.Page != "" {
			msg += " " + shortLogURL(details.Page)
		}
	}
	if entry.Context != "" && entry.Context != "general" {
		msg = "Browsertrix " + entry.Context + ": " + msg
	}
	return level, msg
}

func isBrowsertrixNonPageURL(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return lower == "" ||
		strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "#")
}

func browsertrixRequestFailureLog(entry browsertrixLogEntry, level string) (string, string) {
	if entry.Context != "recorder" || entry.Message != "Request failed" {
		return "", ""
	}
	var details struct {
		URL       string `json:"url"`
		Page      string `json:"page"`
		Type      string `json:"type"`
		ErrorText string `json:"errorText"`
		Status    int    `json:"status"`
	}
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		return "", ""
	}
	failedURL := firstNonEmpty(details.URL, details.Page)
	if failedURL == "" {
		return "", ""
	}

	prefix := "Browsertrix recorder: request failed"
	if strings.Contains(details.ErrorText, "ERR_BLOCKED_BY_CLIENT") {
		level = "debug"
		prefix = "Browsertrix recorder: blocked request"
	}
	if details.Type != "" {
		prefix += " [" + details.Type + "]"
	}
	msg := prefix + " " + shortLogURL(failedURL)
	if details.ErrorText != "" {
		msg += ": " + details.ErrorText
	} else if details.Status != 0 {
		msg += fmt.Sprintf(": HTTP %d", details.Status)
	}
	if details.Page != "" && details.Page != failedURL && level != "debug" {
		msg += " on " + shortLogURL(details.Page)
	}
	return level, msg
}

func shortLogURL(value string) string {
	value = strings.TrimSpace(value)
	const limit = 180
	if len(value) <= limit {
		return value
	}
	return value[:120] + "..." + value[len(value)-45:]
}

func readBrowsertrixDone(path string) (*browsertrixDone, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var done browsertrixDone
	if err := json.Unmarshal(b, &done); err != nil {
		return nil, err
	}
	return &done, nil
}

func (a *App) browsertrixJobDir(jobID string) string {
	return filepath.Join(a.dataDir, "browsertrix", "jobs", jobID)
}

func (a *App) browsertrixCollectionDir(jobID string) string {
	return filepath.Join(a.dataDir, "browsertrix", "runs", "collections", jobID)
}

func cleanupBrowsertrixJobSecrets(jobDir string) {
	_ = os.Remove(filepath.Join(jobDir, "cookies.json"))
	_ = os.Remove(filepath.Join(jobDir, "cookie-profile.tar.gz"))
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return b
}

func logLineFunc(onLog func(level, message string), level, message string) {
	if onLog != nil {
		onLog(level, message)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
