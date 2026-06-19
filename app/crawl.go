package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type CapturedPage struct {
	URL           string
	FinalURL      string
	CanonicalURL  string
	Title         string
	Markdown      string
	Replayable    bool
	Depth         int
	StatusCode    int
	ContentType   string
	ResourceCount int
	BlockedCount  int
}

type CaptureResult struct {
	WARCPath string
	Pages    []CapturedPage
}

func captureTimeout(maxPages int) time.Duration {
	if maxPages < 1 {
		maxPages = 1
	}
	timeout := time.Duration(maxPages) * 45 * time.Second
	if timeout < 5*time.Minute {
		return 5 * time.Minute
	}
	if timeout > 2*time.Hour {
		return 2 * time.Hour
	}
	return timeout
}

func capturedPageFailureReason(page CapturedPage) string {
	if page.StatusCode >= 400 {
		return fmt.Sprintf("captured main page returned HTTP %d", page.StatusCode)
	}
	if page.StatusCode == 0 && strings.TrimSpace(page.Markdown) == "" {
		return "captured main page has no HTTP status or extracted text"
	}

	text := strings.ToLower(page.Title + "\n" + page.Markdown)
	blockIndicators := []string{
		"something has gone terribly wrong :(",
		"enable javascript and cookies to continue",
		"checking if the site connection is secure",
		"verify you are human",
		"this page could not be loaded",
		"attention required! | cloudflare",
		"error 1020",
	}
	for _, indicator := range blockIndicators {
		if strings.Contains(text, indicator) {
			return fmt.Sprintf("captured main page looks like a browser or bot-block error page: %q", indicator)
		}
	}
	return ""
}

func parseURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid URL %q", rawURL)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed, nil
}

func normalizeURL(rawURL string) string {
	parsed, err := parseURL(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Fragment = ""
	if (parsed.Scheme == "http" && strings.HasSuffix(parsed.Host, ":80")) ||
		(parsed.Scheme == "https" && strings.HasSuffix(parsed.Host, ":443")) {
		parsed.Host = strings.Split(parsed.Host, ":")[0]
	}
	return parsed.String()
}

func shouldCrawl(link, startHost, scope, prefix string, visited map[string]bool) bool {
	if visited[normalizeURL(link)] {
		return false
	}
	if !inCaptureScope(link, startHost, scope, prefix) {
		return false
	}

	parsed, err := parseURL(link)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	skipExts := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".woff", ".woff2", ".ttf", ".otf", ".eot", ".ico",
		".pdf", ".mp3", ".mp4", ".webm", ".webp", ".json",
		".xml", ".rss", ".atom", ".zip", ".gz", ".tar",
	}
	for _, ext := range skipExts {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	return true
}

func inCaptureScope(rawURL, startHost, scope, prefix string) bool {
	parsed, err := parseURL(rawURL)
	if err != nil {
		return false
	}
	switch scope {
	case "single_page", "same_subdomain", "":
		return strings.EqualFold(parsed.Hostname(), startHost)
	case "prefix":
		return prefix != "" && strings.HasPrefix(rawURL, prefix)
	case "explicit_urls":
		return true
	default:
		return strings.EqualFold(parsed.Hostname(), startHost)
	}
}

func markdownFromText(title, pageURL, text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines)+3)
	if strings.TrimSpace(title) != "" {
		out = append(out, "# "+strings.TrimSpace(title), "")
	}
	if strings.TrimSpace(pageURL) != "" {
		out = append(out, "Source: "+strings.TrimSpace(pageURL), "")
	}
	blank := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if !blank && len(out) > 0 {
				out = append(out, "")
				blank = true
			}
			continue
		}
		out = append(out, line)
		blank = false
	}
	return strings.TrimSpace(strings.Join(out, "\n")) + "\n"
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
