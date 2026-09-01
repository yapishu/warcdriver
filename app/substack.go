package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const substackSitemapTimeout = 45 * time.Second

type substackSitemap struct {
	URLs []struct {
		Location string `xml:"loc"`
	} `xml:"url"`
}

func substackHomepageURL(rawURL string) (string, error) {
	parsed, err := parseURL(rawURL)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "substack.com" || !strings.HasSuffix(host, ".substack.com") {
		return "", fmt.Errorf("Substack mode requires a publication URL such as https://publication.substack.com")
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/"}).String(), nil
}

func discoverSubstackPosts(ctx context.Context, client *http.Client, rawURL string) ([]string, error) {
	homepage, err := substackHomepageURL(rawURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: substackSitemapTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, homepage+"sitemap.xml", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/xml,text/xml;q=0.9,*/*;q=0.1")
	req.Header.Set("User-Agent", "WARCdriver/1.0 Substack sitemap discovery")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Substack sitemap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("fetch Substack sitemap: HTTP %d", resp.StatusCode)
	}
	var sitemap substackSitemap
	decoder := xml.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	if err := decoder.Decode(&sitemap); err != nil {
		return nil, fmt.Errorf("parse Substack sitemap: %w", err)
	}
	home, _ := url.Parse(homepage)
	seen := map[string]bool{}
	posts := make([]string, 0, len(sitemap.URLs))
	for _, entry := range sitemap.URLs {
		candidate, err := url.Parse(strings.TrimSpace(entry.Location))
		if err != nil || !strings.EqualFold(candidate.Hostname(), home.Hostname()) || !isSubstackPostURL(candidate.String()) {
			continue
		}
		candidate.Fragment = ""
		candidate.RawQuery = ""
		normalized := normalizeURL(candidate.String())
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		posts = append(posts, candidate.String())
	}
	if len(posts) == 0 {
		return nil, fmt.Errorf("Substack sitemap did not contain any post URLs")
	}
	sort.Strings(posts)
	return posts, nil
}

func isSubstackPostURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	return len(parts) == 2 && parts[0] == "p" && parts[1] != ""
}

func missingCapturedURLs(expected []string, pages []CapturedPage) []string {
	captured := make(map[string]bool, len(pages))
	for _, page := range pages {
		captured[normalizeURL(page.URL)] = true
		if page.FinalURL != "" {
			captured[normalizeURL(page.FinalURL)] = true
		}
	}
	missing := make([]string, 0)
	for _, rawURL := range expected {
		if !captured[normalizeURL(rawURL)] {
			missing = append(missing, rawURL)
		}
	}
	return missing
}

func capturedPageForURL(pages []CapturedPage, rawURL string) (CapturedPage, bool) {
	want := normalizeURL(rawURL)
	for _, page := range pages {
		if normalizeURL(page.URL) == want || (page.FinalURL != "" && normalizeURL(page.FinalURL) == want) {
			return page, true
		}
	}
	return CapturedPage{}, false
}
