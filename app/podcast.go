package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	substackArchivePageSize = 20
	podcastDownloadAttempts = 4
)

type substackArchivePost struct {
	ID                     int64   `json:"id"`
	Type                   string  `json:"type"`
	Slug                   string  `json:"slug"`
	Title                  string  `json:"title"`
	Description            string  `json:"description"`
	CanonicalURL           string  `json:"canonical_url"`
	PostDate               string  `json:"post_date"`
	PodcastDuration        float64 `json:"podcast_duration"`
	PodcastEpisodeImageURL string  `json:"podcast_episode_image_url"`
	CoverImage             string  `json:"cover_image"`
	PodcastUpload          *struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		MediaType       string `json:"media_type"`
		PrimaryFileSize int64  `json:"primary_file_size"`
	} `json:"podcastUpload"`
}

type podcastEpisode struct {
	PostID      int64   `json:"postId"`
	UploadID    string  `json:"uploadId"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Link        string  `json:"link"`
	PublishedAt string  `json:"publishedAt"`
	Duration    float64 `json:"duration,omitempty"`
	ImageURL    string  `json:"imageUrl,omitempty"`
	Filename    string  `json:"filename"`
	ContentType string  `json:"contentType"`
	Bytes       int64   `json:"bytes"`
}

type podcastManifest struct {
	SiteID           string           `json:"siteId"`
	Title            string           `json:"title"`
	Description      string           `json:"description,omitempty"`
	Link             string           `json:"link"`
	Language         string           `json:"language,omitempty"`
	ImageURL         string           `json:"imageUrl,omitempty"`
	ExpectedEpisodes int              `json:"expectedEpisodes"`
	Episodes         []podcastEpisode `json:"episodes"`
	UpdatedAt        time.Time        `json:"updatedAt"`
}

type PodcastSummary struct {
	Available        bool   `json:"available"`
	EpisodeCount     int    `json:"episodeCount"`
	ExpectedEpisodes int    `json:"expectedEpisodes"`
	TotalBytes       int64  `json:"totalBytes"`
	FeedURL          string `json:"feedUrl,omitempty"`
}

type sourcePodcastChannel struct {
	Title       string `xml:"channel>title"`
	Description string `xml:"channel>description"`
	Link        string `xml:"channel>link"`
	Language    string `xml:"channel>language"`
	Image       struct {
		URL string `xml:"url"`
	} `xml:"channel>image"`
}

func cookieHeaderForBrowserCookies(cookies []browserCookieData, rawURL string) string {
	target, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(target.Hostname())
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	now := float64(time.Now().Unix())
	pairs := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie.Name == "" || cookie.Expires != nil && *cookie.Expires <= now || cookie.Secure && target.Scheme != "https" {
			continue
		}
		cookieHost := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(cookie.Domain)), ".")
		if cookie.URL != "" {
			parsed, parseErr := url.Parse(cookie.URL)
			if parseErr != nil || !strings.EqualFold(parsed.Hostname(), host) {
				continue
			}
		} else if cookieHost == "" || !domainMatches(host, cookieHost) {
			continue
		}
		cookiePath := firstNonEmpty(cookie.Path, "/")
		if !strings.HasPrefix(path, cookiePath) {
			continue
		}
		pairs = append(pairs, (&http.Cookie{Name: cookie.Name, Value: cookie.Value}).String())
	}
	return strings.Join(pairs, "; ")
}

func substackRequest(ctx context.Context, client *http.Client, rawURL, accept string, cookies []browserCookieData) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "WARCdriver/1.0 Substack podcast mirror")
	if cookieHeader := cookieHeaderForBrowserCookies(cookies, rawURL); cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	return client.Do(req)
}

func discoverSubstackPodcast(ctx context.Context, homepage string, cookies []browserCookieData) (podcastManifest, []substackArchivePost, error) {
	client := &http.Client{Timeout: substackSitemapTimeout}
	manifest := podcastManifest{Link: homepage, Language: "en"}
	if resp, err := substackRequest(ctx, client, homepage+"feed", "application/rss+xml,application/xml;q=0.9", cookies); err == nil {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var channel sourcePodcastChannel
			_ = xml.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&channel)
			manifest.Title = strings.TrimSpace(channel.Title)
			manifest.Description = strings.TrimSpace(channel.Description)
			manifest.Language = firstNonEmpty(strings.TrimSpace(channel.Language), "en")
			manifest.ImageURL = strings.TrimSpace(channel.Image.URL)
		}
		_ = resp.Body.Close()
	}

	seen := map[string]bool{}
	episodes := []substackArchivePost{}
	for offset := 0; offset < 10000; offset += substackArchivePageSize {
		archiveURL := homepage + "api/v1/archive?sort=new&search=&offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(substackArchivePageSize)
		resp, err := substackRequest(ctx, client, archiveURL, "application/json", cookies)
		if err != nil {
			return manifest, nil, fmt.Errorf("fetch Substack podcast inventory: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			return manifest, nil, fmt.Errorf("fetch Substack podcast inventory: HTTP %d", resp.StatusCode)
		}
		var page []substackArchivePost
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&page)
		_ = resp.Body.Close()
		if err != nil {
			return manifest, nil, fmt.Errorf("parse Substack podcast inventory: %w", err)
		}
		for _, post := range page {
			if post.PodcastUpload == nil || post.PodcastUpload.ID == "" || post.PodcastUpload.MediaType != "audio" || seen[post.PodcastUpload.ID] {
				continue
			}
			seen[post.PodcastUpload.ID] = true
			episodes = append(episodes, post)
		}
		if len(page) < substackArchivePageSize {
			break
		}
	}
	return manifest, episodes, nil
}

func (a *App) podcastDir(siteID string) string {
	return filepath.Join(a.dataDir, "podcasts", siteID)
}

func (a *App) podcastManifestPath(siteID string) string {
	return filepath.Join(a.podcastDir(siteID), "manifest.json")
}

func (a *App) loadPodcastManifest(siteID string) (podcastManifest, error) {
	var manifest podcastManifest
	b, err := os.ReadFile(a.podcastManifestPath(siteID))
	if err != nil {
		return manifest, err
	}
	err = json.Unmarshal(b, &manifest)
	return manifest, err
}

func (a *App) writePodcastManifest(manifest podcastManifest) error {
	manifest.UpdatedAt = time.Now().UTC()
	sort.SliceStable(manifest.Episodes, func(i, j int) bool { return manifest.Episodes[i].PublishedAt > manifest.Episodes[j].PublishedAt })
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(a.podcastManifestPath(manifest.SiteID), b, 0o644)
}

func (a *App) podcastSummary(siteID string) *PodcastSummary {
	manifest, err := a.loadPodcastManifest(siteID)
	if err != nil || manifest.ExpectedEpisodes == 0 {
		return nil
	}
	summary := &PodcastSummary{Available: len(manifest.Episodes) > 0, EpisodeCount: len(manifest.Episodes), ExpectedEpisodes: manifest.ExpectedEpisodes}
	for _, episode := range manifest.Episodes {
		summary.TotalBytes += episode.Bytes
	}
	if summary.Available {
		summary.FeedURL = "/api/sites/" + siteID + "/podcast/feed.xml"
	}
	return summary
}

func podcastFilename(post substackArchivePost) string {
	return fmt.Sprintf("%d-%s.mp3", post.ID, post.PodcastUpload.ID)
}

func (a *App) mirrorSubstackPodcast(ctx context.Context, site *SiteRecord, homepage string, cookies []browserCookieData, jobLog func(string, string)) (PodcastSummary, error) {
	manifest, posts, err := discoverSubstackPodcast(ctx, homepage, cookies)
	if err != nil {
		return PodcastSummary{}, err
	}
	if len(posts) == 0 {
		jobLog("info", "Substack podcast detection: no audio episodes found")
		return PodcastSummary{}, nil
	}
	manifest.SiteID = site.ID
	manifest.Title = firstNonEmpty(manifest.Title, site.Title.String, site.Host)
	manifest.Description = firstNonEmpty(manifest.Description, site.Summary.String)
	manifest.Link = homepage
	manifest.ExpectedEpisodes = len(posts)
	old, _ := a.loadPodcastManifest(site.ID)
	oldByUpload := map[string]podcastEpisode{}
	for _, episode := range old.Episodes {
		oldByUpload[episode.UploadID] = episode
	}
	jobLog("info", fmt.Sprintf("Substack podcast detected: %d audio episodes; mirroring full media files", len(posts)))
	if err := os.MkdirAll(a.podcastDir(site.ID), 0o755); err != nil {
		return PodcastSummary{}, err
	}
	if err := a.writePodcastManifest(manifest); err != nil {
		return PodcastSummary{}, err
	}
	failed := 0
	for i, post := range posts {
		if err := ctx.Err(); err != nil {
			return PodcastSummary{}, err
		}
		filename := podcastFilename(post)
		mediaPath := filepath.Join(a.podcastDir(site.ID), filename)
		bytes, contentType, downloadErr := a.downloadSubstackPodcastEpisode(ctx, homepage, post.PodcastUpload.ID, post.PodcastUpload.PrimaryFileSize, mediaPath, cookies)
		if downloadErr != nil {
			if previous, ok := oldByUpload[post.PodcastUpload.ID]; ok {
				if info, statErr := os.Stat(filepath.Join(a.podcastDir(site.ID), previous.Filename)); statErr == nil && info.Size() > 0 {
					manifest.Episodes = append(manifest.Episodes, previous)
					continue
				}
			}
			failed++
			jobLog("warn", fmt.Sprintf("podcast audio %d/%d failed (%s): %v", i+1, len(posts), post.Title, downloadErr))
			continue
		}
		episode := podcastEpisode{
			PostID: post.ID, UploadID: post.PodcastUpload.ID, Title: firstNonEmpty(post.Title, post.Slug),
			Description: post.Description, Link: firstNonEmpty(post.CanonicalURL, homepage+"p/"+post.Slug),
			PublishedAt: post.PostDate, Duration: post.PodcastDuration,
			ImageURL: firstNonEmpty(post.PodcastEpisodeImageURL, post.CoverImage), Filename: filename,
			ContentType: firstNonEmpty(contentType, "audio/mpeg"), Bytes: bytes,
		}
		manifest.Episodes = append(manifest.Episodes, episode)
		if err := a.writePodcastManifest(manifest); err != nil {
			return PodcastSummary{}, err
		}
		message := fmt.Sprintf("podcast audio %d/%d ready: %s", i+1, len(posts), episode.Title)
		jobLog("info", message)
	}
	if err := a.writePodcastManifest(manifest); err != nil {
		return PodcastSummary{}, err
	}
	summary := *a.podcastSummary(site.ID)
	if failed > 0 {
		jobLog("warn", fmt.Sprintf("podcast mirror incomplete: %d/%d episodes ready; use Refresh podcast to retry", summary.EpisodeCount, summary.ExpectedEpisodes))
	} else {
		jobLog("info", fmt.Sprintf("podcast mirror complete: %d episodes, %s", summary.EpisodeCount, humanBytes(summary.TotalBytes)))
	}
	return summary, nil
}

func (a *App) downloadSubstackPodcastEpisode(ctx context.Context, homepage, uploadID string, expectedSize int64, targetPath string, cookies []browserCookieData) (int64, string, error) {
	if info, err := os.Stat(targetPath); err == nil && info.Size() > 0 {
		if expectedSize <= 0 || info.Size() == expectedSize {
			return info.Size(), "audio/mpeg", nil
		}
		if info.Size() < expectedSize {
			_ = os.Rename(targetPath, targetPath+".part")
		} else {
			_ = os.Remove(targetPath)
		}
	}
	partPath := targetPath + ".part"
	var lastErr error
	for attempt := 0; attempt < podcastDownloadAttempts; attempt++ {
		if attempt > 0 {
			if err := waitForRetry(ctx, time.Duration(5*(1<<(attempt-1)))*time.Second); err != nil {
				return 0, "", err
			}
		}
		signedURL, err := resolveSubstackPodcastURL(ctx, homepage, uploadID, cookies)
		if err != nil {
			lastErr = err
			continue
		}
		start := int64(0)
		if info, statErr := os.Stat(partPath); statErr == nil {
			start = info.Size()
			if expectedSize > 0 && start > expectedSize {
				_ = os.Truncate(partPath, 0)
				start = 0
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedURL, nil)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("User-Agent", "WARCdriver/1.0 Substack podcast mirror")
		if start > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && expectedSize > 0 && start == expectedSize {
			_ = resp.Body.Close()
			if err := os.Rename(partPath, targetPath); err != nil {
				return 0, "", err
			}
			return expectedSize, "audio/mpeg", nil
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("media HTTP %d", resp.StatusCode)
			continue
		}
		contentType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
		if !strings.HasPrefix(contentType, "audio/") && contentType != "application/octet-stream" && contentType != "binary/octet-stream" {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("unexpected media content type %q", contentType)
			continue
		}
		flags := os.O_CREATE | os.O_WRONLY
		if resp.StatusCode == http.StatusPartialContent && start > 0 {
			flags |= os.O_APPEND
		} else {
			flags |= os.O_TRUNC
			start = 0
		}
		file, err := os.OpenFile(partPath, flags, 0o644)
		if err != nil {
			_ = resp.Body.Close()
			return 0, "", err
		}
		_, copyErr := io.Copy(file, resp.Body)
		closeErr := file.Close()
		_ = resp.Body.Close()
		if copyErr != nil || closeErr != nil {
			lastErr = firstError(copyErr, closeErr)
			continue
		}
		info, err := os.Stat(partPath)
		if err != nil || info.Size() == 0 {
			lastErr = fmt.Errorf("downloaded media is empty")
			continue
		}
		if expectedSize > 0 && info.Size() != expectedSize {
			lastErr = fmt.Errorf("incomplete media: downloaded %d of %d bytes", info.Size(), expectedSize)
			continue
		}
		if err := os.Rename(partPath, targetPath); err != nil {
			return 0, "", err
		}
		if contentType == "application/octet-stream" || contentType == "binary/octet-stream" {
			contentType = "audio/mpeg"
		}
		return info.Size(), contentType, nil
	}
	return 0, "", fmt.Errorf("download failed after %d attempts: %w", podcastDownloadAttempts, lastErr)
}

func resolveSubstackPodcastURL(ctx context.Context, homepage, uploadID string, cookies []browserCookieData) (string, error) {
	resolverURL := homepage + "api/v1/video/upload/" + url.PathEscape(uploadID) + "/src?type=mp4"
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := substackRequest(ctx, client, resolverURL, "audio/mpeg,application/octet-stream;q=0.9", cookies)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("audio resolver HTTP %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil || parsed.Hostname() == "" || parsed.Scheme != "https" {
		return "", fmt.Errorf("audio resolver returned an invalid redirect")
	}
	return parsed.String(), nil
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func humanBytes(size int64) string {
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := unit, 0
	for n := size / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func (a *App) runPodcastMirrorJob(ctx context.Context, job *ArchiveJobRecord, jobLog func(string, string)) {
	site, err := a.store.GetSiteByHost(ctx, hostFromURL(job.URL))
	if err != nil {
		_ = a.store.FailJob(context.Background(), job.ID, fmt.Errorf("podcast site not found: %w", err))
		return
	}
	var cookies []browserCookieData
	if job.CookieProfileID.Valid {
		profile, profileErr := a.store.GetCookieProfile(ctx, job.CookieProfileID.String)
		if profileErr != nil {
			_ = a.store.FailJob(context.Background(), job.ID, profileErr)
			return
		}
		cookies, err = browserCookiesForProfile(profile, job.URL)
		if err != nil {
			_ = a.store.FailJob(context.Background(), job.ID, err)
			return
		}
	}
	homepage, err := substackHomepageURL(job.URL)
	if err == nil {
		_, err = a.mirrorSubstackPodcast(ctx, site, homepage, cookies, jobLog)
	}
	if err != nil {
		if ctx.Err() != nil {
			jobLog("warn", "podcast refresh canceled")
			_, _ = a.store.CancelJob(context.Background(), job.ID)
			return
		}
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}
	_ = a.store.FinishJobWithoutCapture(context.Background(), job.ID, "podcast mirror complete")
	jobLog("info", "podcast refresh complete")
}

func (a *App) siteVisibleForPodcast(w http.ResponseWriter, r *http.Request, siteID string) (*SiteRecord, bool) {
	user, _ := userFromContext(r.Context())
	site, err := a.store.GetSiteVisible(r.Context(), siteID, user)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "podcast not found")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	return site, true
}

func (a *App) ServePodcastFeed(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	site, ok := a.siteVisibleForPodcast(w, r, siteID)
	if !ok {
		return
	}
	manifest, err := a.loadPodcastManifest(siteID)
	if err != nil || len(manifest.Episodes) == 0 {
		writeError(w, http.StatusNotFound, "podcast feed not found")
		return
	}
	baseURL := requestBaseURL(r)
	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(renderPodcastRSS(manifest, site, baseURL))
}

func (a *App) ServePodcastMedia(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	if _, ok := a.siteVisibleForPodcast(w, r, siteID); !ok {
		return
	}
	filename := chi.URLParam(r, "filename")
	if filename == "" || filename != filepath.Base(filename) {
		writeError(w, http.StatusBadRequest, "invalid media filename")
		return
	}
	manifest, err := a.loadPodcastManifest(siteID)
	if err != nil {
		writeError(w, http.StatusNotFound, "podcast media not found")
		return
	}
	allowed := false
	for _, episode := range manifest.Episodes {
		if episode.Filename == filename {
			allowed = true
			if episode.ContentType != "" {
				w.Header().Set("Content-Type", episode.ContentType)
			}
			break
		}
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "podcast media not found")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeFile(w, r, filepath.Join(a.podcastDir(siteID), filename))
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	host := r.Host
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		host = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return scheme + "://" + host
}

func xmlText(value string) string {
	var out strings.Builder
	_ = xml.EscapeText(&out, []byte(value))
	return out.String()
}

func renderPodcastRSS(manifest podcastManifest, site *SiteRecord, baseURL string) []byte {
	feedURL := baseURL + "/api/sites/" + manifest.SiteID + "/podcast/feed.xml"
	var out strings.Builder
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	out.WriteString(`<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel>`)
	out.WriteString("<title>" + xmlText(firstNonEmpty(manifest.Title, site.Title.String, site.Host)) + "</title>")
	out.WriteString("<description>" + xmlText(firstNonEmpty(manifest.Description, site.Summary.String)) + "</description>")
	out.WriteString("<link>" + xmlText(manifest.Link) + "</link>")
	out.WriteString(`<atom:link href="` + xmlText(feedURL) + `" rel="self" type="application/rss+xml"/>`)
	out.WriteString("<language>" + xmlText(firstNonEmpty(manifest.Language, "en")) + "</language>")
	out.WriteString("<lastBuildDate>" + manifest.UpdatedAt.UTC().Format(time.RFC1123Z) + "</lastBuildDate>")
	if manifest.ImageURL != "" {
		out.WriteString(`<itunes:image href="` + xmlText(manifest.ImageURL) + `"/>`)
	}
	for _, episode := range manifest.Episodes {
		mediaURL := baseURL + "/api/sites/" + manifest.SiteID + "/podcast/media/" + url.PathEscape(episode.Filename)
		out.WriteString("<item><title>" + xmlText(episode.Title) + "</title>")
		out.WriteString("<description>" + xmlText(episode.Description) + "</description>")
		out.WriteString("<link>" + xmlText(episode.Link) + "</link>")
		out.WriteString(`<guid isPermaLink="false">` + xmlText(fmt.Sprintf("warcdriver:%s:%d:%s", manifest.SiteID, episode.PostID, episode.UploadID)) + `</guid>`)
		if published, err := time.Parse(time.RFC3339Nano, episode.PublishedAt); err == nil {
			out.WriteString("<pubDate>" + published.UTC().Format(time.RFC1123Z) + "</pubDate>")
		}
		out.WriteString(`<enclosure url="` + xmlText(mediaURL) + `" length="` + strconv.FormatInt(episode.Bytes, 10) + `" type="` + xmlText(firstNonEmpty(episode.ContentType, "audio/mpeg")) + `"/>`)
		if episode.Duration > 0 {
			out.WriteString("<itunes:duration>" + strconv.Itoa(int(episode.Duration)) + "</itunes:duration>")
		}
		if episode.ImageURL != "" {
			out.WriteString(`<itunes:image href="` + xmlText(episode.ImageURL) + `"/>`)
		}
		out.WriteString("</item>")
	}
	out.WriteString("</channel></rss>\n")
	return []byte(out.String())
}
