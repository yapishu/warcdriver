package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCookieHeaderForBrowserCookiesScopesDomainsAndPaths(t *testing.T) {
	cookies := []browserCookieData{
		{Name: "subscriber", Value: "yes", Domain: ".substack.com", Path: "/", Secure: true},
		{Name: "publication", Value: "yes", URL: "https://publication.substack.com/", Path: "/api", Secure: true},
		{Name: "wrong", Value: "no", Domain: ".example.com", Path: "/"},
	}
	header := cookieHeaderForBrowserCookies(cookies, "https://publication.substack.com/api/v1/archive")
	if !strings.Contains(header, "subscriber=yes") || !strings.Contains(header, "publication=yes") || strings.Contains(header, "wrong=no") {
		t.Fatalf("unexpected scoped cookie header %q", header)
	}
	if got := cookieHeaderForBrowserCookies(cookies, "https://api.substack.com/feed"); got != "subscriber=yes" {
		t.Fatalf("expected only the domain cookie for api.substack.com, got %q", got)
	}
}

func TestRenderPodcastRSSUsesMirroredMediaURL(t *testing.T) {
	manifest := podcastManifest{
		SiteID: "site-1", Title: "A & B", Description: "Archive <copy>", Link: "https://publication.substack.com/",
		Language: "en", ExpectedEpisodes: 1, UpdatedAt: time.Date(2026, 9, 10, 1, 2, 3, 0, time.UTC),
		Episodes: []podcastEpisode{{
			PostID: 42, UploadID: "upload-1", Title: "Episode & one", Link: "https://publication.substack.com/p/one",
			PublishedAt: "2026-09-09T01:02:03Z", Filename: "42-upload-1.mp3", ContentType: "audio/mpeg", Bytes: 1234,
		}},
	}
	rss := renderPodcastRSS(manifest, &SiteRecord{Host: "publication.substack.com"}, "https://arc.example")
	if err := xml.Unmarshal(rss, new(any)); err != nil {
		t.Fatalf("rendered podcast feed is not valid XML: %v\n%s", err, rss)
	}
	text := string(rss)
	for _, want := range []string{
		"A &amp; B", "Episode &amp; one",
		`url="https://arc.example/api/sites/site-1/podcast/media/42-upload-1.mp3"`,
		`href="https://arc.example/api/sites/site-1/podcast/feed.xml"`,
		`length="1234"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered feed missing %q", want)
		}
	}
}

func TestSourcePodcastChannelMetadata(t *testing.T) {
	var channel sourcePodcastChannel
	input := `<rss><channel><title>Example show</title><description>Example description</description><link>https://example.test</link><language>en-US</language><image><url>https://example.test/art.jpg</url></image></channel></rss>`
	if err := xml.Unmarshal([]byte(input), &channel); err != nil {
		t.Fatal(err)
	}
	if channel.Title != "Example show" || channel.Description != "Example description" || channel.Language != "en-US" || channel.Image.URL != "https://example.test/art.jpg" {
		t.Fatalf("unexpected channel metadata: %+v", channel)
	}
}

func TestPublicPodcastFeedAndMediaRoutes(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := OpenStore(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	job, err := store.CreateArchiveJob(ctx, "", ArchiveJobCreate{URL: "https://publication.substack.com/", Scope: "substack", Visibility: VisibilityPublic})
	if err != nil {
		t.Fatal(err)
	}
	site, err := store.UpsertSite(ctx, "publication.substack.com", "Publication", "Description")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := store.CreateCapture(ctx, job.ID, site.ID, "", job.URL, "Publication", filepath.Join(dataDir, "capture.wacz"), VisibilityPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateItem(ctx, ItemRecord{JobID: job.ID, CaptureID: capture.ID, SiteID: site.ID, URL: "https://publication.substack.com/p/one", Title: "One", TagsJSON: "[]", Replayable: true}); err != nil {
		t.Fatal(err)
	}
	app := &App{store: store, dataDir: dataDir, activeJobs: map[string]context.CancelFunc{}}
	manifest := podcastManifest{
		SiteID: site.ID, Title: "Publication", Link: job.URL, ExpectedEpisodes: 1,
		Episodes: []podcastEpisode{{PostID: 1, UploadID: "upload", Title: "Episode", Link: job.URL + "p/one", PublishedAt: "2026-09-10T01:02:03Z", Filename: "1-upload.mp3", ContentType: "audio/mpeg", Bytes: 5}},
	}
	if err := app.writePodcastManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.podcastDir(site.ID), "1-upload.mp3"), []byte("audio"), 0o644); err != nil {
		t.Fatal(err)
	}

	feedReq := httptest.NewRequest(http.MethodGet, "/api/sites/"+site.ID+"/podcast/feed.xml", nil)
	feedReq.Host = "arc.example"
	feedReq.Header.Set("X-Forwarded-Proto", "https")
	feedRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(feedRec, feedReq)
	if feedRec.Code != http.StatusOK || !strings.Contains(feedRec.Body.String(), "https://arc.example/api/sites/"+site.ID+"/podcast/media/1-upload.mp3") {
		t.Fatalf("feed status/body = %d %s", feedRec.Code, feedRec.Body.String())
	}

	mediaReq := httptest.NewRequest(http.MethodGet, "/api/sites/"+site.ID+"/podcast/media/1-upload.mp3", nil)
	mediaRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(mediaRec, mediaReq)
	if mediaRec.Code != http.StatusOK || mediaRec.Body.String() != "audio" || mediaRec.Header().Get("Content-Type") != "audio/mpeg" {
		t.Fatalf("media status/type/body = %d %q %q", mediaRec.Code, mediaRec.Header().Get("Content-Type"), mediaRec.Body.String())
	}
}
