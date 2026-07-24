package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"warcdrive/internal/api"
)

func TestNormalizeArchiveJobDefaultSinglePageDepthZero(t *testing.T) {
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/"}
	got, err := normalizeArchiveJobRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "single_page" || got.Depth != 0 {
		t.Fatalf("scope/depth = %s/%d, want single_page/0", got.Scope, got.Depth)
	}
}

func TestNormalizeArchiveJobDepthWithoutScopePromotesLinkedPages(t *testing.T) {
	depth := 2
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/", Depth: &depth}
	got, err := normalizeArchiveJobRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "linked_pages" || got.Depth != 2 {
		t.Fatalf("scope/depth = %s/%d, want linked_pages/2", got.Scope, got.Depth)
	}
}

func TestNormalizeArchiveJobExplicitSinglePageIgnoresDepth(t *testing.T) {
	depth := 2
	scope := api.SinglePage
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/", Scope: &scope, Depth: &depth}
	got, err := normalizeArchiveJobRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "single_page" || got.Depth != 0 {
		t.Fatalf("scope/depth = %s/%d, want single_page/0", got.Scope, got.Depth)
	}
}

func TestNormalizeArchiveJobSubdomainDefaultsToAllDepth(t *testing.T) {
	scope := api.ArchiveScope("same_subdomain")
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/", Scope: &scope}
	got, err := normalizeArchiveJobRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "same_subdomain" || got.Depth != -1 || got.MaxPages != 0 {
		t.Fatalf("scope/depth/maxPages = %s/%d/%d, want same_subdomain/-1/0", got.Scope, got.Depth, got.MaxPages)
	}
}

func TestNormalizeArchiveJobAllowsUnlimitedMaxPages(t *testing.T) {
	maxPages := 0
	scope := api.ArchiveScope("same_subdomain")
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/", Scope: &scope, MaxPages: &maxPages}
	got, err := normalizeArchiveJobRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxPages != 0 {
		t.Fatalf("maxPages = %d, want 0 for unlimited", got.MaxPages)
	}
}

func TestNormalizeArchiveJobAcceptsPathExcludeRegex(t *testing.T) {
	pathExcludeRx := `/comment(?:[/?#]|$)`
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/", PathExcludeRx: &pathExcludeRx}
	got, err := normalizeArchiveJobRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.PathExcludeRx != pathExcludeRx {
		t.Fatalf("pathExcludeRx = %q, want %q", got.PathExcludeRx, pathExcludeRx)
	}
}

func TestNormalizeArchiveJobRejectsBadPathExcludeRegex(t *testing.T) {
	pathExcludeRx := `[`
	req := api.CreateArchiveJobJSONRequestBody{Url: "https://example.com/", PathExcludeRx: &pathExcludeRx}
	if _, err := normalizeArchiveJobRequest(req); err == nil {
		t.Fatal("expected invalid pathExcludeRx to fail")
	}
}

func TestReplayUIAssetIsAvailableWithoutAuthentication(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/warcs/ui.js", nil)
	rec := httptest.NewRecorder()

	(&App{}).Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/javascript; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("expected embedded replay UI JavaScript")
	}
}

func TestCapturePageRetriesDefaultMigration(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, "capture_page_retries_default_v2"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(ctx, "capture_page_retries", "0"); err != nil {
		t.Fatal(err)
	}
	if err := store.migrateCapturePageRetriesDefault(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetSetting(ctx, "capture_page_retries"); err != nil || got != "3" {
		t.Fatalf("capture_page_retries = %q, err = %v; want 3", got, err)
	}

	if err := store.SetSetting(ctx, "capture_page_retries", "0"); err != nil {
		t.Fatal(err)
	}
	if err := store.migrateCapturePageRetriesDefault(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetSetting(ctx, "capture_page_retries"); err != nil || got != "0" {
		t.Fatalf("explicit post-migration retry setting = %q, err = %v; want 0", got, err)
	}
}

func TestRecaptureItemQueuesReplacementJob(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := OpenStore(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	app := &App{store: store, dataDir: dataDir, activeJobs: map[string]context.CancelFunc{}}

	user, err := store.CreateUser(ctx, UserCreate{
		Username:     "owner",
		DisplayName:  "Owner",
		PasswordHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	host := "example.com"
	secret := "[]"
	profile, err := store.CreateCookieProfile(ctx, "example", "json", &host, &secret)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateArchiveJob(ctx, user.ID, ArchiveJobCreate{
		URL:             "https://example.com/archive",
		Scope:           "linked_pages",
		Depth:           2,
		MaxPages:        50,
		CookieProfileID: profile.ID,
		Visibility:      VisibilityPublic,
		Enrich:          false,
	})
	if err != nil {
		t.Fatal(err)
	}
	site, err := store.UpsertSite(ctx, "example.com", "Example")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := store.CreateCapture(ctx, job.ID, site.ID, user.ID, job.URL, "Example", filepath.Join(dataDir, "old.wacz"), VisibilityPublic)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.CreateItem(ctx, ItemRecord{
		JobID:      job.ID,
		CaptureID:  capture.ID,
		SiteID:     site.ID,
		URL:        "https://example.com/p/rate-limited",
		Title:      "Too Many Requests",
		TagsJSON:   "[]",
		Replayable: true,
		Depth:      1,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/items/"+item.ID+"/recapture", nil)
	req = req.WithContext(withUser(req.Context(), user))
	rec := httptest.NewRecorder()
	app.RecaptureItem(rec, req, item.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body api.ArchiveJob
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	queued, err := store.GetArchiveJob(ctx, body.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !queued.ReplaceItemID.Valid || queued.ReplaceItemID.String != item.ID {
		t.Fatalf("replace item = %#v, want %s", queued.ReplaceItemID, item.ID)
	}
	if queued.URL != item.URL || queued.Scope != "single_page" || queued.Depth != 0 || queued.MaxPages != 1 {
		t.Fatalf("queued job = url %s scope %s depth %d maxPages %d", queued.URL, queued.Scope, queued.Depth, queued.MaxPages)
	}
	if !queued.CookieProfileID.Valid || queued.CookieProfileID.String != profile.ID {
		t.Fatalf("cookie profile = %#v, want %s", queued.CookieProfileID, profile.ID)
	}
	if queued.Visibility != VisibilityPublic || queued.Enrich {
		t.Fatalf("visibility/enrich = %s/%v, want public/false", queued.Visibility, queued.Enrich)
	}
}
