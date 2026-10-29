package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReplaceCapturedItemRequiresReplayableResponse(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := OpenStore(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	app := &App{store: store, dataDir: dataDir}
	job, err := store.CreateArchiveJob(ctx, "", ArchiveJobCreate{
		URL: "https://example.com/post", Scope: "single_page", Visibility: VisibilityPrivate,
	})
	if err != nil {
		t.Fatal(err)
	}
	site, err := store.UpsertSite(ctx, "example.com", "Example", "")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := store.CreateCapture(ctx, job.ID, site.ID, "", job.URL, "Example", filepath.Join(dataDir, "capture.wacz"), VisibilityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.CreateItem(ctx, ItemRecord{
		JobID: job.ID, CaptureID: capture.ID, SiteID: site.ID,
		URL: job.URL, Title: "Existing page", TagsJSON: "[]", Replayable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	markdownPath, err := app.writeCapturedMarkdown(capture.ID, item.ID, "Existing content")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetItemMarkdownPath(ctx, item.ID, markdownPath); err != nil {
		t.Fatal(err)
	}
	before, err := store.GetItem(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacementJob, err := store.CreateArchiveJob(ctx, "", ArchiveJobCreate{
		URL: job.URL, Scope: "single_page", Visibility: VisibilityPrivate, ReplaceItemID: item.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := store.CreateCapture(ctx, replacementJob.ID, site.ID, "", job.URL, "Replacement", filepath.Join(dataDir, "replacement.wacz"), VisibilityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	page := CapturedPage{URL: job.URL, Title: "Replacement page", Markdown: "Replacement content", StatusCode: 200, ContentType: "text/html"}
	err = app.replaceCapturedItem(ctx, replacementJob, replacement, site, page, false, func(string, string) {})
	if err == nil || !strings.Contains(err.Error(), "no replayable document response") {
		t.Fatalf("replacement error = %v; want non-replayable response rejection", err)
	}
	after, err := store.GetItem(ctx, item.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected replacement changed item: before=%+v after=%+v err=%v", before, after, err)
	}
	content, err := os.ReadFile(markdownPath)
	if err != nil || string(content) != "Existing content" {
		t.Fatalf("existing markdown = %q, err = %v", content, err)
	}
	if _, err := os.Stat(store.MarkdownPath(replacement.ID, item.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected replacement must not write markdown: %v", err)
	}

	page.Replayable = true
	if err := app.replaceCapturedItem(ctx, replacementJob, replacement, site, page, false, func(string, string) {}); err != nil {
		t.Fatal(err)
	}
	after, err = store.GetItem(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != item.ID || after.CaptureID != replacement.ID || after.JobID != replacementJob.ID || after.Title != page.Title || !after.Replayable {
		t.Fatalf("unexpected replacement item: %+v", after)
	}
	content, err = os.ReadFile(after.MarkdownPath.String)
	if err != nil || string(content) != page.Markdown {
		t.Fatalf("replacement markdown = %q, err = %v", content, err)
	}
}
