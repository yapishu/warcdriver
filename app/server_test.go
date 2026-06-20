package main

import (
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
	pathExcludeRx := `^/p/[^/]+/comment(?:[/?#]|$)`
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
