package main

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	got := normalizeURL("HTTPS://Example.COM:443/path?a=1#frag")
	want := "https://example.com/path?a=1"
	if got != want {
		t.Fatalf("normalizeURL got %q, want %q", got, want)
	}
}

func TestRateLimitRetryDelayUsesBoundedExponentialBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: 30 * time.Second},
		{attempt: 1, want: time.Minute},
		{attempt: 2, want: 2 * time.Minute},
		{attempt: 3, want: 4 * time.Minute},
		{attempt: 4, want: 5 * time.Minute},
		{attempt: 8, want: 5 * time.Minute},
	}
	for _, test := range tests {
		if got := rateLimitRetryDelay(test.attempt); got != test.want {
			t.Errorf("attempt %d delay = %s, want %s", test.attempt, got, test.want)
		}
	}
}

func TestShouldCrawlSameSubdomain(t *testing.T) {
	visited := map[string]bool{}
	if !shouldCrawl("https://pub.substack.com/p/post", "pub.substack.com", "same_subdomain", "", visited) {
		t.Fatal("expected same host article to be crawlable")
	}
	if shouldCrawl("https://other.substack.com/p/post", "pub.substack.com", "same_subdomain", "", visited) {
		t.Fatal("expected different substack subdomain to be rejected")
	}
	if shouldCrawl("https://pub.substack.com/image.png", "pub.substack.com", "same_subdomain", "", visited) {
		t.Fatal("expected asset extension to be rejected for page discovery")
	}
}

func TestMarkdownFromText(t *testing.T) {
	got := markdownFromText("Title", "https://example.com", "First line\n\nSecond line")
	if got == "" || got[:7] != "# Title" {
		t.Fatalf("unexpected markdown: %q", got)
	}
}

func TestCapturedPageFailureReason(t *testing.T) {
	if reason := capturedPageFailureReason(CapturedPage{StatusCode: 403}); reason == "" {
		t.Fatal("expected HTTP error capture to fail")
	}
	if reason := capturedPageFailureReason(CapturedPage{StatusCode: 429}); !strings.Contains(reason, "rate limited") {
		t.Fatalf("expected HTTP 429 capture to be treated as rate limited, got %q", reason)
	}
	if reason := capturedPageFailureReason(CapturedPage{StatusCode: 200, Markdown: "Too many requests"}); !strings.Contains(reason, "rate limited") {
		t.Fatalf("expected text rate limit page to fail, got %q", reason)
	}
	if reason := capturedPageFailureReason(CapturedPage{StatusCode: 200, Markdown: "Something has gone terribly wrong :("}); reason == "" {
		t.Fatal("expected browser error capture to fail")
	}
	if reason := capturedPageFailureReason(CapturedPage{}); reason == "" {
		t.Fatal("expected empty capture to fail")
	}
	if reason := capturedPageFailureReason(CapturedPage{StatusCode: 200, Title: "Article", Markdown: "Readable archived text"}); reason != "" {
		t.Fatalf("expected ordinary capture to pass, got %q", reason)
	}
}
