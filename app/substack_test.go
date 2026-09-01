package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubstackHomepageURL(t *testing.T) {
	got, err := substackHomepageURL("https://Publication.Substack.com/p/post?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://publication.substack.com/" {
		t.Fatalf("homepage = %q", got)
	}
	if _, err := substackHomepageURL("https://example.com/"); err == nil {
		t.Fatal("expected non-Substack URL to fail")
	}
}

func TestDiscoverSubstackPostsFiltersAndDeduplicates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset>` +
			`<url><loc>https://publication.substack.com/archive</loc></url>` +
			`<url><loc>https://publication.substack.com/p/one</loc></url>` +
			`<url><loc>https://publication.substack.com/p/one?utm_source=x</loc></url>` +
			`<url><loc>https://publication.substack.com/p/two/comments</loc></url>` +
			`<url><loc>https://other.substack.com/p/other</loc></url>` +
			`<url><loc>https://publication.substack.com/p/two</loc></url>` +
			`</urlset>`))
	}))
	defer server.Close()

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(req)
	})}
	posts, err := discoverSubstackPosts(context.Background(), client, "https://publication.substack.com/")
	if err != nil {
		t.Fatal(err)
	}
	if len(posts) != 2 || !strings.HasSuffix(posts[0], "/p/one") || !strings.HasSuffix(posts[1], "/p/two") {
		t.Fatalf("posts = %#v", posts)
	}
}

func TestMissingCapturedURLs(t *testing.T) {
	missing := missingCapturedURLs([]string{"https://pub.test/p/one", "https://pub.test/p/two"}, []CapturedPage{{URL: "https://pub.test/p/one"}})
	if len(missing) != 1 || !strings.HasSuffix(missing[0], "/p/two") {
		t.Fatalf("missing = %#v", missing)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }
