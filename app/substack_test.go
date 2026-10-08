package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubstackHomepageURL(t *testing.T) {
	tests := map[string]string{
		"https://Publication.Substack.com/p/post?x=1": "https://publication.substack.com/",
		"https://Journal.Example.org/p/post?x=1":      "https://journal.example.org/",
	}
	for rawURL, want := range tests {
		got, err := substackHomepageURL(rawURL)
		if err != nil {
			t.Fatalf("substackHomepageURL(%q): %v", rawURL, err)
		}
		if got != want {
			t.Fatalf("substackHomepageURL(%q) = %q, want %q", rawURL, got, want)
		}
	}
	if _, err := substackHomepageURL("https://substack.com/"); err == nil {
		t.Fatal("expected the central Substack host to fail")
	}
}

func TestDiscoverSubstackPostsSupportsCustomDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset>` +
			`<url><loc>https://journal.example.org/p/one</loc></url>` +
			`<url><loc>https://journal.example.org/p/two</loc></url>` +
			`<url><loc>https://publication.substack.com/p/not-this-publication</loc></url>` +
			`</urlset>`))
	}))
	defer server.Close()

	client := &http.Client{Transport: substackTestTransport(server.URL)}
	posts, err := discoverSubstackPosts(context.Background(), client, "https://journal.example.org/p/seed")
	if err != nil {
		t.Fatal(err)
	}
	if len(posts) != 2 || posts[0] != "https://journal.example.org/p/one" || posts[1] != "https://journal.example.org/p/two" {
		t.Fatalf("posts = %#v", posts)
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

	client := &http.Client{Transport: substackTestTransport(server.URL)}
	posts, err := discoverSubstackPosts(context.Background(), client, "https://publication.substack.com/")
	if err != nil {
		t.Fatal(err)
	}
	if len(posts) != 2 || !strings.HasSuffix(posts[0], "/p/one") || !strings.HasSuffix(posts[1], "/p/two") {
		t.Fatalf("posts = %#v", posts)
	}
}

func TestDiscoverSubstackPublicationUsesRedirectedCustomDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Logical-Host") == "nonzionism.substack.com" {
			http.Redirect(w, r, "https://nonzionism.com/sitemap.xml", http.StatusMovedPermanently)
			return
		}
		_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset>` +
			`<url><loc>https://nonzionism.com/p/one</loc></url>` +
			`<url><loc>https://nonzionism.com/p/two</loc></url>` +
			`</urlset>`))
	}))
	defer server.Close()

	homepage, posts, err := discoverSubstackPublication(
		context.Background(),
		&http.Client{Transport: substackTestTransport(server.URL)},
		"https://nonzionism.substack.com/p/seed",
	)
	if err != nil {
		t.Fatal(err)
	}
	if homepage != "https://nonzionism.com/" {
		t.Fatalf("homepage = %q, want redirected custom domain", homepage)
	}
	if len(posts) != 2 || posts[0] != "https://nonzionism.com/p/one" || posts[1] != "https://nonzionism.com/p/two" {
		t.Fatalf("posts = %#v", posts)
	}
}

func TestMissingCapturedURLs(t *testing.T) {
	missing := missingCapturedURLs([]string{"https://pub.test/p/one", "https://pub.test/p/two"}, []CapturedPage{{URL: "https://pub.test/p/one"}})
	if len(missing) != 1 || !strings.HasSuffix(missing[0], "/p/two") {
		t.Fatalf("missing = %#v", missing)
	}
}

func TestNewSubstackPostURLsDiffsIndexedPosts(t *testing.T) {
	discovered := []string{
		"https://publication.substack.com/p/three",
		"https://publication.substack.com/p/one?utm_source=sitemap",
		"https://publication.substack.com/p/two",
		"https://publication.substack.com/p/three",
	}
	items := []ItemRecord{
		{URL: "https://publication.substack.com/p/one"},
		{URL: "https://publication.substack.com/p/two"},
	}
	missing := newSubstackPostURLs(discovered, items)
	if len(missing) != 1 || missing[0] != "https://publication.substack.com/p/three" {
		t.Fatalf("missing = %#v", missing)
	}
	if !allSubstackPostURLs(missing) {
		t.Fatal("expected incremental post list to be recognized as Substack posts")
	}
	if allSubstackPostURLs(nil) || allSubstackPostURLs([]string{"https://publication.substack.com/archive"}) {
		t.Fatal("non-post or empty lists must not activate Substack incremental mode")
	}
}

func TestClassifyFailedSubstackImagesSeparatesBrokenSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/empty":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", "0")
		case "/missing":
			http.NotFound(w, r)
		default:
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", "42")
		}
	}))
	defer server.Close()

	broken, unresolved := classifyFailedSubstackImages(context.Background(), 4, []string{
		server.URL + "/empty",
		server.URL + "/missing",
		server.URL + "/reachable",
	})
	if broken != 2 || unresolved != 2 {
		t.Fatalf("broken/unresolved = %d/%d, want 2/2", broken, unresolved)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func substackTestTransport(serverURL string) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		logicalURL := *req.URL
		networkReq := req.Clone(req.Context())
		networkURL := logicalURL
		networkURL.Scheme = "http"
		networkURL.Host = strings.TrimPrefix(serverURL, "http://")
		networkReq.URL = &networkURL
		networkReq.Header.Set("X-Test-Logical-Host", logicalURL.Hostname())
		resp, err := http.DefaultTransport.RoundTrip(networkReq)
		if resp != nil {
			logicalReq := req.Clone(req.Context())
			logicalReq.URL = &logicalURL
			resp.Request = logicalReq
		}
		return resp, err
	})
}
