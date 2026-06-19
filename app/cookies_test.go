package main

import "testing"

func TestNetscapeCookieHeader(t *testing.T) {
	content := ".example.com\tTRUE\t/\tFALSE\t0\tsid\tabc\nother.com\tFALSE\t/\tFALSE\t0\tbad\tno"
	got := netscapeCookieHeader(content, "www.example.com")
	if got != "sid=abc" {
		t.Fatalf("got %q, want sid=abc", got)
	}
}

func TestJSONCookieHeader(t *testing.T) {
	got, err := jsonCookieHeader(`[{"name":"sid","value":"abc","domain":".example.com"},{"name":"bad","value":"no","domain":"other.com"}]`, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sid=abc" {
		t.Fatalf("got %q, want sid=abc", got)
	}
}

func TestBrowserCookiesFromJSON(t *testing.T) {
	cookies, err := browserCookiesFromJSON(`[{"name":"sid","value":"abc","domain":".substack.com","path":"/","secure":true,"httpOnly":true,"sameSite":"no_restriction"},{"name":"bad","value":"no","domain":"other.com"}]`, "https://eventsinukraine.substack.com/p/post")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatalf("expected 1 relevant cookie, got %d", len(cookies))
	}
	got := cookies[0]
	if got.Name != "sid" || got.Domain != ".substack.com" || got.Path != "/" || !got.Secure || !got.HTTPOnly || got.SameSite != "None" {
		t.Fatalf("unexpected browser cookie: %+v", got)
	}
}

func TestBrowserCookiesFromRawHeader(t *testing.T) {
	cookies := browserCookiesFromRawHeader("sid=abc; theme=dark", "https://example.com/path")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "sid" || cookies[0].URL != "https://example.com/path" {
		t.Fatalf("unexpected raw browser cookie: %+v", cookies[0])
	}
}

func TestDomainMatches(t *testing.T) {
	if !domainMatches("www.example.com", ".example.com") {
		t.Fatal("expected subdomain match")
	}
	if domainMatches("badexample.com", "example.com") {
		t.Fatal("expected suffix without dot to be rejected")
	}
}
