package main

import (
	"database/sql"
	"testing"
)

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

func TestBrowserCookiesFromJSONPreservesFullExport(t *testing.T) {
	cookies, err := browserCookiesFromJSON(`[{"name":"sid","value":"abc","domain":".substack.com","path":"/","secure":true,"httpOnly":true,"sameSite":"no_restriction"},{"name":"bad","value":"no","domain":"other.com"}]`, "https://eventsinukraine.substack.com/p/post")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 2 {
		t.Fatalf("expected full valid cookie export, got %d", len(cookies))
	}
	got := cookies[0]
	if got.Name != "sid" || got.Domain != ".substack.com" || got.Path != "/" || !got.Secure || !got.HTTPOnly || got.SameSite != "None" {
		t.Fatalf("unexpected browser cookie: %+v", got)
	}
	if cookies[1].Name != "bad" || cookies[1].Domain != "other.com" {
		t.Fatalf("cross-domain cookie should be preserved for browser profile import: %+v", cookies[1])
	}
}

func TestBrowserCookiesFromJSONPreservesProviderCookiesForCustomDomains(t *testing.T) {
	cookies, err := browserCookiesFromJSON(`[{"name":"substack.sid","value":"abc","domain":".substack.com","path":"/","secure":true},{"name":"publication.sid","value":"def","domain":"marsreview.org","path":"/","secure":true}]`, "https://marsreview.org/p/post")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 2 {
		t.Fatalf("expected provider and custom-domain cookies, got %d", len(cookies))
	}
	if cookies[0].Domain != ".substack.com" || cookies[1].Domain != "marsreview.org" {
		t.Fatalf("unexpected imported domains: %+v", cookies)
	}
}

func TestBrowserCookiesForProfileDoesNotRejectProviderHostLabel(t *testing.T) {
	profile := &CookieProfileRecord{
		Name:       "substack",
		SourceType: "json",
		Host:       sql.NullString{String: "substack.com", Valid: true},
		Secret:     sql.NullString{String: `[{"name":"substack.sid","value":"abc","domain":".substack.com","path":"/","secure":true}]`, Valid: true},
	}
	cookies, err := browserCookiesForProfile(profile, "https://marsreview.org/p/post")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 || cookies[0].Domain != ".substack.com" {
		t.Fatalf("expected provider cookie to be imported for custom domain target: %+v", cookies)
	}
}

func TestBrowserCookiesFromNetscapePreservesFullExport(t *testing.T) {
	content := ".substack.com\tTRUE\t/\tTRUE\t1893456000\tsubstack.sid\tabc\nmarsreview.org\tFALSE\t/\tTRUE\t1893456000\tpublication.sid\tdef"
	cookies := browserCookiesFromNetscape(content, "https://marsreview.org/p/post")
	if len(cookies) != 2 {
		t.Fatalf("expected full valid Netscape export, got %d", len(cookies))
	}
	if cookies[0].Domain != ".substack.com" {
		t.Fatalf("subdomain cookie should use domain import: %+v", cookies[0])
	}
	if cookies[1].URL != "https://marsreview.org/" {
		t.Fatalf("host-only cookie should use URL import: %+v", cookies[1])
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
