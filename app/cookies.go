package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type browserCookieData struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	URL      string   `json:"url,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Secure   bool     `json:"secure,omitempty"`
	HTTPOnly bool     `json:"httpOnly,omitempty"`
	SameSite string   `json:"sameSite,omitempty"`
	Expires  *float64 `json:"expires,omitempty"`
}

func cookieHeaderForProfile(profile *CookieProfileRecord, targetURL string) (string, error) {
	if profile == nil || !profile.Secret.Valid {
		return "", nil
	}
	host := hostFromURL(targetURL)
	if profile.Host.Valid && profile.Host.String != "" && !domainMatches(host, profile.Host.String) {
		return "", fmt.Errorf("cookie profile host %q does not match target host %q", profile.Host.String, host)
	}

	switch profile.SourceType {
	case "raw_header":
		return strings.TrimSpace(profile.Secret.String), nil
	case "netscape":
		return netscapeCookieHeader(profile.Secret.String, host), nil
	case "json":
		return jsonCookieHeader(profile.Secret.String, host)
	default:
		return "", fmt.Errorf("unsupported cookie profile source type %q", profile.SourceType)
	}
}

func browserCookiesForProfile(profile *CookieProfileRecord, targetURL string) ([]browserCookieData, error) {
	if profile == nil || !profile.Secret.Valid {
		return nil, nil
	}

	switch profile.SourceType {
	case "raw_header":
		return browserCookiesFromRawHeader(profile.Secret.String, targetURL), nil
	case "netscape":
		return browserCookiesFromNetscape(profile.Secret.String, targetURL), nil
	case "json":
		return browserCookiesFromJSON(profile.Secret.String, targetURL)
	default:
		return nil, fmt.Errorf("unsupported cookie profile source type %q", profile.SourceType)
	}
}

func browserCookiesFromRawHeader(header, targetURL string) []browserCookieData {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Cookie", strings.TrimSpace(header))
	var out []browserCookieData
	for _, c := range req.Cookies() {
		if c.Name == "" {
			continue
		}
		out = append(out, browserCookieData{
			Name:  c.Name,
			Value: c.Value,
			URL:   targetURL,
			Path:  "/",
		})
	}
	return out
}

func browserCookiesFromNetscape(content, _ string) []browserCookieData {
	var out []browserCookieData
	for _, c := range parseNetscapeCookies(content) {
		domain := strings.TrimSpace(c.Domain)
		if c.Name == "" || domain == "" || cookieExpired(c.Expires) {
			continue
		}
		cookie := browserCookieData{
			Name:     c.Name,
			Value:    c.Value,
			Path:     firstNonEmpty(c.Path, "/"),
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		}
		if c.IncludeSubdomains {
			cookie.Domain = domain
		} else {
			cookie.URL = cookieURLForDomain(cookieScheme(cookie.Secure, ""), strings.TrimPrefix(domain, "."), cookie.Path)
		}
		if c.Expires != nil {
			expires := float64(c.Expires.Unix())
			cookie.Expires = &expires
		}
		out = append(out, cookie)
	}
	return out
}

func browserCookiesFromJSON(content, _ string) ([]browserCookieData, error) {
	cookies, err := parseJSONCookies(content)
	if err != nil {
		return nil, err
	}
	var out []browserCookieData
	for _, c := range cookies {
		domain := strings.TrimSpace(firstNonEmpty(c.Domain, c.Host))
		sourceURL := strings.TrimSpace(c.URL)
		urlHost := hostFromURL(sourceURL)
		hostOnly := c.HostOnly
		if domain == "" {
			domain = urlHost
			hostOnly = true
		}
		if c.Name == "" || domain == "" {
			continue
		}
		expiresAt := cookieExpiry(c)
		if cookieExpired(expiresAt) {
			continue
		}

		path := firstNonEmpty(c.Path, "/")
		cookie := browserCookieData{
			Name:     c.Name,
			Value:    c.Value,
			Path:     path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly || c.HTTPOnlyAlt,
			SameSite: browserCookieSameSite(c.SameSite),
		}
		if expiresAt != nil {
			expires := float64(expiresAt.Unix())
			cookie.Expires = &expires
		}
		if cookie.SameSite == "None" {
			cookie.Secure = true
		}
		if hostOnly {
			cookie.URL = firstNonEmpty(sourceURL, cookieURLForDomain(cookieScheme(cookie.Secure, sourceURL), strings.TrimPrefix(domain, "."), path))
		} else {
			cookie.Domain = domain
		}
		out = append(out, cookie)
	}
	return out, nil
}

func cookieExpired(expires *time.Time) bool {
	return expires != nil && !expires.After(time.Now())
}

func browserCookieSameSite(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return "Strict"
	case "lax":
		return "Lax"
	case "none", "no_restriction", "no restriction":
		return "None"
	default:
		return ""
	}
}

func cookieScheme(secure bool, sourceURL string) string {
	if parsed, err := url.Parse(sourceURL); err == nil && parsed.Scheme != "" {
		return parsed.Scheme
	}
	if secure {
		return "https"
	}
	return "https"
}

func netscapeCookieHeader(content, host string) string {
	var pairs []string
	for _, c := range parseNetscapeCookies(content) {
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if c.Name == "" || !domainMatches(host, domain) {
			continue
		}
		pairs = append(pairs, (&http.Cookie{Name: c.Name, Value: c.Value}).String())
	}
	return strings.Join(pairs, "; ")
}

type netscapeCookie struct {
	Domain            string
	IncludeSubdomains bool
	Path              string
	Secure            bool
	Expires           *time.Time
	Name              string
	Value             string
	HTTPOnly          bool
}

func parseNetscapeCookies(content string) []netscapeCookie {
	var out []netscapeCookie
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			httpOnly = true
			line = strings.TrimPrefix(line, "#HttpOnly_")
		} else if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			parts = strings.Fields(line)
		}
		if len(parts) < 7 {
			continue
		}
		var expires *time.Time
		if unix, err := strconv.ParseInt(parts[4], 10, 64); err == nil && unix > 0 {
			t := time.Unix(unix, 0)
			expires = &t
		}
		out = append(out, netscapeCookie{
			Domain:            parts[0],
			IncludeSubdomains: strings.EqualFold(parts[1], "TRUE"),
			Path:              parts[2],
			Secure:            strings.EqualFold(parts[3], "TRUE"),
			Expires:           expires,
			Name:              parts[5],
			Value:             parts[6],
			HTTPOnly:          httpOnly,
		})
	}
	return out
}

func jsonCookieHeader(content, host string) (string, error) {
	cookies, err := parseJSONCookies(content)
	if err != nil {
		return "", err
	}
	var pairs []string
	for _, c := range cookies {
		domain := strings.TrimPrefix(strings.ToLower(firstNonEmpty(c.Domain, c.Host)), ".")
		if c.Name == "" || !domainMatches(host, domain) {
			continue
		}
		pairs = append(pairs, (&http.Cookie{Name: c.Name, Value: c.Value}).String())
	}
	return strings.Join(pairs, "; "), nil
}

type exportedCookie struct {
	Name           string          `json:"name"`
	Value          string          `json:"value"`
	Domain         string          `json:"domain"`
	Host           string          `json:"host"`
	URL            string          `json:"url"`
	Path           string          `json:"path"`
	Secure         bool            `json:"secure"`
	HTTPOnly       bool            `json:"httpOnly"`
	HTTPOnlyAlt    bool            `json:"httponly"`
	HostOnly       bool            `json:"hostOnly"`
	Session        bool            `json:"session"`
	SameSite       string          `json:"sameSite"`
	ExpirationDate json.RawMessage `json:"expirationDate"`
	Expires        json.RawMessage `json:"expires"`
	Expiry         json.RawMessage `json:"expiry"`
}

func parseJSONCookies(content string) ([]exportedCookie, error) {
	trimmed := bytes.TrimSpace([]byte(content))
	if len(trimmed) == 0 {
		return nil, nil
	}
	var cookies []exportedCookie
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &cookies); err != nil {
			return nil, err
		}
		return cookies, nil
	}
	var wrapper struct {
		Cookies []exportedCookie `json:"cookies"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Cookies, nil
}

func cookieExpiry(c exportedCookie) *time.Time {
	for _, raw := range []json.RawMessage{c.ExpirationDate, c.Expires, c.Expiry} {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		if t := parseCookieExpiry(raw); t != nil {
			return t
		}
	}
	return nil
}

func parseCookieExpiry(raw json.RawMessage) *time.Time {
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		if number <= 0 {
			return nil
		}
		t := time.Unix(int64(number), int64((number-float64(int64(number)))*1e9))
		return &t
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil || strings.TrimSpace(text) == "" {
		return nil
	}
	if number, err := strconv.ParseFloat(text, 64); err == nil && number > 0 {
		t := time.Unix(int64(number), int64((number-float64(int64(number)))*1e9))
		return &t
	}
	for _, layout := range []string{time.RFC3339, http.TimeFormat, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, text); err == nil {
			return &t
		}
	}
	return nil
}

func cookieURLForDomain(scheme, domain, path string) string {
	if scheme == "" {
		scheme = "https"
	}
	if path == "" || !strings.HasPrefix(path, "/") {
		path = "/"
	}
	return (&url.URL{Scheme: scheme, Host: domain, Path: path}).String()
}

func domainMatches(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func validateCookieProfileInput(sourceType string, host *string, cookieHeader *string, content *string) error {
	switch sourceType {
	case "raw_header":
		if cookieHeader == nil || strings.TrimSpace(*cookieHeader) == "" {
			return fmt.Errorf("raw_header profiles require cookieHeader")
		}
	case "netscape", "json":
		if content == nil || strings.TrimSpace(*content) == "" {
			return fmt.Errorf("%s profiles require content", sourceType)
		}
		if sourceType == "json" {
			if _, err := parseJSONCookies(*content); err != nil {
				return fmt.Errorf("invalid JSON cookie export: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported sourceType %q", sourceType)
	}
	if host != nil && strings.TrimSpace(*host) != "" {
		if _, err := url.Parse("https://" + strings.TrimSpace(*host)); err != nil {
			return fmt.Errorf("invalid host")
		}
	}
	return nil
}
