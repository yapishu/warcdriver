package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

type URLFilter struct {
	mu     sync.RWMutex
	engine *urlfilter.NetworkEngine
	lists  []string
}

func NewURLFilter(ctx context.Context, dataDir string, listURLs []string) *URLFilter {
	f := &URLFilter{}
	if err := f.Reload(ctx, dataDir, listURLs); err != nil {
		log.Printf("filter engine disabled: %v", err)
	}
	return f
}

func (f *URLFilter) Reload(ctx context.Context, dataDir string, listURLs []string) error {
	if len(listURLs) == 0 {
		listURLs = defaultFilterLists()
	}
	cacheDir := filepath.Join(dataDir, "filters")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}

	var lists []filterlist.Interface
	for i, listURL := range listURLs {
		text, err := fetchFilterList(ctx, cacheDir, listURL)
		if err != nil {
			log.Printf("filter list %s unavailable: %v", listURL, err)
			continue
		}
		lists = append(lists, filterlist.NewString(&filterlist.StringConfig{
			RulesText:      text,
			ID:             rules.ListID(i + 1),
			IgnoreCosmetic: true,
		}))
	}
	if len(lists) == 0 {
		return fmt.Errorf("no filter lists loaded")
	}

	storage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return err
	}
	engine := urlfilter.NewNetworkEngine(storage)

	f.mu.Lock()
	f.engine = engine
	f.lists = append([]string(nil), listURLs...)
	f.mu.Unlock()

	log.Printf("loaded URL filter engine with %d network rules from %d lists", engine.RulesCount(), len(lists))
	return nil
}

func (f *URLFilter) Lists() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]string(nil), f.lists...)
}

func (f *URLFilter) ShouldBlock(requestURL, sourceURL string, resourceType string) (bool, string) {
	f.mu.RLock()
	engine := f.engine
	f.mu.RUnlock()
	if engine == nil {
		return false, ""
	}
	req := rules.NewRequest(requestURL, sourceURL, requestType(resourceType))
	rule, ok := engine.Match(req)
	if !ok || rule == nil || rule.Whitelist {
		return false, ""
	}
	return true, rule.Text()
}

func defaultFilterLists() []string {
	return []string{
		"https://easylist.to/easylist/easylist.txt",
		"https://easylist.to/easylist/easyprivacy.txt",
	}
}

func fetchFilterList(ctx context.Context, cacheDir, rawURL string) (string, error) {
	cachePath := filepath.Join(cacheDir, filterCacheName(rawURL))
	if stat, err := os.Stat(cachePath); err == nil && time.Since(stat.ModTime()) < 24*time.Hour {
		b, err := os.ReadFile(cachePath)
		return string(b), err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return cachedOrError(cachePath, err)
	}
	req.Header.Set("User-Agent", "warcdriver/0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cachedOrError(cachePath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return cachedOrError(cachePath, fmt.Errorf("status %s", resp.Status))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return cachedOrError(cachePath, err)
	}
	if err := os.WriteFile(cachePath, body, 0o644); err != nil {
		return "", err
	}
	return string(body), nil
}

func cachedOrError(cachePath string, cause error) (string, error) {
	b, err := os.ReadFile(cachePath)
	if err == nil {
		return string(b), nil
	}
	return "", cause
}

func filterCacheName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "list.txt"
	}
	name := strings.Trim(u.Hostname()+u.EscapedPath(), "/")
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(name)
	if name == "" {
		return "list.txt"
	}
	return name
}

func requestType(t string) rules.RequestType {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "document":
		return rules.TypeDocument
	case "stylesheet", "css":
		return rules.TypeStylesheet
	case "script", "js":
		return rules.TypeScript
	case "image", "img":
		return rules.TypeImage
	case "font":
		return rules.TypeFont
	case "media", "audio", "video":
		return rules.TypeMedia
	case "websocket", "web_socket":
		return rules.TypeWebsocket
	case "xhr", "fetch", "xmlhttprequest":
		return rules.TypeXmlhttprequest
	case "ping":
		return rules.TypePing
	default:
		return rules.TypeOther
	}
}
