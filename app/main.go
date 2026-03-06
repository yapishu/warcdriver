package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

var RootContentDir string

func init() {
	RootContentDir = getenv("DATA_DIR", "/data")
}

func main() {
	http.HandleFunc("/archive", handleArchive)
	http.HandleFunc("/crawl", handleCrawl)
	addr := ":8808"
	log.Printf("warcdriver listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

type archiveRequest struct {
	URLs []string `json:"urls"`
}

type archiveResponse struct {
	Path string `json:"path"`
}

type crawlRequest struct {
	URL      string `json:"url"`
	MaxPages int    `json:"maxPages,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

type crawlResponse struct {
	Path        string   `json:"path"`
	UrlsCrawled []string `json:"urlsCrawled"`
}

func handleArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, _ := io.ReadAll(r.Body)
	log.Printf("archive request: %s", string(raw))

	var req archiveRequest
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&req); err != nil || len(req.URLs) == 0 {
		http.Error(w, "bad request: provide {\"urls\": [...]}", http.StatusBadRequest)
		return
	}

	firstURL, _ := url.Parse(req.URLs[0])
	domain := getDomainFromURL(firstURL)
	filename := fmt.Sprintf("%s-%d.warc.gz", domain, time.Now().Unix())

	path, err := archiveURLs(req.URLs, filename)
	if err != nil {
		log.Printf("archive error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("archived %d URLs to %s", len(req.URLs), path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(archiveResponse{Path: filename})
}

func handleCrawl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, _ := io.ReadAll(r.Body)
	log.Printf("crawl request: %s", string(raw))

	var req crawlRequest
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "bad request: provide {\"url\": \"...\"}", http.StatusBadRequest)
		return
	}

	maxPages := 100
	if req.MaxPages > 0 {
		maxPages = req.MaxPages
	}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}
	domain := getDomainFromURL(parsedURL)
	filename := fmt.Sprintf("%s-%d.warc.gz", domain, time.Now().Unix())

	path, urlsCrawled, err := crawlAndArchive(req.URL, filename, maxPages, req.Prefix)
	if err != nil {
		log.Printf("crawl error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("crawled %d pages to %s", len(urlsCrawled), path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(crawlResponse{Path: filename, UrlsCrawled: urlsCrawled})
}

func getDomainFromURL(parsedURL *url.URL) string {
	host := parsedURL.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// Handle country-code TLDs (e.g., example.co.uk)
	if len(parts[len(parts)-1]) == 2 && len(parts[len(parts)-2]) <= 3 {
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], "-")
		}
		return strings.Join(parts, "-")
	}
	return strings.Join(parts[len(parts)-2:], "-")
}

func remoteAllocator(ctx context.Context) (context.Context, context.CancelFunc, error) {
	host := getenv("CHROME_HOST", "chrome")
	port := getenv("CHROME_PORT", "9222")

	ip := host
	if host != "127.0.0.1" && host != "localhost" {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup %s: %w", host, err)
		}
		ip = addrs[0]
	}

	versionURL := fmt.Sprintf("http://%s:%s/json/version", ip, port)
	resp, err := http.Get(versionURL)
	if err != nil {
		return nil, nil, fmt.Errorf("chrome not reachable at %s: %w", versionURL, err)
	}
	defer resp.Body.Close()

	var data struct {
		WebSocketDebuggerUrl string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, fmt.Errorf("chrome version endpoint: %w", err)
	}

	allocCtx, cancel := chromedp.NewRemoteAllocator(ctx, data.WebSocketDebuggerUrl, chromedp.NoModifyURL)
	return allocCtx, cancel, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
