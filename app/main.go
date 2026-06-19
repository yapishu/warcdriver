package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var RootContentDir string

func init() {
	RootContentDir = getenv("DATA_DIR", "/data")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := OpenStore(ctx, RootContentDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := bootstrapAdmin(ctx, store); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}

	app := NewApp(ctx, store, RootContentDir)
	workers := getenvInt("ARCHIVE_WORKERS", 1)
	app.StartWorkers(ctx, workers)

	addr := getenv("ADDR", ":8808")
	srv := &http.Server{
		Addr:              addr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("warcdriver listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func effectiveCaptureUserAgent(ctx context.Context, configured string) string {
	_ = ctx
	if ua := strings.TrimSpace(configured); ua != "" {
		return normalizeCaptureUserAgent(ua)
	}
	if ua := strings.TrimSpace(getenv("CAPTURE_USER_AGENT", "")); ua != "" {
		return normalizeCaptureUserAgent(ua)
	}
	return ""
}

func normalizeCaptureUserAgent(ua string) string {
	ua = strings.ReplaceAll(ua, "HeadlessChrome", "Chrome")
	ua = strings.ReplaceAll(ua, "Headless Chromium", "Chromium")
	return strings.TrimSpace(ua)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}
