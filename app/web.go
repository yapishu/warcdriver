package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed frontend/dist/*
var embeddedFrontend embed.FS

var webAssets fs.FS

func init() {
	sub, err := fs.Sub(embeddedFrontend, "frontend/dist")
	if err != nil {
		panic(err)
	}
	webAssets = sub
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "index.html")
	if err != nil {
		http.Error(w, "index unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func serveReplayWorker(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "replay/sw.js")
	if err != nil {
		http.Error(w, "replay worker unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Service-Worker-Allowed", "/api/warcs/")
	_, _ = w.Write(b)
}

func serveReplayUI(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "replay/ui.js")
	if err != nil {
		http.Error(w, "replay UI unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(b)
}

func serveAppWorker(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "app-sw.js")
	if err != nil {
		http.Error(w, "app worker unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Service-Worker-Allowed", "/")
	_, _ = w.Write(b)
}

func serveManifest(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "manifest.webmanifest")
	if err != nil {
		http.Error(w, "manifest unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	_, _ = w.Write(b)
}
