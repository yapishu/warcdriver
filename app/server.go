package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"warcdrive/internal/api"
)

type App struct {
	store            *Store
	filter           *URLFilter
	dataDir          string
	cookieSecureMode string
	activeMu         sync.Mutex
	activeJobs       map[string]context.CancelFunc
}

func NewApp(ctx context.Context, store *Store, dataDir string) *App {
	filterLists := defaultFilterLists()
	if raw, err := store.GetSetting(ctx, "filter_lists"); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &filterLists)
	}
	return &App{
		store:            store,
		filter:           NewURLFilter(ctx, dataDir, filterLists),
		dataDir:          dataDir,
		cookieSecureMode: strings.ToLower(strings.TrimSpace(getenv("COOKIE_SECURE", "auto"))),
		activeJobs:       map[string]context.CancelFunc{},
	}
}

func (a *App) Routes() http.Handler {
	root := chi.NewRouter()
	root.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.Get("/api/warcs/sw.js", serveReplayWorker)
	root.Get("/app-sw.js", serveAppWorker)
	root.Head("/app-sw.js", serveAppWorker)
	root.Get("/manifest.webmanifest", serveManifest)
	root.Head("/manifest.webmanifest", serveManifest)
	root.Handle("/assets/*", http.FileServer(http.FS(webAssets)))
	root.Handle("/icons/*", http.FileServer(http.FS(webAssets)))
	root.Handle("/replay/*", http.FileServer(http.FS(webAssets)))
	root.Get("/", serveIndex)
	root.Head("/", serveIndex)
	root.Get("/app", serveIndex)
	root.Head("/app", serveIndex)
	root.Get("/app/*", serveIndex)
	root.Head("/app/*", serveIndex)
	root.Get("/viewer/{captureId}", serveIndex)
	root.Head("/viewer/{captureId}", serveIndex)

	apiRouter := chi.NewRouter()
	apiRouter.Use(a.authMiddleware)
	api.HandlerFromMux(a, apiRouter)
	root.Mount("/", apiRouter)

	root.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		serveIndex(w, r)
	})
	return root
}

func (a *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			next.ServeHTTP(w, r)
			return
		}

		user, err := a.authenticate(r)
		if err != nil && publicWarcReadPath(r.URL.Path) {
			id, ok := warcIDFromReadPath(r.URL.Path)
			if ok {
				capture, captureErr := a.store.GetCapture(r.Context(), id)
				if captureErr == nil && capture.Visibility == VisibilityPublic {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

func publicWarcReadPath(path string) bool {
	if !strings.HasPrefix(path, "/api/warcs/") {
		return false
	}
	return strings.HasSuffix(path, "/download") || strings.HasSuffix(path, "/metadata")
}

func warcIDFromReadPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/api/warcs/")
	id, suffix, ok := strings.Cut(path, "/")
	if !ok || id == "" {
		return "", false
	}
	return id, suffix == "download" || suffix == "metadata"
}

func (a *App) authenticate(r *http.Request) (*UserRecord, error) {
	ctx := r.Context()
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[len("bearer "):])
		if token != "" {
			return a.store.GetAPITokenUser(ctx, hashToken(token))
		}
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		session, err := a.store.GetSession(ctx, hashToken(c.Value))
		if err != nil {
			return nil, err
		}
		if time.Now().UTC().After(session.ExpiresAt) {
			_ = a.store.DeleteSession(ctx, session.TokenHash)
			return nil, sql.ErrNoRows
		}
		return a.store.GetUserByID(ctx, session.UserID)
	}
	return nil, sql.ErrNoRows
}

func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	var req api.LoginJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	user, err := a.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || !verifyPassword(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	if err := a.store.CreateSession(r.Context(), user.ID, hashToken(token), expires); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save session")
		return
	}
	http.SetCookie(w, sessionCookie(token, expires, a.secureCookieForRequest(r)))
	writeJSON(w, http.StatusOK, api.MeResponse{User: apiUser(user)})
}

func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		_ = a.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, expiredSessionCookie(a.secureCookieForRequest(r)))
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) secureCookieForRequest(r *http.Request) bool {
	switch a.cookieSecureMode {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return requestIsHTTPS(r)
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := firstForwardedProto(r.Header.Get("X-Forwarded-Proto")); proto == "https" {
		return true
	}
	for _, part := range strings.Split(r.Header.Get("Forwarded"), ";") {
		part = strings.TrimSpace(part)
		key, value, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "proto") {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(value), `"`), "https")
		}
	}
	return false
}

func firstForwardedProto(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if before, _, ok := strings.Cut(value, ","); ok {
		value = before
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func (a *App) GetMe(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	writeJSON(w, http.StatusOK, api.MeResponse{User: apiUser(user)})
}

func (a *App) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	users, err := a.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.User, 0, len(users))
	for i := range users {
		out = append(out, apiUser(&users[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (a *App) CreateUser(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	var req api.CreateUserJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	password := strings.TrimSpace(req.Password)
	if len(password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	isAdmin := false
	if req.IsAdmin != nil {
		isAdmin = *req.IsAdmin
	}
	user, err := a.store.CreateUser(r.Context(), UserCreate{
		Username:     req.Username,
		Email:        plainString(req.Email),
		DisplayName:  plainString(req.DisplayName),
		PasswordHash: hash,
		IsAdmin:      isAdmin,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, apiUser(user))
}

func (a *App) UpdateUser(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !a.requireAdmin(w, r) {
		return
	}
	var req api.UpdateUserJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	update := UserUpdate{
		Username:    req.Username,
		Email:       req.Email,
		DisplayName: req.DisplayName,
		IsAdmin:     req.IsAdmin,
	}
	if req.Password != nil {
		password := strings.TrimSpace(*req.Password)
		if len(password) < 8 {
			writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hash, err := hashPassword(password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		update.PasswordHash = &hash
	}
	if req.IsAdmin != nil && !*req.IsAdmin {
		current, _ := userFromContext(r.Context())
		if current != nil && current.ID == id {
			writeError(w, http.StatusBadRequest, "cannot remove admin from the current user")
			return
		}
	}
	user, err := a.store.UpdateUser(r.Context(), id, update)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, apiUser(user))
}

func (a *App) DeleteUser(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !a.requireAdmin(w, r) {
		return
	}
	current, _ := userFromContext(r.Context())
	if current != nil && current.ID == id {
		writeError(w, http.StatusBadRequest, "cannot delete the current user")
		return
	}
	err := a.store.DeleteUser(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	user, ok := userFromContext(r.Context())
	if !ok || user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	if !user.IsAdmin {
		writeError(w, http.StatusForbidden, "admin required")
		return false
	}
	return true
}

func (a *App) canManageJob(w http.ResponseWriter, r *http.Request, id string) bool {
	user, _ := userFromContext(r.Context())
	job, err := a.store.GetArchiveJob(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "job not found")
		return false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if user == nil || (!user.IsAdmin && (!job.UserID.Valid || job.UserID.String != user.ID)) {
		writeError(w, http.StatusForbidden, "job owner or admin required")
		return false
	}
	return true
}

func userCanManageCapture(user *UserRecord, capture *CaptureRecord) bool {
	if user == nil || capture == nil {
		return false
	}
	return user.IsAdmin || (capture.OwnerUserID.Valid && capture.OwnerUserID.String == user.ID)
}

func (a *App) CreateArchiveJob(w http.ResponseWriter, r *http.Request) {
	var req api.CreateArchiveJobJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	jobCreate, err := normalizeArchiveJobRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, _ := userFromContext(r.Context())
	userID := ""
	if user != nil {
		userID = user.ID
	}
	job, err := a.store.CreateArchiveJob(r.Context(), userID, jobCreate)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.store.AddJobLog(r.Context(), job.ID, "info", "job queued")
	writeJSON(w, http.StatusAccepted, apiArchiveJob(job))
}

func (a *App) ListArchiveJobs(w http.ResponseWriter, r *http.Request, params api.ListArchiveJobsParams) {
	limit := boundedLimit(params.Limit, 50, 200)
	user, _ := userFromContext(r.Context())
	jobs, err := a.store.ListArchiveJobsVisible(r.Context(), user, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.ArchiveJob, 0, len(jobs))
	for i := range jobs {
		out = append(out, apiArchiveJob(&jobs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (a *App) GetArchiveJob(w http.ResponseWriter, r *http.Request, id api.Id) {
	user, _ := userFromContext(r.Context())
	job, err := a.store.GetArchiveJobVisible(r.Context(), id, user)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	logs, err := a.store.ListJobLogs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items, err := a.store.ListItemsForJobVisible(r.Context(), id, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	apiItems := make([]api.Item, 0, len(items))
	for i := range items {
		apiItems = append(apiItems, apiItem(&items[i]))
	}
	apiLogs := make([]api.JobLog, 0, len(logs))
	for i := range logs {
		apiLogs = append(apiLogs, api.JobLog{At: logs[i].At, Level: logs[i].Level, Message: logs[i].Message})
	}
	detail := apiArchiveJobDetail(job)
	detail.Logs = apiLogs
	detail.Items = &apiItems
	writeJSON(w, http.StatusOK, detail)
}

func (a *App) CancelArchiveJob(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !a.canManageJob(w, r, id) {
		return
	}
	a.cancelActiveJob(id)
	job, err := a.store.CancelJob(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.store.AddJobLog(r.Context(), id, "warn", "job canceled")
	writeJSON(w, http.StatusOK, apiArchiveJob(job))
}

func (a *App) DeleteArchiveJob(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !a.canManageJob(w, r, id) {
		return
	}
	a.cancelActiveJob(id)
	if err := a.store.DeleteArchiveJob(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) ListSites(w http.ResponseWriter, r *http.Request, params api.ListSitesParams) {
	user, _ := userFromContext(r.Context())
	sites, err := a.store.ListSitesVisible(r.Context(), user, boundedLimit(params.Limit, 100, 200))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.Site, 0, len(sites))
	for i := range sites {
		out = append(out, apiSite(&sites[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out})
}

func (a *App) GetSite(w http.ResponseWriter, r *http.Request, id api.Id) {
	user, _ := userFromContext(r.Context())
	site, err := a.store.GetSiteVisible(r.Context(), id, user)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items, err := a.store.ListItemsForSiteVisible(r.Context(), id, user, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.Item, 0, len(items))
	for i := range items {
		out = append(out, apiItem(&items[i]))
	}
	writeJSON(w, http.StatusOK, api.SiteDetail{Site: apiSite(site), Items: out})
}

func (a *App) DeleteSite(w http.ResponseWriter, r *http.Request, id api.Id) {
	if !a.requireAdmin(w, r) {
		return
	}
	err := a.store.DeleteSite(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) ListItems(w http.ResponseWriter, r *http.Request, params api.ListItemsParams) {
	siteID := ""
	if params.SiteId != nil {
		siteID = *params.SiteId
	}
	q := ""
	if params.Q != nil {
		q = *params.Q
	}
	user, _ := userFromContext(r.Context())
	items, err := a.store.ListItemsVisible(r.Context(), user, siteID, q, boundedLimit(params.Limit, 100, 200))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.Item, 0, len(items))
	for i := range items {
		out = append(out, apiItem(&items[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *App) GetItem(w http.ResponseWriter, r *http.Request, id api.Id) {
	user, _ := userFromContext(r.Context())
	item, err := a.store.GetItemVisible(r.Context(), id, user)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail := apiItemDetail(item)
	if item.MarkdownPath.Valid {
		if b, err := os.ReadFile(item.MarkdownPath.String); err == nil {
			md := string(b)
			detail.Markdown = &md
		}
	}
	warcURL := "/api/warcs/" + item.CaptureID + "/download"
	detail.WarcDownloadUrl = &warcURL
	if item.Replayable {
		replayURL := "/viewer/" + item.CaptureID + "?url=" + url.QueryEscape(item.URL)
		detail.ReplayUrl = &replayURL
	}
	writeJSON(w, http.StatusOK, detail)
}

func (a *App) RecaptureItem(w http.ResponseWriter, r *http.Request, id api.Id) {
	user, _ := userFromContext(r.Context())
	item, err := a.store.GetItemVisible(r.Context(), id, user)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	capture, err := a.store.GetCapture(r.Context(), item.CaptureID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !userCanManageCapture(user, capture) {
		writeError(w, http.StatusForbidden, "capture owner or admin required")
		return
	}

	req := ArchiveJobCreate{
		URL:           item.URL,
		Scope:         "single_page",
		Depth:         0,
		MaxPages:      1,
		Visibility:    capture.Visibility,
		Enrich:        true,
		ReplaceItemID: item.ID,
	}
	if original, err := a.store.GetArchiveJob(r.Context(), item.JobID); err == nil {
		req.Enrich = original.Enrich
		if original.CookieProfileID.Valid {
			req.CookieProfileID = original.CookieProfileID.String
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	userID := ""
	if user != nil {
		userID = user.ID
	}
	job, err := a.store.CreateArchiveJob(r.Context(), userID, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.store.AddJobLog(r.Context(), job.ID, "info", "replacement job queued")
	writeJSON(w, http.StatusAccepted, apiArchiveJob(job))
}

func (a *App) DeleteItem(w http.ResponseWriter, r *http.Request, id api.Id) {
	user, _ := userFromContext(r.Context())
	item, err := a.store.GetItemVisible(r.Context(), id, user)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	capture, err := a.store.GetCapture(r.Context(), item.CaptureID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !userCanManageCapture(user, capture) {
		writeError(w, http.StatusForbidden, "capture owner or admin required")
		return
	}
	err = a.store.DeleteItem(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) captureForRead(r *http.Request, id string) (*CaptureRecord, error) {
	user, ok := userFromContext(r.Context())
	if ok && user != nil {
		return a.store.GetCaptureVisible(r.Context(), id, user)
	}
	capture, err := a.store.GetCapture(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if capture.Visibility != VisibilityPublic {
		return nil, sql.ErrNoRows
	}
	return capture, nil
}

func (a *App) DownloadWarc(w http.ResponseWriter, r *http.Request, id api.Id) {
	capture, err := a.captureForRead(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", archiveFileContentType(capture.WARCPath))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(capture.WARCPath)))
	http.ServeFile(w, r, capture.WARCPath)
}

func (a *App) GetWarcMetadata(w http.ResponseWriter, r *http.Request, id api.Id) {
	capture, err := a.captureForRead(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.WarcMetadata{
		CaptureId:  capture.ID,
		StartUrl:   capture.StartURL,
		Title:      nullableString(capture.Title),
		Visibility: api.Visibility(capture.Visibility),
		CreatedAt:  capture.CreatedAt,
	})
}

func (a *App) UpdateWarcVisibility(w http.ResponseWriter, r *http.Request, id api.Id) {
	var req api.UpdateWarcVisibilityJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	user, _ := userFromContext(r.Context())
	capture, err := a.store.GetCapture(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !userCanManageCapture(user, capture) {
		writeError(w, http.StatusForbidden, "capture owner or admin required")
		return
	}
	capture, err = a.store.UpdateCaptureVisibility(r.Context(), id, string(req.Visibility))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.WarcMetadata{
		CaptureId:  capture.ID,
		StartUrl:   capture.StartURL,
		Title:      nullableString(capture.Title),
		Visibility: api.Visibility(capture.Visibility),
		CreatedAt:  capture.CreatedAt,
	})
}

func (a *App) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.currentSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *App) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req api.UpdateSettingsJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.OpenRouterApiKey != nil {
		if err := a.store.SetSetting(r.Context(), "openrouter_api_key", *req.OpenRouterApiKey); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.OpenRouterModel != nil {
		if err := a.store.SetSetting(r.Context(), "openrouter_model", *req.OpenRouterModel); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.EnrichmentEnabled != nil {
		if err := a.store.SetSetting(r.Context(), "enrichment_enabled", strconv.FormatBool(*req.EnrichmentEnabled)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.FilterLists != nil {
		raw, _ := json.Marshal(*req.FilterLists)
		if err := a.store.SetSetting(r.Context(), "filter_lists", string(raw)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := a.filter.Reload(r.Context(), a.dataDir, *req.FilterLists); err != nil {
			log.Printf("filter reload failed: %v", err)
		}
	}
	if req.UserAgent != nil {
		if err := a.store.SetSetting(r.Context(), "user_agent", *req.UserAgent); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.CaptureHeadless != nil {
		if err := a.store.SetSetting(r.Context(), "capture_headless", strconv.FormatBool(*req.CaptureHeadless)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.CapturePageDelay != nil {
		if err := a.store.SetSetting(r.Context(), "capture_page_delay", strconv.Itoa(clampInt(*req.CapturePageDelay, 1, 120))); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.CapturePageRetries != nil {
		if err := a.store.SetSetting(r.Context(), "capture_page_retries", strconv.Itoa(clampInt(*req.CapturePageRetries, 0, 5))); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.CaptureUseSitemap != nil {
		if err := a.store.SetSetting(r.Context(), "capture_use_sitemap", strconv.FormatBool(*req.CaptureUseSitemap)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	settings, err := a.currentSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *App) TestOpenRouter(w http.ResponseWriter, r *http.Request) {
	key, _ := a.openRouterAPIKey(r.Context())
	if key == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "OpenRouter API key is not configured"})
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://openrouter.ai/api/v1/models", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": resp.Status})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "OpenRouter reachable"})
}

func (a *App) ListCookieProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := a.store.ListCookieProfiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.CookieProfile, 0, len(profiles))
	for i := range profiles {
		out = append(out, apiCookieProfile(&profiles[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

func (a *App) CreateCookieProfile(w http.ResponseWriter, r *http.Request) {
	var req api.CreateCookieProfileJSONRequestBody
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	sourceType := string(req.SourceType)
	if err := validateCookieProfileInput(sourceType, req.Host, req.CookieHeader, req.Content); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var secret *string
	switch sourceType {
	case "raw_header":
		secret = req.CookieHeader
	case "netscape", "json":
		secret = req.Content
	}
	profile, err := a.store.CreateCookieProfile(r.Context(), req.Name, sourceType, req.Host, secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, apiCookieProfile(profile))
}

func (a *App) DeleteCookieProfile(w http.ResponseWriter, r *http.Request, id api.Id) {
	err := a.store.DeleteCookieProfile(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "cookie profile not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) currentSettings(ctx context.Context) (api.Settings, error) {
	model, err := a.store.GetSetting(ctx, "openrouter_model")
	if err != nil {
		return api.Settings{}, err
	}
	enrichmentRaw, err := a.store.GetSetting(ctx, "enrichment_enabled")
	if err != nil {
		return api.Settings{}, err
	}
	filterRaw, err := a.store.GetSetting(ctx, "filter_lists")
	if err != nil {
		return api.Settings{}, err
	}
	var lists []string
	if err := json.Unmarshal([]byte(filterRaw), &lists); err != nil || len(lists) == 0 {
		lists = defaultFilterLists()
	}
	enabled, _ := strconv.ParseBool(enrichmentRaw)
	userAgent, _ := a.store.GetSetting(ctx, "user_agent")
	if strings.TrimSpace(userAgent) == "" {
		userAgent = getenv("CAPTURE_USER_AGENT", "")
	}
	headlessRaw, _ := a.store.GetSetting(ctx, "capture_headless")
	captureHeadless, _ := strconv.ParseBool(firstNonEmpty(headlessRaw, getenv("CAPTURE_HEADLESS", "false")))
	capturePageDelay := a.captureSettingInt(ctx, "capture_page_delay", "CAPTURE_PAGE_DELAY", 3, 1, 120)
	capturePageRetries := a.captureSettingInt(ctx, "capture_page_retries", "CAPTURE_PAGE_RETRIES", 0, 0, 5)
	captureUseSitemap := a.captureSettingBool(ctx, "capture_use_sitemap", "CAPTURE_USE_SITEMAP", true)
	openRouterKey, _ := a.openRouterAPIKey(ctx)
	openRouterKeyConfigured := openRouterKey != ""
	settings := api.Settings{
		OpenRouterModel:            model,
		OpenRouterApiKeyConfigured: &openRouterKeyConfigured,
		EnrichmentEnabled:          enabled,
		FilterLists:                lists,
		UserAgent:                  nullablePlainString(userAgent),
		CaptureHeadless:            captureHeadless,
		CapturePageDelay:           capturePageDelay,
		CapturePageRetries:         capturePageRetries,
		CaptureUseSitemap:          captureUseSitemap,
	}
	return settings, nil
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func nullablePlainString(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

func plainString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func normalizeArchiveJobRequest(req api.CreateArchiveJobJSONRequestBody) (ArchiveJobCreate, error) {
	if strings.TrimSpace(req.Url) == "" {
		return ArchiveJobCreate{}, fmt.Errorf("url is required")
	}
	if _, err := mustHTTPURL(req.Url); err != nil {
		return ArchiveJobCreate{}, err
	}
	scopeProvided := req.Scope != nil
	scope := "single_page"
	if req.Scope != nil {
		scope = string(*req.Scope)
	}
	switch scope {
	case "single_page", "linked_pages", "same_subdomain", "prefix", "explicit_urls":
	default:
		return ArchiveJobCreate{}, fmt.Errorf("unsupported scope %q", scope)
	}
	depthProvided := req.Depth != nil
	depth := 0
	if scope == "linked_pages" {
		depth = 1
	} else if scope == "same_subdomain" || scope == "prefix" {
		depth = -1
	}
	if req.Depth != nil {
		depth = *req.Depth
	}
	if !scopeProvided && depthProvided && depth > 0 {
		scope = "linked_pages"
	}
	if scope == "single_page" || scope == "explicit_urls" {
		depth = 0
	} else if scope == "linked_pages" && depth < 1 {
		depth = 1
	} else if (scope == "same_subdomain" || scope == "prefix") && depth == 0 {
		depth = -1
	}
	maxPages := 100
	if scope == "same_subdomain" || scope == "prefix" {
		maxPages = 0
	}
	if req.MaxPages != nil {
		maxPages = *req.MaxPages
	}
	enrich := true
	if req.Enrich != nil {
		enrich = *req.Enrich
	}
	urls := []string{}
	if req.Urls != nil {
		for _, u := range *req.Urls {
			if _, err := mustHTTPURL(u); err != nil {
				return ArchiveJobCreate{}, fmt.Errorf("invalid urls entry %q: %w", u, err)
			}
			urls = append(urls, u)
		}
	}
	prefix := ""
	if req.Prefix != nil {
		prefix = *req.Prefix
	}
	pathExcludeRx := ""
	if req.PathExcludeRx != nil {
		pathExcludeRx = strings.TrimSpace(*req.PathExcludeRx)
		if _, err := regexp.Compile(pathExcludeRx); err != nil {
			return ArchiveJobCreate{}, fmt.Errorf("invalid pathExcludeRx: %w", err)
		}
	}
	cookieProfileID := ""
	if req.CookieProfileId != nil {
		cookieProfileID = *req.CookieProfileId
	}
	visibility := VisibilityPrivate
	if req.Visibility != nil {
		visibility = normalizeVisibility(string(*req.Visibility))
	}
	if depth < -1 || depth > 5 {
		return ArchiveJobCreate{}, fmt.Errorf("depth must be between -1 and 5")
	}
	if maxPages < 0 || maxPages > 1000 {
		return ArchiveJobCreate{}, fmt.Errorf("maxPages must be between 0 and 1000; use 0 for unlimited")
	}
	return ArchiveJobCreate{
		URL:             req.Url,
		URLs:            urls,
		Scope:           scope,
		Depth:           depth,
		MaxPages:        maxPages,
		Prefix:          prefix,
		PathExcludeRx:   pathExcludeRx,
		CookieProfileID: cookieProfileID,
		Visibility:      visibility,
		Enrich:          enrich,
	}, nil
}

func mustHTTPURL(raw string) (string, error) {
	u, err := parseURL(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("URL must use http or https")
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("URL host is required")
	}
	return u.String(), nil
}

func boundedLimit(v *int, def, max int) int {
	if v == nil || *v <= 0 {
		return def
	}
	if *v > max {
		return max
	}
	return *v
}

func readJSON(r *http.Request, dest any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json response error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}

func nullableString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func nullableTime(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	return &v.Time
}

func nullableInt(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	i := int(v.Int64)
	return &i
}

func tagsFromJSON(raw string) *[]string {
	var tags []string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		tags = []string{}
	}
	return &tags
}

func apiUser(u *UserRecord) api.User {
	if u == nil {
		return api.User{}
	}
	return api.User{Id: u.ID, Username: u.Username, Email: nullableString(u.Email), DisplayName: u.DisplayName, IsAdmin: u.IsAdmin, CreatedAt: u.CreatedAt}
}

func apiArchiveJob(j *ArchiveJobRecord) api.ArchiveJob {
	return api.ArchiveJob{
		Id:            j.ID,
		Url:           j.URL,
		Scope:         api.ArchiveScope(j.Scope),
		Depth:         j.Depth,
		MaxPages:      j.MaxPages,
		Visibility:    api.Visibility(j.Visibility),
		Status:        api.JobStatus(j.Status),
		StatusMessage: nullableString(j.StatusMessage),
		Error:         nullableString(j.Error),
		CaptureId:     nullableString(j.CaptureID),
		CreatedAt:     j.CreatedAt,
		StartedAt:     nullableTime(j.StartedAt),
		FinishedAt:    nullableTime(j.FinishedAt),
	}
}

func apiArchiveJobDetail(j *ArchiveJobRecord) api.ArchiveJobDetail {
	base := apiArchiveJob(j)
	return api.ArchiveJobDetail{
		Id:            base.Id,
		Url:           base.Url,
		Scope:         base.Scope,
		Depth:         base.Depth,
		MaxPages:      base.MaxPages,
		Visibility:    base.Visibility,
		Status:        base.Status,
		StatusMessage: base.StatusMessage,
		Error:         base.Error,
		CaptureId:     base.CaptureId,
		CreatedAt:     base.CreatedAt,
		StartedAt:     base.StartedAt,
		FinishedAt:    base.FinishedAt,
		Logs:          []api.JobLog{},
	}
}

func apiSite(s *SiteRecord) api.Site {
	return api.Site{
		Id:        s.ID,
		Host:      s.Host,
		Title:     nullableString(s.Title),
		ItemCount: s.ItemCount,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}

func apiItem(i *ItemRecord) api.Item {
	return api.Item{
		Id:           i.ID,
		SiteId:       i.SiteID,
		CaptureId:    i.CaptureID,
		Url:          i.URL,
		CanonicalUrl: nullableString(i.CanonicalURL),
		Title:        i.Title,
		Summary:      nullableString(i.Summary),
		Tags:         tagsFromJSON(i.TagsJSON),
		Replayable:   i.Replayable,
		Depth:        i.Depth,
		StatusCode:   nullableInt(i.StatusCode),
		ContentType:  nullableString(i.ContentType),
		CreatedAt:    i.CreatedAt,
	}
}

func apiItemDetail(i *ItemRecord) api.ItemDetail {
	base := apiItem(i)
	return api.ItemDetail{
		Id:           base.Id,
		SiteId:       base.SiteId,
		CaptureId:    base.CaptureId,
		Url:          base.Url,
		CanonicalUrl: base.CanonicalUrl,
		Title:        base.Title,
		Summary:      base.Summary,
		Tags:         base.Tags,
		Replayable:   base.Replayable,
		Depth:        base.Depth,
		StatusCode:   base.StatusCode,
		ContentType:  base.ContentType,
		CreatedAt:    base.CreatedAt,
	}
}

func apiCookieProfile(c *CookieProfileRecord) api.CookieProfile {
	return api.CookieProfile{
		Id:         c.ID,
		Name:       c.Name,
		SourceType: api.CookieProfileSourceType(c.SourceType),
		Host:       nullableString(c.Host),
		CreatedAt:  c.CreatedAt,
	}
}

func archiveFileContentType(path string) string {
	switch {
	case strings.HasSuffix(strings.ToLower(path), ".wacz"):
		return "application/wacz"
	case strings.HasSuffix(strings.ToLower(path), ".warc.gz"):
		return "application/gzip"
	case strings.HasSuffix(strings.ToLower(path), ".warc"):
		return "application/warc"
	default:
		return "application/octet-stream"
	}
}
