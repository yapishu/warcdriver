package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (a *App) StartWorkers(ctx context.Context, n int) {
	if err := a.store.RequeueRunningJobs(ctx); err != nil {
		log.Printf("requeue running jobs: %v", err)
	}
	if n < 1 {
		n = 1
	}
	for i := 0; i < n; i++ {
		go a.workerLoop(ctx, i+1)
	}
}

func (a *App) workerLoop(ctx context.Context, workerID int) {
	log.Printf("archive worker %d started", workerID)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		job, err := a.store.ClaimNextArchiveJob(ctx)
		if err == nil {
			a.runArchiveJob(ctx, job)
			continue
		}
		if err != nil && !errorsIsNoRows(err) {
			log.Printf("worker claim error: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) runArchiveJob(ctx context.Context, job *ArchiveJobRecord) {
	jobCtx, cancel := context.WithCancel(ctx)
	a.setActiveJob(job.ID, cancel)
	defer func() {
		a.clearActiveJob(job.ID)
		cancel()
	}()

	jobLog := func(level, msg string) {
		_ = a.store.AddJobLog(context.Background(), job.ID, level, msg)
	}
	jobLog("info", "job started")

	var explicit []string
	_ = json.Unmarshal([]byte(job.URLsJSON), &explicit)

	var browserCookies []browserCookieData
	if job.CookieProfileID.Valid {
		profile, err := a.store.GetCookieProfile(jobCtx, job.CookieProfileID.String)
		if err != nil {
			jobLog("error", "cookie profile not found: "+err.Error())
			_ = a.store.FailJob(ctx, job.ID, err)
			return
		}
		browserCookies, err = browserCookiesForProfile(profile, job.URL)
		if err != nil {
			jobLog("error", "cookie profile failed: "+err.Error())
			_ = a.store.FailJob(ctx, job.ID, err)
			return
		}
		if len(browserCookies) == 0 {
			err := fmt.Errorf("cookie profile %q has no cookies relevant to %s", profile.Name, hostFromURL(job.URL))
			jobLog("error", err.Error())
			_ = a.store.FailJob(ctx, job.ID, err)
			return
		}
		jobLog("info", fmt.Sprintf("cookie profile %q selected with %d relevant cookies", profile.Name, len(browserCookies)))
	}
	userAgentSetting, _ := a.store.GetSetting(jobCtx, "user_agent")
	userAgent := effectiveCaptureUserAgent(jobCtx, userAgentSetting)
	if userAgent != "" {
		jobLog("info", "capture user agent configured")
	}
	headlessRaw, _ := a.store.GetSetting(jobCtx, "capture_headless")
	captureHeadless, _ := strconv.ParseBool(firstNonEmpty(headlessRaw, getenv("CAPTURE_HEADLESS", "false")))
	if captureHeadless {
		jobLog("info", "capture browser mode: headless Brave")
	} else {
		jobLog("info", "capture browser mode: headed Brave via Xvfb")
	}
	pageDelay := a.captureSettingInt(jobCtx, "capture_page_delay", "CAPTURE_PAGE_DELAY", 3, 1, 120)
	pageRetries := a.captureSettingInt(jobCtx, "capture_page_retries", "CAPTURE_PAGE_RETRIES", 0, 0, 5)
	useSitemap := a.captureSettingBool(jobCtx, "capture_use_sitemap", "CAPTURE_USE_SITEMAP", true)
	jobLog("info", fmt.Sprintf("capture pacing: %ds page delay, %d page retries", pageDelay, pageRetries))

	onCaptureLog := func(level, message string) {
		jobLog(level, message)
		_ = a.store.UpdateJobMessage(context.Background(), job.ID, message)
	}
	result, err := a.captureArchiveWithBrowsertrix(jobCtx, BrowsertrixCaptureOptions{
		JobID:        job.ID,
		StartURL:     job.URL,
		ExplicitURLs: explicit,
		Scope:        job.Scope,
		Depth:        job.Depth,
		MaxPages:     job.MaxPages,
		Prefix:       nullString(job.Prefix),
		UserAgent:    userAgent,
		Cookies:      browserCookies,
		BlockAds:     a.filter != nil,
		Headless:     captureHeadless,
		PageDelay:    pageDelay,
		PageRetries:  pageRetries,
		UseSitemap:   useSitemap,
		OnLog:        onCaptureLog,
	})
	if err != nil {
		if jobCtx.Err() != nil {
			jobLog("warn", "capture canceled")
			_, _ = a.store.CancelJob(context.Background(), job.ID)
			return
		}
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}
	if len(result.Pages) == 0 {
		err := fmt.Errorf("no pages captured")
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}

	first := result.Pages[0]
	if reason := capturedPageFailureReason(first); reason != "" {
		err := fmt.Errorf("%s", reason)
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}
	for _, page := range result.Pages {
		if page.StatusCode >= 400 {
			jobLog("warn", fmt.Sprintf("captured page returned HTTP %d: %s", page.StatusCode, page.URL))
		}
	}
	siteHost := hostFromURL(job.URL)
	site, err := a.store.UpsertSite(jobCtx, siteHost, first.Title)
	if err != nil {
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}
	capture, err := a.store.CreateCapture(jobCtx, job.ID, site.ID, job.URL, first.Title, result.WARCPath)
	if err != nil {
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}

	for _, page := range result.Pages {
		if jobCtx.Err() != nil {
			jobLog("warn", "capture canceled during indexing")
			_, _ = a.store.CancelJob(context.Background(), job.ID)
			return
		}
		item, err := a.store.CreateItem(jobCtx, ItemRecord{
			JobID:        job.ID,
			CaptureID:    capture.ID,
			SiteID:       site.ID,
			URL:          page.URL,
			CanonicalURL: sqlNullString(page.CanonicalURL),
			Title:        firstNonEmpty(page.Title, page.URL),
			Summary:      sqlNullString(localSummary(page.Markdown)),
			TagsJSON:     "[]",
			Replayable:   page.Replayable,
			Depth:        page.Depth,
			StatusCode:   sqlNullInt(page.StatusCode),
			ContentType:  sqlNullString(page.ContentType),
		})
		if err != nil {
			jobLog("error", "failed to index item: "+err.Error())
			continue
		}
		mdPath := a.store.MarkdownPath(capture.ID, item.ID)
		if err := os.MkdirAll(filepath.Dir(mdPath), 0o755); err != nil {
			jobLog("error", "failed to create markdown dir: "+err.Error())
		} else if err := os.WriteFile(mdPath, []byte(page.Markdown), 0o644); err != nil {
			jobLog("error", "failed to write markdown: "+err.Error())
		} else {
			_ = a.store.SetItemMarkdownPath(jobCtx, item.ID, mdPath)
		}
		if shouldEnrich, _ := a.enrichmentEnabled(jobCtx); job.Enrich && shouldEnrich {
			if summary, tags, err := a.enrichMarkdown(jobCtx, page.Markdown); err == nil {
				_ = a.store.UpdateItemEnrichment(jobCtx, item.ID, summary, tags)
			} else {
				jobLog("warn", "OpenRouter enrichment failed: "+err.Error())
			}
		}
	}

	if err := a.store.FinishJob(context.Background(), job.ID, capture.ID); err != nil {
		log.Printf("finish job %s: %v", job.ID, err)
	}
	jobLog("info", fmt.Sprintf("job complete: captured %d pages", len(result.Pages)))
}

func (a *App) setActiveJob(jobID string, cancel context.CancelFunc) {
	a.activeMu.Lock()
	defer a.activeMu.Unlock()
	a.activeJobs[jobID] = cancel
}

func (a *App) clearActiveJob(jobID string) {
	a.activeMu.Lock()
	defer a.activeMu.Unlock()
	delete(a.activeJobs, jobID)
}

func (a *App) cancelActiveJob(jobID string) {
	a.activeMu.Lock()
	cancel := a.activeJobs[jobID]
	a.activeMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *App) enrichmentEnabled(ctx context.Context) (bool, error) {
	raw, err := a.store.GetSetting(ctx, "enrichment_enabled")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(raw, "true"), nil
}

func (a *App) openRouterAPIKey(ctx context.Context) (string, error) {
	key, err := a.store.GetSetting(ctx, "openrouter_api_key")
	key = strings.TrimSpace(key)
	if key == "" {
		key = strings.TrimSpace(getenv("OPENROUTER_API_KEY", ""))
	}
	return key, err
}

func (a *App) enrichMarkdown(ctx context.Context, markdown string) (string, []string, error) {
	key, _ := a.openRouterAPIKey(ctx)
	if key == "" {
		return "", nil, fmt.Errorf("OpenRouter API key is not configured")
	}
	model, _ := a.store.GetSetting(ctx, "openrouter_model")
	if model == "" {
		model = "openrouter/auto"
	}
	if len(markdown) > 20000 {
		markdown = markdown[:20000]
	}

	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You organize a personal web archive. Return compact JSON only with keys summary, tags. summary must be one sentence. tags must be 3 to 8 short lowercase tags. Write the summary and tags in English regardless of the source language.",
			},
			{
				"role":    "user",
				"content": markdown,
			},
		},
		"response_format": map[string]string{"type": "json_object"},
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://openrouter.ai/api/v1/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "https://warcdriver.local")
	req.Header.Set("X-Title", "WARCdriver")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("OpenRouter returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return "", nil, err
	}
	if len(decoded.Choices) == 0 {
		return "", nil, fmt.Errorf("OpenRouter returned no choices")
	}
	var payload struct {
		Summary string   `json:"summary"`
		Tags    []string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(decoded.Choices[0].Message.Content), &payload); err != nil {
		return localSummary(decoded.Choices[0].Message.Content), nil, nil
	}
	if payload.Summary == "" {
		payload.Summary = localSummary(markdown)
	}
	return payload.Summary, normalizeTags(payload.Tags), nil
}

func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		tag = strings.Trim(tag, "#,.; ")
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
		if len(out) == 8 {
			break
		}
	}
	return out
}

func localSummary(markdown string) string {
	text := strings.Join(strings.Fields(markdown), " ")
	if text == "" {
		return ""
	}
	for _, sep := range []string{". ", "! ", "? "} {
		if idx := strings.Index(text, sep); idx > 40 && idx < 240 {
			return strings.TrimSpace(text[:idx+1])
		}
	}
	if len(text) > 220 {
		return strings.TrimSpace(text[:220]) + "..."
	}
	return text
}

func errorsIsNoRows(err error) bool {
	return err == sql.ErrNoRows
}

func (a *App) captureSettingInt(ctx context.Context, key, envKey string, fallback, minValue, maxValue int) int {
	raw, _ := a.store.GetSetting(ctx, key)
	if strings.TrimSpace(raw) == "" {
		raw = getenv(envKey, strconv.Itoa(fallback))
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func (a *App) captureSettingBool(ctx context.Context, key, envKey string, fallback bool) bool {
	raw, _ := a.store.GetSetting(ctx, key)
	if strings.TrimSpace(raw) == "" {
		raw = getenv(envKey, strconv.FormatBool(fallback))
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func nullString(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.String
}

func sqlNullString(v string) sql.NullString {
	if strings.TrimSpace(v) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}

func sqlNullInt(v int) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true}
}
