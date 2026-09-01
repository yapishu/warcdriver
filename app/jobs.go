package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultCapturePageRetries = 3
	rateLimitRetryBaseDelay   = 30 * time.Second
	rateLimitRetryMaxDelay    = 5 * time.Minute
	substackMinPageDelay      = 60
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

func cookieDomainLogSuffix(cookies []browserCookieData) string {
	seen := map[string]bool{}
	for _, cookie := range cookies {
		domain := strings.TrimSpace(cookie.Domain)
		if domain == "" && cookie.URL != "" {
			domain = hostFromURL(cookie.URL)
		}
		if domain == "" {
			continue
		}
		seen[domain] = true
	}
	if len(seen) == 0 {
		return ""
	}
	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	if len(domains) > 8 {
		return fmt.Sprintf(" across %d domains: %s, +%d more", len(domains), strings.Join(domains[:8], ", "), len(domains)-8)
	}
	return fmt.Sprintf(" across %d domains: %s", len(domains), strings.Join(domains, ", "))
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
	isSubstackMode := job.Scope == "substack"
	captureStartURL := job.URL
	captureScope := job.Scope
	captureDepth := job.Depth
	captureMaxPages := job.MaxPages
	if isSubstackMode {
		var err error
		explicit, err = discoverSubstackPosts(jobCtx, nil, job.URL)
		if err != nil {
			jobLog("error", err.Error())
			_ = a.store.FailJob(ctx, job.ID, err)
			return
		}
		captureStartURL, _ = substackHomepageURL(job.URL)
		captureScope = "explicit_urls"
		captureDepth = 0
		captureMaxPages = len(explicit) + 1
		jobLog("info", fmt.Sprintf("Substack mode discovered %d posts from sitemap; capturing exact post URLs plus homepage metadata", len(explicit)))
	}

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
			err := fmt.Errorf("cookie profile %q has no valid cookies to import", profile.Name)
			jobLog("error", err.Error())
			_ = a.store.FailJob(ctx, job.ID, err)
			return
		}
		jobLog("info", fmt.Sprintf("cookie profile %q selected with %d cookies%s", profile.Name, len(browserCookies), cookieDomainLogSuffix(browserCookies)))
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
	if isSubstackMode && pageDelay < substackMinPageDelay {
		pageDelay = substackMinPageDelay
	}
	pageRetries := a.captureSettingInt(jobCtx, "capture_page_retries", "CAPTURE_PAGE_RETRIES", defaultCapturePageRetries, 0, 5)
	useSitemap := a.captureSettingBool(jobCtx, "capture_use_sitemap", "CAPTURE_USE_SITEMAP", true)
	jobLog("info", fmt.Sprintf("capture pacing: %ds page delay, %d page retries", pageDelay, pageRetries))

	onCaptureLog := func(level, message string) {
		jobLog(level, message)
		_ = a.store.UpdateJobMessage(context.Background(), job.ID, message)
	}
	captureOptions := BrowsertrixCaptureOptions{
		JobID:         job.ID,
		StartURL:      captureStartURL,
		ExplicitURLs:  explicit,
		Scope:         captureScope,
		Depth:         captureDepth,
		MaxPages:      captureMaxPages,
		Prefix:        nullString(job.Prefix),
		PathExcludeRx: nullString(job.PathExcludeRx),
		UserAgent:     userAgent,
		Cookies:       browserCookies,
		BlockAds:      a.filter != nil,
		Headless:      captureHeadless,
		PageDelay:     pageDelay,
		PageRetries:   pageRetries,
		UseSitemap:    useSitemap,
		SubstackMode:  isSubstackMode,
		OnLog:         onCaptureLog,
	}

	result, err := a.captureWithRateLimitBackoff(jobCtx, captureOptions, jobLog)
	if err != nil {
		if jobCtx.Err() != nil {
			jobLog("warn", "capture canceled")
			_, _ = a.store.CancelJob(context.Background(), job.ID)
		} else {
			jobLog("error", err.Error())
			a.discardBrowsertrixRun(job.ID, jobLog)
			_ = a.store.FailJob(context.Background(), job.ID, err)
		}
		return
	}

	first := result.Pages[0]
	if isSubstackMode {
		if homepage, ok := capturedPageForURL(result.Pages, captureStartURL); ok && capturedPageFailureReason(homepage) == "" {
			first = homepage
		} else {
			first = CapturedPage{URL: captureStartURL, FinalURL: captureStartURL, Title: hostFromURL(captureStartURL), StatusCode: http.StatusOK}
			jobLog("warn", "Substack homepage metadata was unavailable; preserving publication host metadata instead of using a random post")
		}
	}
	if reason := capturedPageFailureReason(first); reason != "" {
		err := fmt.Errorf("%s", reason)
		jobLog("error", err.Error())
		a.discardBrowsertrixRun(job.ID, jobLog)
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}
	for _, page := range result.Pages {
		if page.StatusCode >= 400 {
			jobLog("warn", fmt.Sprintf("captured page returned HTTP %d: %s", page.StatusCode, page.URL))
		}
	}
	siteHost := hostFromURL(job.URL)
	site, err := a.store.UpsertSite(jobCtx, siteHost, first.Title, localSummary(first.Markdown))
	if err != nil {
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}
	capture, err := a.store.CreateCapture(jobCtx, job.ID, site.ID, nullString(job.UserID), job.URL, first.Title, result.WARCPath, job.Visibility)
	if err != nil {
		jobLog("error", err.Error())
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}

	shouldEnrich, _ := a.enrichmentEnabled(jobCtx)
	if job.ReplaceItemID.Valid {
		if err := a.replaceCapturedItem(jobCtx, job, capture, site, first, shouldEnrich, jobLog); err != nil {
			jobLog("error", err.Error())
			_ = a.store.FailJob(context.Background(), job.ID, err)
			return
		}
		if err := a.store.FinishJob(context.Background(), job.ID, capture.ID); err != nil {
			log.Printf("finish job %s: %v", job.ID, err)
		}
		jobLog("info", "job complete: replaced archived item")
		return
	}

	indexed := 0
	retryURLs := []string{}
	if isSubstackMode {
		retryURLs = append(retryURLs, missingCapturedURLs(explicit, result.Pages)...)
		if len(retryURLs) > 0 {
			jobLog("warn", fmt.Sprintf("Browsertrix produced no page record for %d expected Substack posts; scheduling isolated retries", len(retryURLs)))
		}
	}
	for _, page := range result.Pages {
		if jobCtx.Err() != nil {
			jobLog("warn", "capture canceled during indexing")
			_, _ = a.store.CancelJob(context.Background(), job.ID)
			return
		}
		if isSubstackMode && !isSubstackPostURL(page.URL) {
			continue
		}
		if reason := capturedPageFailureReason(page); reason != "" {
			jobLog("warn", fmt.Sprintf("skip captured page %s: %s", page.URL, reason))
			if isSubstackPostURL(page.URL) || capturedPageRateLimitReason(page) != "" {
				retryURLs = append(retryURLs, page.URL)
			}
			continue
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
			_ = a.store.SetItemSearchText(jobCtx, item.ID, page.Markdown)
		}
		if job.Enrich && shouldEnrich {
			if summary, tags, err := a.enrichMarkdown(jobCtx, page.Markdown); err == nil {
				_ = a.store.UpdateItemEnrichment(jobCtx, item.ID, summary, tags)
			} else {
				jobLog("warn", "OpenRouter enrichment failed: "+err.Error())
			}
		}
		indexed++
	}

	if indexed == 0 {
		err := fmt.Errorf("no usable pages captured")
		jobLog("error", err.Error())
		a.discardBrowsertrixRun(job.ID, jobLog)
		_ = a.store.FailJob(context.Background(), job.ID, err)
		return
	}

	if err := a.store.FinishJob(context.Background(), job.ID, capture.ID); err != nil {
		log.Printf("finish job %s: %v", job.ID, err)
	}
	if pageRetries > 0 && len(retryURLs) > 0 {
		a.queuePageRetries(context.Background(), job, retryURLs, jobLog)
	}
	if isSubstackMode {
		jobLog("info", fmt.Sprintf("job complete: indexed %d/%d Substack posts; missing or failed posts were queued for isolated retry", indexed, len(explicit)))
	} else {
		jobLog("info", fmt.Sprintf("job complete: captured %d pages", indexed))
	}
}

func (a *App) queuePageRetries(ctx context.Context, parent *ArchiveJobRecord, urls []string, jobLog func(level, msg string)) {
	seen := make(map[string]bool, len(urls))
	queued := 0
	for _, rawURL := range urls {
		rawURL = strings.TrimSpace(rawURL)
		normalized := normalizeURL(rawURL)
		if rawURL == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		retryJob, err := a.store.CreateArchiveJob(ctx, nullString(parent.UserID), ArchiveJobCreate{
			URL:             rawURL,
			Scope:           "single_page",
			Depth:           0,
			MaxPages:        1,
			CookieProfileID: nullString(parent.CookieProfileID),
			Visibility:      parent.Visibility,
			Enrich:          parent.Enrich,
		})
		if err != nil {
			jobLog("error", fmt.Sprintf("failed to queue page retry for %s: %v", rawURL, err))
			continue
		}
		_ = a.store.AddJobLog(ctx, retryJob.ID, "info", fmt.Sprintf("job queued to retry missing or failed page from job %s", parent.ID))
		queued++
	}
	if queued > 0 {
		jobLog("info", fmt.Sprintf("queued %d missing or failed pages as isolated retry jobs with exponential backoff for rate limits", queued))
	}
}

func (a *App) captureWithRateLimitBackoff(ctx context.Context, opts BrowsertrixCaptureOptions, jobLog func(level, msg string)) (*CaptureResult, error) {
	maxRetries := browsertrixMaxPageRetries(opts)
	for attempt := 0; ; attempt++ {
		result, err := a.captureArchiveWithBrowsertrix(ctx, opts)
		if err != nil {
			return nil, err
		}
		if len(result.Pages) == 0 {
			a.discardBrowsertrixRun(opts.JobID, jobLog)
			return nil, fmt.Errorf("no pages captured")
		}
		primary, _ := capturedPageForURL(result.Pages, opts.StartURL)
		if !opts.SubstackMode {
			if primary.URL == "" {
				primary = result.Pages[0]
			}
		}
		if !opts.SubstackMode {
			if reason := capturedPageRateLimitReason(primary); reason != "" {
				a.discardBrowsertrixRun(opts.JobID, jobLog)
				if attempt >= maxRetries {
					return nil, fmt.Errorf("%s after %d attempts", reason, attempt+1)
				}
				delay := rateLimitRetryDelay(attempt)
				message := fmt.Sprintf("%s; retrying in %s", reason, delay.Round(time.Second))
				jobLog("warn", message)
				_ = a.store.UpdateJobMessage(context.Background(), opts.JobID, message)
				if err := waitForRetry(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
		}
		return result, nil
	}
}

func rateLimitRetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := rateLimitRetryBaseDelay
	for i := 0; i < attempt && delay < rateLimitRetryMaxDelay; i++ {
		delay *= 2
	}
	if delay > rateLimitRetryMaxDelay {
		return rateLimitRetryMaxDelay
	}
	return delay
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *App) discardBrowsertrixRun(jobID string, jobLog func(level, msg string)) {
	if jobID == "" {
		return
	}
	if err := os.RemoveAll(a.browsertrixCollectionDir(jobID)); err != nil {
		jobLog("warn", "failed to discard rejected archive: "+err.Error())
	}
}

func (a *App) replaceCapturedItem(ctx context.Context, job *ArchiveJobRecord, capture *CaptureRecord, site *SiteRecord, page CapturedPage, shouldEnrich bool, jobLog func(level, msg string)) error {
	if _, err := a.store.GetItem(ctx, job.ReplaceItemID.String); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("replacement item not found")
		}
		return err
	}
	rec := itemRecordForCapturedPage(job, capture, site, page)
	mdPath, err := a.writeCapturedMarkdown(capture.ID, job.ReplaceItemID.String, page.Markdown)
	if err != nil {
		return err
	}
	rec.MarkdownPath = sqlNullString(mdPath)
	if job.Enrich && shouldEnrich {
		if summary, tags, err := a.enrichMarkdown(ctx, page.Markdown); err == nil {
			rec.Summary = sqlNullString(summary)
			rawTags, marshalErr := json.Marshal(tags)
			if marshalErr != nil {
				return marshalErr
			}
			rec.TagsJSON = string(rawTags)
		} else {
			jobLog("warn", "OpenRouter enrichment failed: "+err.Error())
		}
	}
	if _, err := a.store.ReplaceItem(ctx, job.ReplaceItemID.String, rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("replacement item not found")
		}
		return err
	}
	_ = a.store.SetItemSearchText(ctx, job.ReplaceItemID.String, page.Markdown)
	return nil
}

func itemRecordForCapturedPage(job *ArchiveJobRecord, capture *CaptureRecord, site *SiteRecord, page CapturedPage) ItemRecord {
	return ItemRecord{
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
	}
}

func (a *App) writeCapturedMarkdown(captureID, itemID, markdown string) (string, error) {
	mdPath := a.store.MarkdownPath(captureID, itemID)
	if err := os.MkdirAll(filepath.Dir(mdPath), 0o755); err != nil {
		return "", fmt.Errorf("failed to create markdown dir: %w", err)
	}
	if err := os.WriteFile(mdPath, []byte(markdown), 0o644); err != nil {
		return "", fmt.Errorf("failed to write markdown: %w", err)
	}
	return mdPath, nil
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
