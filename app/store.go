package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusCanceled  = "canceled"

	VisibilityPrivate = "private"
	VisibilityPublic  = "public"
)

type Store struct {
	db      *sql.DB
	dataDir string
}

type UserRecord struct {
	ID           string
	Username     string
	Email        sql.NullString
	DisplayName  string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
}

type SessionRecord struct {
	UserID    string
	TokenHash string
	ExpiresAt time.Time
}

type ArchiveJobRecord struct {
	ID              string
	UserID          sql.NullString
	URL             string
	URLsJSON        string
	Scope           string
	Depth           int
	MaxPages        int
	Prefix          sql.NullString
	PathExcludeRx   sql.NullString
	CookieProfileID sql.NullString
	Visibility      string
	Enrich          bool
	Status          string
	StatusMessage   sql.NullString
	Error           sql.NullString
	CaptureID       sql.NullString
	ReplaceItemID   sql.NullString
	CreatedAt       time.Time
	StartedAt       sql.NullTime
	FinishedAt      sql.NullTime
}

type CaptureRecord struct {
	ID          string
	JobID       string
	SiteID      string
	OwnerUserID sql.NullString
	StartURL    string
	Title       sql.NullString
	WARCPath    string
	Visibility  string
	CreatedAt   time.Time
}

type SiteRecord struct {
	ID        string
	Host      string
	Title     sql.NullString
	Summary   sql.NullString
	ItemCount int
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SiteFailureRecord struct {
	SiteID    string
	JobID     string
	URL       string
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ItemRecord struct {
	ID           string
	JobID        string
	CaptureID    string
	SiteID       string
	URL          string
	CanonicalURL sql.NullString
	Title        string
	Summary      sql.NullString
	TagsJSON     string
	Replayable   bool
	Depth        int
	StatusCode   sql.NullInt64
	ContentType  sql.NullString
	MarkdownPath sql.NullString
	CreatedAt    time.Time
}

type CookieProfileRecord struct {
	ID         string
	Name       string
	SourceType string
	Host       sql.NullString
	Secret     sql.NullString
	CreatedAt  time.Time
}

type JobLogRecord struct {
	At      time.Time
	Level   string
	Message string
}

func OpenStore(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "warcdriver.sqlite3")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	store := &Store{db: db, dataDir: dataDir}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT UNIQUE,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token_hash TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			prefix TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_used_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS cookie_profiles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			source_type TEXT NOT NULL,
			host TEXT,
			secret TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS archive_jobs (
			id TEXT PRIMARY KEY,
			user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
			url TEXT NOT NULL,
			urls_json TEXT NOT NULL DEFAULT '[]',
			scope TEXT NOT NULL,
			depth INTEGER NOT NULL,
			max_pages INTEGER NOT NULL,
			prefix TEXT,
			path_exclude_rx TEXT,
			cookie_profile_id TEXT REFERENCES cookie_profiles(id) ON DELETE SET NULL,
			visibility TEXT NOT NULL DEFAULT 'private',
			use_browser_profile INTEGER NOT NULL DEFAULT 0,
			enrich INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL,
			status_message TEXT,
			error TEXT,
			capture_id TEXT,
			replace_item_id TEXT,
			created_at TEXT NOT NULL,
			started_at TEXT,
			finished_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_archive_jobs_status_created ON archive_jobs(status, created_at)`,
		`CREATE TABLE IF NOT EXISTS sites (
			id TEXT PRIMARY KEY,
			host TEXT NOT NULL UNIQUE,
			title TEXT,
			summary TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS captures (
			id TEXT PRIMARY KEY,
			job_id TEXT NOT NULL REFERENCES archive_jobs(id) ON DELETE CASCADE,
			site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
			start_url TEXT NOT NULL,
			title TEXT,
			warc_path TEXT NOT NULL,
			visibility TEXT NOT NULL DEFAULT 'private',
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS items (
			id TEXT PRIMARY KEY,
			job_id TEXT NOT NULL REFERENCES archive_jobs(id) ON DELETE CASCADE,
			capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
			site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			canonical_url TEXT,
			title TEXT NOT NULL,
			summary TEXT,
			tags_json TEXT NOT NULL DEFAULT '[]',
			replayable INTEGER NOT NULL DEFAULT 1,
			depth INTEGER NOT NULL,
			status_code INTEGER,
			content_type TEXT,
			markdown_path TEXT,
			search_text TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_items_site_created ON items(site_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_items_capture ON items(capture_id)`,
		`CREATE TABLE IF NOT EXISTS site_failures (
			site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			job_id TEXT NOT NULL REFERENCES archive_jobs(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			error TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(site_id, url)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_site_failures_site_updated ON site_failures(site_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS job_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL REFERENCES archive_jobs(id) ON DELETE CASCADE,
			at TEXT NOT NULL,
			level TEXT NOT NULL,
			message TEXT NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := s.ensureUsersSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureItemsSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureSitesSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureArchiveJobsSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureCapturesSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureReplayabilityBackfill(ctx); err != nil {
		return err
	}
	return s.ensureDefaultSettings(ctx)
}

type tableColumn struct {
	NotNull bool
}

type userMigrationRecord struct {
	ID           string
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string
	CreatedAt    string
}

func (s *Store) ensureUsersSchema(ctx context.Context) error {
	cols, err := s.tableColumns(ctx, "users")
	if err != nil {
		return err
	}
	emailCol, hasEmail := cols["email"]
	_, hasUsername := cols["username"]
	if hasUsername && hasEmail && !emailCol.NotNull {
		return s.ensureUserAdminSchema(ctx)
	}

	users, err := s.usersForMigration(ctx, hasUsername, hasEmail)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	defer func() {
		_, _ = s.db.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`)
	}()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE users_new (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		email TEXT UNIQUE,
		display_name TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL
	)`); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, user := range users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users_new(id, username, email, display_name, password_hash, is_admin, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			user.ID, user.Username, nullableDBText(user.Email), user.DisplayName, user.PasswordHash, 0, user.CreatedAt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE users`); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE users_new RENAME TO users`); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.ensureUserAdminSchema(ctx)
}

func (s *Store) ensureUserAdminSchema(ctx context.Context) error {
	cols, err := s.tableColumns(ctx, "users")
	if err != nil {
		return err
	}
	if _, ok := cols["is_admin"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	var admins int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE is_admin != 0`).Scan(&admins); err != nil {
		return err
	}
	if admins > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET is_admin = 1 WHERE id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1)`)
	return err
}

func (s *Store) tableColumns(ctx context.Context, table string) (map[string]tableColumn, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := map[string]tableColumn{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = tableColumn{NotNull: notNull != 0}
	}
	return cols, rows.Err()
}

func (s *Store) ensureItemsSchema(ctx context.Context) error {
	cols, err := s.tableColumns(ctx, "items")
	if err != nil {
		return err
	}
	if _, ok := cols["replayable"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE items ADD COLUMN replayable INTEGER NOT NULL DEFAULT 1`); err != nil {
			return err
		}
	}
	if _, ok := cols["search_text"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE items ADD COLUMN search_text TEXT`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureSitesSchema(ctx context.Context) error {
	cols, err := s.tableColumns(ctx, "sites")
	if err != nil {
		return err
	}
	if _, ok := cols["summary"]; !ok {
		_, err = s.db.ExecContext(ctx, `ALTER TABLE sites ADD COLUMN summary TEXT`)
	}
	return err
}

func (s *Store) ensureArchiveJobsSchema(ctx context.Context) error {
	cols, err := s.tableColumns(ctx, "archive_jobs")
	if err != nil {
		return err
	}
	if _, ok := cols["path_exclude_rx"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE archive_jobs ADD COLUMN path_exclude_rx TEXT`); err != nil {
			return err
		}
	}
	if _, ok := cols["visibility"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE archive_jobs ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'`); err != nil {
			return err
		}
	}
	if _, ok := cols["replace_item_id"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE archive_jobs ADD COLUMN replace_item_id TEXT`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureCapturesSchema(ctx context.Context) error {
	cols, err := s.tableColumns(ctx, "captures")
	if err != nil {
		return err
	}
	if _, ok := cols["owner_user_id"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE captures ADD COLUMN owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL`); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE captures SET owner_user_id = (SELECT user_id FROM archive_jobs WHERE archive_jobs.id = captures.job_id) WHERE owner_user_id IS NULL`); err != nil {
			return err
		}
	}
	if _, ok := cols["visibility"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE captures ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureReplayabilityBackfill(ctx context.Context) error {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, "replayability_backfilled_v1").Scan(&value)
	if err == nil && value == "true" {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := s.backfillItemReplayability(ctx); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		"replayability_backfilled_v1", "true")
	return err
}

func (s *Store) backfillItemReplayability(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, warc_path FROM captures ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type capturePath struct {
		ID   string
		Path string
	}
	var captures []capturePath
	for rows.Next() {
		var rec capturePath
		if err := rows.Scan(&rec.ID, &rec.Path); err != nil {
			return err
		}
		captures = append(captures, rec)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, capture := range captures {
		if strings.TrimSpace(capture.Path) == "" || !strings.HasSuffix(strings.ToLower(capture.Path), ".wacz") {
			continue
		}
		replayable, err := readBrowsertrixReplayableURLsFromWACZ(capture.Path)
		if err != nil {
			continue
		}
		if replayable == nil {
			continue
		}
		if err := s.backfillCaptureReplayability(ctx, capture.ID, replayable); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) backfillCaptureReplayability(ctx context.Context, captureID string, replayable map[string]bool) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, url FROM items WHERE capture_id = ?`, captureID)
	if err != nil {
		return err
	}
	defer rows.Close()

	type itemReplayability struct {
		ID         string
		Replayable bool
	}
	var items []itemReplayability
	for rows.Next() {
		var id, rawURL string
		if err := rows.Scan(&id, &rawURL); err != nil {
			return err
		}
		items = append(items, itemReplayability{
			ID:         id,
			Replayable: replayable[normalizeURL(rawURL)],
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `UPDATE items SET replayable = ? WHERE id = ?`, boolInt(item.Replayable), item.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) usersForMigration(ctx context.Context, hasUsername, hasEmail bool) ([]userMigrationRecord, error) {
	usernameExpr := "''"
	if hasUsername {
		usernameExpr = "username"
	}
	emailExpr := "''"
	if hasEmail {
		emailExpr = "email"
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT id, %s, %s, display_name, password_hash, created_at FROM users`, usernameExpr, emailExpr))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	used := map[string]bool{}
	var users []userMigrationRecord
	for rows.Next() {
		var rec userMigrationRecord
		var username, email sql.NullString
		if err := rows.Scan(&rec.ID, &username, &email, &rec.DisplayName, &rec.PasswordHash, &rec.CreatedAt); err != nil {
			return nil, err
		}
		rec.Email = strings.TrimSpace(email.String)
		rec.Username = normalizeUsername(username.String)
		if rec.Username == "user" && strings.TrimSpace(username.String) == "" {
			rec.Username = usernameFromEmailOrID(rec.Email, rec.ID)
		}
		rec.Username = uniqueUsername(rec.Username, used)
		users = append(users, rec)
	}
	return users, rows.Err()
}

func usernameFromEmailOrID(email, id string) string {
	base := strings.TrimSpace(email)
	if at := strings.Index(base, "@"); at > 0 {
		base = base[:at]
	}
	if base == "" {
		base = id
	}
	return normalizeUsername(base)
}

func normalizeUsername(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	username := strings.Trim(b.String(), "._-")
	if username == "" {
		return "user"
	}
	return username
}

func uniqueUsername(base string, used map[string]bool) string {
	base = normalizeUsername(base)
	username := base
	for i := 2; used[username]; i++ {
		username = fmt.Sprintf("%s%d", base, i)
	}
	used[username] = true
	return username
}

func nullableDBText(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func (s *Store) ensureDefaultSettings(ctx context.Context) error {
	defaults := map[string]string{
		"openrouter_model":     getenv("OPENROUTER_MODEL", "openrouter/auto"),
		"openrouter_api_key":   getenv("OPENROUTER_API_KEY", ""),
		"enrichment_enabled":   "true",
		"filter_lists":         `["https://easylist.to/easylist/easylist.txt","https://easylist.to/easylist/easyprivacy.txt"]`,
		"user_agent":           getenv("CAPTURE_USER_AGENT", ""),
		"capture_headless":     getenv("CAPTURE_HEADLESS", "false"),
		"capture_page_delay":   getenv("CAPTURE_PAGE_DELAY", "3"),
		"capture_page_retries": getenv("CAPTURE_PAGE_RETRIES", strconv.Itoa(defaultCapturePageRetries)),
		"capture_use_sitemap":  getenv("CAPTURE_USE_SITEMAP", "true"),
	}
	for k, v := range defaults {
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)`, k, v); err != nil {
			return err
		}
	}
	return s.migrateCapturePageRetriesDefault(ctx)
}

func (s *Store) migrateCapturePageRetriesDefault(ctx context.Context) error {
	const migrationKey = "capture_page_retries_default_v2"
	var applied string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, migrationKey).Scan(&applied)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET value = ? WHERE key = ? AND value = ?`,
		strconv.Itoa(defaultCapturePageRetries), "capture_page_retries", "0"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?)`, migrationKey, "true"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

type UserCreate struct {
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string
	IsAdmin      bool
}

type UserUpdate struct {
	Username     *string
	Email        *string
	DisplayName  *string
	PasswordHash *string
	IsAdmin      *bool
}

func (s *Store) ListUsers(ctx context.Context) ([]UserRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, email, display_name, password_hash, is_admin, created_at FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRecord
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *user)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, req UserCreate) (*UserRecord, error) {
	now := time.Now().UTC()
	email := strings.TrimSpace(req.Email)
	u := &UserRecord{
		ID:           uuid.NewString(),
		Username:     normalizeUsername(req.Username),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		PasswordHash: req.PasswordHash,
		IsAdmin:      req.IsAdmin,
		CreatedAt:    now,
	}
	if email != "" {
		u.Email = sql.NullString{String: strings.ToLower(email), Valid: true}
	}
	if u.DisplayName == "" {
		u.DisplayName = u.Username
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id, username, email, display_name, password_hash, is_admin, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, nullableDBText(u.Email.String), u.DisplayName, u.PasswordHash, boolInt(u.IsAdmin), formatTime(now))
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, email, display_name, password_hash, is_admin, created_at FROM users WHERE username = ?`, normalizeUsername(username))
	return scanUser(row)
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*UserRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, email, display_name, password_hash, is_admin, created_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, id string, req UserUpdate) (*UserRecord, error) {
	set := []string{}
	args := []any{}
	if req.Username != nil {
		set = append(set, "username = ?")
		args = append(args, normalizeUsername(*req.Username))
	}
	if req.Email != nil {
		set = append(set, "email = ?")
		args = append(args, nullableDBText(strings.ToLower(strings.TrimSpace(*req.Email))))
	}
	if req.DisplayName != nil {
		displayName := strings.TrimSpace(*req.DisplayName)
		if displayName == "" && req.Username != nil {
			displayName = normalizeUsername(*req.Username)
		}
		set = append(set, "display_name = ?")
		args = append(args, displayName)
	}
	if req.PasswordHash != nil {
		set = append(set, "password_hash = ?")
		args = append(args, *req.PasswordHash)
	}
	if req.IsAdmin != nil {
		set = append(set, "is_admin = ?")
		args = append(args, boolInt(*req.IsAdmin))
	}
	if len(set) > 0 {
		args = append(args, id)
		res, err := s.db.ExecContext(ctx, `UPDATE users SET `+strings.Join(set, ", ")+` WHERE id = ?`, args...)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, sql.ErrNoRows
		}
	}
	return s.GetUserByID(ctx, id)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanUser(row interface{ Scan(dest ...any) error }) (*UserRecord, error) {
	var u UserRecord
	var created string
	var isAdmin int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &isAdmin, &created); err != nil {
		return nil, err
	}
	t, err := parseTime(created)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.CreatedAt = t
	return &u, nil
}

func (s *Store) CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES(?, ?, ?, ?)`,
		tokenHash, userID, formatTime(expiresAt.UTC()), formatTime(time.Now().UTC()))
	return err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (*SessionRecord, error) {
	var rec SessionRecord
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT s.user_id, s.token_hash, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`, tokenHash).
		Scan(&rec.UserID, &rec.TokenHash, &expires)
	if err != nil {
		return nil, err
	}
	t, err := parseTime(expires)
	if err != nil {
		return nil, err
	}
	rec.ExpiresAt = t
	return &rec, nil
}

func (s *Store) CreateAPIToken(ctx context.Context, userID, name, tokenHash, prefix string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO api_tokens(id, user_id, name, token_hash, prefix, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), userID, name, tokenHash, prefix, formatTime(time.Now().UTC()))
	return err
}

func (s *Store) GetAPITokenUser(ctx context.Context, tokenHash string) (*UserRecord, error) {
	var userID string
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM api_tokens WHERE token_hash = ?`, tokenHash).Scan(&userID)
	if err != nil {
		return nil, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?`, formatTime(time.Now().UTC()), tokenHash)
	return s.GetUserByID(ctx, userID)
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) CreateCookieProfile(ctx context.Context, name, sourceType string, host, secret *string) (*CookieProfileRecord, error) {
	now := time.Now().UTC()
	rec := &CookieProfileRecord{
		ID:         uuid.NewString(),
		Name:       strings.TrimSpace(name),
		SourceType: sourceType,
		CreatedAt:  now,
	}
	if host != nil && strings.TrimSpace(*host) != "" {
		rec.Host = sql.NullString{String: strings.ToLower(strings.TrimSpace(*host)), Valid: true}
	}
	if secret != nil {
		rec.Secret = sql.NullString{String: *secret, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO cookie_profiles(id, name, source_type, host, secret, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Name, rec.SourceType, rec.Host, rec.Secret, formatTime(now))
	return rec, err
}

func (s *Store) ListCookieProfiles(ctx context.Context) ([]CookieProfileRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, source_type, host, secret, created_at FROM cookie_profiles ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CookieProfileRecord
	for rows.Next() {
		rec, err := scanCookieProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) GetCookieProfile(ctx context.Context, id string) (*CookieProfileRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, source_type, host, secret, created_at FROM cookie_profiles WHERE id = ?`, id)
	return scanCookieProfile(row)
}

func (s *Store) DeleteCookieProfile(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cookie_profiles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanCookieProfile(row interface{ Scan(dest ...any) error }) (*CookieProfileRecord, error) {
	var rec CookieProfileRecord
	var created string
	if err := row.Scan(&rec.ID, &rec.Name, &rec.SourceType, &rec.Host, &rec.Secret, &created); err != nil {
		return nil, err
	}
	t, err := parseTime(created)
	if err != nil {
		return nil, err
	}
	rec.CreatedAt = t
	return &rec, nil
}

func (s *Store) CreateArchiveJob(ctx context.Context, userID string, req ArchiveJobCreate) (*ArchiveJobRecord, error) {
	now := time.Now().UTC()
	urlsJSON, err := json.Marshal(req.URLs)
	if err != nil {
		return nil, err
	}
	rec := &ArchiveJobRecord{
		ID:         uuid.NewString(),
		URL:        req.URL,
		URLsJSON:   string(urlsJSON),
		Scope:      req.Scope,
		Depth:      req.Depth,
		MaxPages:   req.MaxPages,
		Visibility: normalizeVisibility(req.Visibility),
		Enrich:     req.Enrich,
		Status:     StatusQueued,
		CreatedAt:  now,
	}
	if userID != "" {
		rec.UserID = sql.NullString{String: userID, Valid: true}
	}
	if req.Prefix != "" {
		rec.Prefix = sql.NullString{String: req.Prefix, Valid: true}
	}
	if req.PathExcludeRx != "" {
		rec.PathExcludeRx = sql.NullString{String: req.PathExcludeRx, Valid: true}
	}
	if req.CookieProfileID != "" {
		rec.CookieProfileID = sql.NullString{String: req.CookieProfileID, Valid: true}
	}
	if req.ReplaceItemID != "" {
		rec.ReplaceItemID = sql.NullString{String: req.ReplaceItemID, Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO archive_jobs(
			id, user_id, url, urls_json, scope, depth, max_pages, prefix, path_exclude_rx, cookie_profile_id,
			visibility, use_browser_profile, enrich, status, capture_id, replace_item_id, created_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.UserID, rec.URL, rec.URLsJSON, rec.Scope, rec.Depth, rec.MaxPages,
		rec.Prefix, rec.PathExcludeRx, rec.CookieProfileID, rec.Visibility, 0, boolInt(rec.Enrich),
		rec.Status, rec.CaptureID, rec.ReplaceItemID, formatTime(now))
	return rec, err
}

type ArchiveJobCreate struct {
	URL             string
	URLs            []string
	Scope           string
	Depth           int
	MaxPages        int
	Prefix          string
	PathExcludeRx   string
	CookieProfileID string
	Visibility      string
	Enrich          bool
	ReplaceItemID   string
}

func (s *Store) ClaimNextArchiveJob(ctx context.Context) (*ArchiveJobRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `SELECT id, user_id, url, urls_json, scope, depth, max_pages, prefix, path_exclude_rx, cookie_profile_id,
			visibility, use_browser_profile, enrich, status, status_message, error, capture_id, replace_item_id, created_at, started_at, finished_at
		FROM archive_jobs WHERE status = ? ORDER BY created_at ASC LIMIT 1`, StatusQueued)
	rec, err := scanArchiveJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `UPDATE archive_jobs SET status = ?, status_message = ?, started_at = ? WHERE id = ? AND status = ?`,
		StatusRunning, "capture running", formatTime(now), rec.ID, StatusQueued)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	rec.Status = StatusRunning
	rec.StatusMessage = sql.NullString{String: "capture running", Valid: true}
	rec.StartedAt = sql.NullTime{Time: now, Valid: true}
	return rec, nil
}

func (s *Store) RequeueRunningJobs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE archive_jobs SET status = ?, status_message = ?, started_at = NULL
		WHERE status = ?`, StatusQueued, "requeued after restart", StatusRunning)
	return err
}

func (s *Store) GetArchiveJob(ctx context.Context, id string) (*ArchiveJobRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, url, urls_json, scope, depth, max_pages, prefix, path_exclude_rx, cookie_profile_id,
			visibility, use_browser_profile, enrich, status, status_message, error, capture_id, replace_item_id, created_at, started_at, finished_at
		FROM archive_jobs WHERE id = ?`, id)
	return scanArchiveJob(row)
}

func (s *Store) FindActiveArchiveJob(ctx context.Context, rawURL, scope string) (*ArchiveJobRecord, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM archive_jobs
		WHERE url = ? AND scope = ? AND status IN (?, ?)
		ORDER BY created_at DESC LIMIT 1`, rawURL, scope, StatusQueued, StatusRunning).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetArchiveJob(ctx, id)
}

func (s *Store) ListArchiveJobs(ctx context.Context, limit int) ([]ArchiveJobRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, url, urls_json, scope, depth, max_pages, prefix, path_exclude_rx, cookie_profile_id,
			visibility, use_browser_profile, enrich, status, status_message, error, capture_id, replace_item_id, created_at, started_at, finished_at
		FROM archive_jobs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArchiveJobRecord
	for rows.Next() {
		rec, err := scanArchiveJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) ListArchiveJobsVisible(ctx context.Context, user *UserRecord, limit int) ([]ArchiveJobRecord, error) {
	userID, isAdmin := accessArgs(user)
	rows, err := s.db.QueryContext(ctx, `SELECT j.id, j.user_id, j.url, j.urls_json, j.scope, j.depth, j.max_pages, j.prefix, j.path_exclude_rx, j.cookie_profile_id,
			j.visibility, j.use_browser_profile, j.enrich, j.status, j.status_message, j.error, j.capture_id, j.replace_item_id, j.created_at, j.started_at, j.finished_at
		FROM archive_jobs j
		LEFT JOIN captures c ON c.id = j.capture_id
		WHERE ? = 1 OR j.user_id = ? OR c.visibility = 'public'
		ORDER BY j.created_at DESC LIMIT ?`, boolInt(isAdmin), userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArchiveJobRecord
	for rows.Next() {
		rec, err := scanArchiveJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) GetArchiveJobVisible(ctx context.Context, id string, user *UserRecord) (*ArchiveJobRecord, error) {
	userID, isAdmin := accessArgs(user)
	row := s.db.QueryRowContext(ctx, `SELECT j.id, j.user_id, j.url, j.urls_json, j.scope, j.depth, j.max_pages, j.prefix, j.path_exclude_rx, j.cookie_profile_id,
			j.visibility, j.use_browser_profile, j.enrich, j.status, j.status_message, j.error, j.capture_id, j.replace_item_id, j.created_at, j.started_at, j.finished_at
		FROM archive_jobs j
		LEFT JOIN captures c ON c.id = j.capture_id
		WHERE j.id = ? AND (? = 1 OR j.user_id = ? OR c.visibility = 'public')`, id, boolInt(isAdmin), userID)
	return scanArchiveJob(row)
}

func scanArchiveJob(row interface{ Scan(dest ...any) error }) (*ArchiveJobRecord, error) {
	var rec ArchiveJobRecord
	var created string
	var started, finished sql.NullString
	var ignoredUseProfile, enrich int
	err := row.Scan(&rec.ID, &rec.UserID, &rec.URL, &rec.URLsJSON, &rec.Scope, &rec.Depth, &rec.MaxPages,
		&rec.Prefix, &rec.PathExcludeRx, &rec.CookieProfileID, &rec.Visibility, &ignoredUseProfile, &enrich, &rec.Status, &rec.StatusMessage,
		&rec.Error, &rec.CaptureID, &rec.ReplaceItemID, &created, &started, &finished)
	if err != nil {
		return nil, err
	}
	t, err := parseTime(created)
	if err != nil {
		return nil, err
	}
	rec.CreatedAt = t
	rec.Visibility = normalizeVisibility(rec.Visibility)
	rec.Enrich = enrich != 0
	if started.Valid {
		if t, err := parseTime(started.String); err == nil {
			rec.StartedAt = sql.NullTime{Time: t, Valid: true}
		}
	}
	if finished.Valid {
		if t, err := parseTime(finished.String); err == nil {
			rec.FinishedAt = sql.NullTime{Time: t, Valid: true}
		}
	}
	return &rec, nil
}

func (s *Store) UpdateJobMessage(ctx context.Context, jobID, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE archive_jobs SET status_message = ? WHERE id = ?`, message, jobID)
	return err
}

func (s *Store) FinishJob(ctx context.Context, jobID, captureID string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE archive_jobs SET status = ?, status_message = ?, capture_id = ?, finished_at = ? WHERE id = ?`,
		StatusSucceeded, "capture complete", captureID, formatTime(now), jobID)
	return err
}

func (s *Store) FailJob(ctx context.Context, jobID string, err error) error {
	now := time.Now().UTC()
	_, dbErr := s.db.ExecContext(ctx, `UPDATE archive_jobs SET status = ?, status_message = ?, error = ?, finished_at = ? WHERE id = ?`,
		StatusFailed, "capture failed", err.Error(), formatTime(now), jobID)
	return dbErr
}

func (s *Store) CancelJob(ctx context.Context, jobID string) (*ArchiveJobRecord, error) {
	job, err := s.GetArchiveJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job.Status == StatusSucceeded || job.Status == StatusFailed || job.Status == StatusCanceled {
		return job, nil
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `UPDATE archive_jobs SET status = ?, status_message = ?, error = ?, finished_at = ? WHERE id = ?`,
		StatusCanceled, "capture canceled", "canceled by user", formatTime(now), jobID)
	if err != nil {
		return nil, err
	}
	return s.GetArchiveJob(ctx, jobID)
}

func (s *Store) DeleteArchiveJob(ctx context.Context, jobID string) error {
	job, err := s.GetArchiveJob(ctx, jobID)
	if err != nil {
		return err
	}
	if job.Status == StatusRunning {
		return fmt.Errorf("running jobs must be canceled before deletion")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM archive_jobs WHERE id = ?`, jobID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) AddJobLog(ctx context.Context, jobID, level, message string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO job_logs(job_id, at, level, message) VALUES(?, ?, ?, ?)`,
		jobID, formatTime(time.Now().UTC()), level, message)
	return err
}

func (s *Store) ListJobLogs(ctx context.Context, jobID string) ([]JobLogRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, level, message FROM job_logs WHERE job_id = ? ORDER BY id ASC`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobLogRecord
	for rows.Next() {
		var rec JobLogRecord
		var at string
		if err := rows.Scan(&at, &rec.Level, &rec.Message); err != nil {
			return nil, err
		}
		t, err := parseTime(at)
		if err != nil {
			return nil, err
		}
		rec.At = t
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) UpsertSite(ctx context.Context, host, title, summary string) (*SiteRecord, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	_, err := s.db.ExecContext(ctx, `INSERT INTO sites(id, host, title, summary, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET
			title = COALESCE(NULLIF(sites.title, ''), excluded.title),
			summary = COALESCE(NULLIF(sites.summary, ''), excluded.summary),
			updated_at = excluded.updated_at`,
		id, host, title, summary, formatTime(now), formatTime(now))
	if err != nil {
		return nil, err
	}
	return s.GetSiteByHost(ctx, host)
}

func (s *Store) GetSiteByHost(ctx context.Context, host string) (*SiteRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT s.id, s.host, s.title, s.summary, count(i.id), s.created_at, s.updated_at
		FROM sites s LEFT JOIN items i ON i.site_id = s.id WHERE s.host = ? GROUP BY s.id`, strings.ToLower(host))
	return scanSite(row)
}

func (s *Store) GetSite(ctx context.Context, id string) (*SiteRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT s.id, s.host, s.title, s.summary, count(i.id), s.created_at, s.updated_at
		FROM sites s LEFT JOIN items i ON i.site_id = s.id WHERE s.id = ? GROUP BY s.id`, id)
	return scanSite(row)
}

func (s *Store) GetSiteVisible(ctx context.Context, id string, user *UserRecord) (*SiteRecord, error) {
	userID, isAdmin := accessArgs(user)
	row := s.db.QueryRowContext(ctx, `SELECT s.id, s.host, s.title, s.summary, count(i.id), s.created_at, s.updated_at
		FROM sites s
		JOIN items i ON i.site_id = s.id
		JOIN captures c ON c.id = i.capture_id
		WHERE s.id = ? AND (? = 1 OR c.owner_user_id = ? OR c.visibility = 'public')
		GROUP BY s.id`, id, boolInt(isAdmin), userID)
	return scanSite(row)
}

func (s *Store) DeleteSite(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sites WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SiteVisibility(ctx context.Context, siteID string) (string, error) {
	var total, public int
	err := s.db.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(CASE WHEN visibility = 'public' THEN 1 ELSE 0 END), 0)
		FROM captures WHERE site_id = ?`, siteID).Scan(&total, &public)
	if err != nil {
		return VisibilityPrivate, err
	}
	if total > 0 && total == public {
		return VisibilityPublic, nil
	}
	return VisibilityPrivate, nil
}

func (s *Store) CanManageSite(ctx context.Context, siteID string, user *UserRecord) (bool, error) {
	if user == nil {
		return false, nil
	}
	if user.IsAdmin {
		return true, nil
	}
	var total, owned int
	err := s.db.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(CASE WHEN owner_user_id = ? THEN 1 ELSE 0 END), 0)
		FROM captures WHERE site_id = ?`, user.ID, siteID).Scan(&total, &owned)
	return total > 0 && total == owned, err
}

func (s *Store) UpdateSiteVisibility(ctx context.Context, siteID, visibility string) error {
	visibility = normalizeVisibility(visibility)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE captures SET visibility = ? WHERE site_id = ?`, visibility, siteID)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE archive_jobs SET visibility = ? WHERE capture_id IN (SELECT id FROM captures WHERE site_id = ?)`, visibility, siteID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecordSiteFailure(ctx context.Context, siteID, jobID, rawURL, failure string) error {
	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, `INSERT INTO site_failures(site_id, job_id, url, error, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(site_id, url) DO UPDATE SET job_id = excluded.job_id, error = excluded.error, updated_at = excluded.updated_at`,
		siteID, jobID, rawURL, failure, now, now)
	return err
}

func (s *Store) ClearSiteFailure(ctx context.Context, siteID, rawURL string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM site_failures WHERE site_id = ? AND url = ?`, siteID, rawURL)
	return err
}

func (s *Store) ListSiteFailures(ctx context.Context, siteID string) ([]SiteFailureRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT site_id, job_id, url, error, created_at, updated_at
		FROM site_failures WHERE site_id = ? ORDER BY url`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SiteFailureRecord{}
	for rows.Next() {
		var rec SiteFailureRecord
		var created, updated string
		if err := rows.Scan(&rec.SiteID, &rec.JobID, &rec.URL, &rec.Error, &created, &updated); err != nil {
			return nil, err
		}
		rec.CreatedAt, _ = parseTime(created)
		rec.UpdatedAt, _ = parseTime(updated)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) ListSites(ctx context.Context, limit int) ([]SiteRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.host, s.title, s.summary, count(i.id), s.created_at, s.updated_at
		FROM sites s LEFT JOIN items i ON i.site_id = s.id GROUP BY s.id ORDER BY s.updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SiteRecord
	for rows.Next() {
		rec, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) ListSitesVisible(ctx context.Context, user *UserRecord, limit int) ([]SiteRecord, error) {
	userID, isAdmin := accessArgs(user)
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.host, s.title, s.summary, count(i.id), s.created_at, s.updated_at
		FROM sites s
		JOIN items i ON i.site_id = s.id
		JOIN captures c ON c.id = i.capture_id
		WHERE ? = 1 OR c.owner_user_id = ? OR c.visibility = 'public'
		GROUP BY s.id
		ORDER BY s.updated_at DESC LIMIT ?`, boolInt(isAdmin), userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SiteRecord
	for rows.Next() {
		rec, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func scanSite(row interface{ Scan(dest ...any) error }) (*SiteRecord, error) {
	var rec SiteRecord
	var created, updated string
	if err := row.Scan(&rec.ID, &rec.Host, &rec.Title, &rec.Summary, &rec.ItemCount, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) CreateCapture(ctx context.Context, jobID, siteID, ownerUserID, startURL, title, warcPath, visibility string) (*CaptureRecord, error) {
	now := time.Now().UTC()
	rec := &CaptureRecord{
		ID:         uuid.NewString(),
		JobID:      jobID,
		SiteID:     siteID,
		StartURL:   startURL,
		WARCPath:   warcPath,
		Visibility: normalizeVisibility(visibility),
		CreatedAt:  now,
	}
	if ownerUserID != "" {
		rec.OwnerUserID = sql.NullString{String: ownerUserID, Valid: true}
	}
	if title != "" {
		rec.Title = sql.NullString{String: title, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO captures(id, job_id, site_id, owner_user_id, start_url, title, warc_path, visibility, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.JobID, rec.SiteID, rec.OwnerUserID, rec.StartURL, rec.Title, rec.WARCPath, rec.Visibility, formatTime(now))
	return rec, err
}

func (s *Store) GetCapture(ctx context.Context, id string) (*CaptureRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, job_id, site_id, owner_user_id, start_url, title, warc_path, visibility, created_at FROM captures WHERE id = ?`, id)
	return scanCapture(row)
}

func (s *Store) GetCaptureVisible(ctx context.Context, id string, user *UserRecord) (*CaptureRecord, error) {
	userID, isAdmin := accessArgs(user)
	row := s.db.QueryRowContext(ctx, `SELECT id, job_id, site_id, owner_user_id, start_url, title, warc_path, visibility, created_at
		FROM captures WHERE id = ? AND (? = 1 OR owner_user_id = ? OR visibility = 'public')`, id, boolInt(isAdmin), userID)
	return scanCapture(row)
}

func (s *Store) UpdateCaptureVisibility(ctx context.Context, id, visibility string) (*CaptureRecord, error) {
	visibility = normalizeVisibility(visibility)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE captures SET visibility = ? WHERE id = ?`, visibility, id)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE archive_jobs SET visibility = ? WHERE capture_id = ?`, visibility, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCapture(ctx, id)
}

func scanCapture(row interface{ Scan(dest ...any) error }) (*CaptureRecord, error) {
	var rec CaptureRecord
	var created string
	if err := row.Scan(&rec.ID, &rec.JobID, &rec.SiteID, &rec.OwnerUserID, &rec.StartURL, &rec.Title, &rec.WARCPath, &rec.Visibility, &created); err != nil {
		return nil, err
	}
	t, err := parseTime(created)
	if err != nil {
		return nil, err
	}
	rec.CreatedAt = t
	rec.Visibility = normalizeVisibility(rec.Visibility)
	return &rec, nil
}

func (s *Store) GetCaptureByWARCID(ctx context.Context, id string) (*CaptureRecord, error) {
	return s.GetCapture(ctx, id)
}

func (s *Store) CreateItem(ctx context.Context, rec ItemRecord) (*ItemRecord, error) {
	now := time.Now().UTC()
	rec.ID = uuid.NewString()
	rec.CreatedAt = now
	if rec.TagsJSON == "" {
		rec.TagsJSON = "[]"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO items(
			id, job_id, capture_id, site_id, url, canonical_url, title, summary, tags_json,
			replayable, depth, status_code, content_type, markdown_path, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.JobID, rec.CaptureID, rec.SiteID, rec.URL, rec.CanonicalURL, rec.Title,
		rec.Summary, rec.TagsJSON, boolInt(rec.Replayable), rec.Depth, rec.StatusCode, rec.ContentType, rec.MarkdownPath,
		formatTime(now))
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) ReplaceItem(ctx context.Context, itemID string, rec ItemRecord) (*ItemRecord, error) {
	now := time.Now().UTC()
	if rec.TagsJSON == "" {
		rec.TagsJSON = "[]"
	}
	res, err := s.db.ExecContext(ctx, `UPDATE items SET
			job_id = ?, capture_id = ?, site_id = ?, url = ?, canonical_url = ?, title = ?, summary = ?, tags_json = ?,
			replayable = ?, depth = ?, status_code = ?, content_type = ?, markdown_path = ?, created_at = ?
		WHERE id = ?`,
		rec.JobID, rec.CaptureID, rec.SiteID, rec.URL, rec.CanonicalURL, rec.Title, rec.Summary, rec.TagsJSON,
		boolInt(rec.Replayable), rec.Depth, rec.StatusCode, rec.ContentType, rec.MarkdownPath, formatTime(now), itemID)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, sql.ErrNoRows
	}
	return s.GetItem(ctx, itemID)
}

func (s *Store) SetItemMarkdownPath(ctx context.Context, itemID, path string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE items SET markdown_path = ? WHERE id = ?`, path, itemID)
	return err
}

func (s *Store) SetItemSearchText(ctx context.Context, itemID, text string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE items SET search_text = ? WHERE id = ?`, text, itemID)
	return err
}

func (s *Store) UpdateItemEnrichment(ctx context.Context, itemID, summary string, tags []string) error {
	rawTags, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE items SET summary = ?, tags_json = ? WHERE id = ?`, summary, string(rawTags), itemID)
	return err
}

func (s *Store) GetItem(ctx context.Context, id string) (*ItemRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, job_id, capture_id, site_id, url, canonical_url, title, summary, tags_json,
			replayable, depth, status_code, content_type, markdown_path, created_at FROM items WHERE id = ?`, id)
	return scanItem(row)
}

func (s *Store) GetItemVisible(ctx context.Context, id string, user *UserRecord) (*ItemRecord, error) {
	userID, isAdmin := accessArgs(user)
	row := s.db.QueryRowContext(ctx, `SELECT i.id, i.job_id, i.capture_id, i.site_id, i.url, i.canonical_url, i.title, i.summary, i.tags_json,
			i.replayable, i.depth, i.status_code, i.content_type, i.markdown_path, i.created_at
		FROM items i
		JOIN captures c ON c.id = i.capture_id
		WHERE i.id = ? AND (? = 1 OR c.owner_user_id = ? OR c.visibility = 'public')`, id, boolInt(isAdmin), userID)
	return scanItem(row)
}

func (s *Store) DeleteItem(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM items WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListItems(ctx context.Context, siteID, query string, limit int) ([]ItemRecord, error) {
	args := []any{}
	where := []string{"1=1"}
	if siteID != "" {
		where = append(where, "site_id = ?")
		args = append(args, siteID)
	}
	if strings.TrimSpace(query) != "" {
		where = append(where, "(url LIKE ? OR title LIKE ? OR summary LIKE ? OR search_text LIKE ?)")
		q := "%" + strings.TrimSpace(query) + "%"
		args = append(args, q, q, q, q)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id, job_id, capture_id, site_id, url, canonical_url, title, summary, tags_json,
			replayable, depth, status_code, content_type, markdown_path, created_at FROM items WHERE `+strings.Join(where, " AND ")+` ORDER BY created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemRecord
	for rows.Next() {
		rec, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) ListItemsVisible(ctx context.Context, user *UserRecord, siteID, query string, limit int) ([]ItemRecord, error) {
	userID, isAdmin := accessArgs(user)
	args := []any{boolInt(isAdmin), userID}
	where := []string{"(? = 1 OR c.owner_user_id = ? OR c.visibility = 'public')"}
	if siteID != "" {
		where = append(where, "i.site_id = ?")
		args = append(args, siteID)
	}
	if strings.TrimSpace(query) != "" {
		where = append(where, "(i.url LIKE ? OR i.title LIKE ? OR i.summary LIKE ? OR i.search_text LIKE ?)")
		q := "%" + strings.TrimSpace(query) + "%"
		args = append(args, q, q, q, q)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT i.id, i.job_id, i.capture_id, i.site_id, i.url, i.canonical_url, i.title, i.summary, i.tags_json,
			i.replayable, i.depth, i.status_code, i.content_type, i.markdown_path, i.created_at
		FROM items i
		JOIN captures c ON c.id = i.capture_id
		WHERE `+strings.Join(where, " AND ")+` ORDER BY i.created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemRecord
	for rows.Next() {
		rec, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) ListItemsForSite(ctx context.Context, siteID string, limit int) ([]ItemRecord, error) {
	return s.ListItems(ctx, siteID, "", limit)
}

func (s *Store) ListItemsForSiteVisible(ctx context.Context, siteID string, user *UserRecord, limit int) ([]ItemRecord, error) {
	return s.ListItemsVisible(ctx, user, siteID, "", limit)
}

func (s *Store) ListItemsForJob(ctx context.Context, jobID string) ([]ItemRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, job_id, capture_id, site_id, url, canonical_url, title, summary, tags_json,
			replayable, depth, status_code, content_type, markdown_path, created_at FROM items WHERE job_id = ? ORDER BY depth ASC, created_at ASC`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemRecord
	for rows.Next() {
		rec, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) ListItemsForJobVisible(ctx context.Context, jobID string, user *UserRecord) ([]ItemRecord, error) {
	userID, isAdmin := accessArgs(user)
	rows, err := s.db.QueryContext(ctx, `SELECT i.id, i.job_id, i.capture_id, i.site_id, i.url, i.canonical_url, i.title, i.summary, i.tags_json,
			i.replayable, i.depth, i.status_code, i.content_type, i.markdown_path, i.created_at
		FROM items i
		JOIN captures c ON c.id = i.capture_id
		WHERE i.job_id = ? AND (? = 1 OR c.owner_user_id = ? OR c.visibility = 'public')
		ORDER BY i.depth ASC, i.created_at ASC`, jobID, boolInt(isAdmin), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemRecord
	for rows.Next() {
		rec, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func scanItem(row interface{ Scan(dest ...any) error }) (*ItemRecord, error) {
	var rec ItemRecord
	var created string
	var replayable int
	if err := row.Scan(&rec.ID, &rec.JobID, &rec.CaptureID, &rec.SiteID, &rec.URL, &rec.CanonicalURL,
		&rec.Title, &rec.Summary, &rec.TagsJSON, &replayable, &rec.Depth, &rec.StatusCode, &rec.ContentType,
		&rec.MarkdownPath, &created); err != nil {
		return nil, err
	}
	t, err := parseTime(created)
	if err != nil {
		return nil, err
	}
	rec.Replayable = replayable != 0
	rec.CreatedAt = t
	return &rec, nil
}

func (s *Store) MarkdownPath(captureID, itemID string) string {
	return filepath.Join(s.dataDir, "markdown", captureID, itemID+".md")
}

func (s *Store) WARCPath(filename string) string {
	return filepath.Join(s.dataDir, "warcs", filename)
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(raw string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, raw)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func accessArgs(user *UserRecord) (string, bool) {
	if user == nil {
		return "", false
	}
	return user.ID, user.IsAdmin
}

func normalizeVisibility(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), VisibilityPublic) {
		return VisibilityPublic
	}
	return VisibilityPrivate
}
