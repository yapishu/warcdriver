package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const sessionCookieName = "warcdriver_session"

type contextKey string

const userContextKey contextKey = "warcdriver_user"

func bootstrapAdmin(ctx context.Context, store *Store) error {
	n, err := store.UserCount(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	email := strings.TrimSpace(getenv("WARC_ADMIN_EMAIL", ""))
	username := strings.TrimSpace(getenv("WARC_ADMIN_USERNAME", ""))
	if username == "" && email != "" {
		username = usernameFromEmailOrID(email, "admin")
	}
	if username == "" {
		username = "admin"
	}
	displayName := getenv("WARC_ADMIN_NAME", username)
	password := getenv("WARC_ADMIN_PASSWORD", "")
	generated := false
	if password == "" {
		var err error
		password, err = randomToken(24)
		if err != nil {
			return err
		}
		generated = true
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	user, err := store.CreateUser(ctx, username, email, displayName, hash)
	if err != nil {
		return err
	}
	if generated {
		log.Printf("created first admin user %s with generated password: %s", user.Username, password)
	} else {
		log.Printf("created first admin user %s from WARC_ADMIN_PASSWORD", user.Username)
	}

	apiToken := getenv("WARC_API_TOKEN", "")
	if apiToken != "" {
		if err := store.CreateAPIToken(ctx, user.ID, "bootstrap", hashToken(apiToken), tokenPrefix(apiToken)); err != nil {
			return err
		}
		log.Printf("seeded bootstrap API token from WARC_API_TOKEN")
	}
	return nil
}

func userFromContext(ctx context.Context) (*UserRecord, bool) {
	u, ok := ctx.Value(userContextKey).(*UserRecord)
	return u, ok
}

func withUser(ctx context.Context, user *UserRecord) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	memory := uint32(64 * 1024)
	iterations := uint32(3)
	parallelism := uint8(1)
	keyLen := uint32(32)
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var version int
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func tokenPrefix(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

func sessionCookie(token string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func expiredSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
