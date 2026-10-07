// Package apiauth authenticates /internal/* HTTP calls with platform API tokens
// (api_clients / api_tokens, 0001) and authorizes them with the same role
// permissions the console uses (roles.permissions, 0003).
//
// A request carries "Authorization: Bearer aeg_...". Only the SHA-256 of the
// token is stored (token_hash) - tokens are 256-bit random, so a fast hash is
// the right tool here (Argon2 is for low-entropy passwords). A permission is
// granted only if BOTH the client's role and the token's scopes allow it
// ("*" matches anything), so a token can be narrower than its client's role but
// never wider.
package apiauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const tokenPrefix = "aeg_"

// Permission names. Existing ones come from 0003_seed_roles.sql; AgentCommand is
// new and is held by no seeded role except admin ("*") - running arbitrary
// commands on endpoints is admin-only by default.
const (
	PermPatchDeploy  = "patch.deploy"
	PermReportsView  = "reports.view"
	PermAgentCommand = "agent.command"
	// PermContentDownload lets IT tooling (not agents - they use their mTLS
	// cert) fetch redistributable content such as the scan cab. Admin-only by
	// default, like agent.command.
	PermContentDownload = "content.download"
)

type Principal struct {
	ClientID   string
	ClientName string
	TokenID    string
	rolePerms  map[string]bool
	scopes     []string
}

func (p Principal) Can(perm string) bool {
	roleOK := p.rolePerms["*"] || p.rolePerms[perm]
	scopeOK := false
	for _, s := range p.scopes {
		if s == "*" || s == perm {
			scopeOK = true
			break
		}
	}
	return roleOK && scopeOK
}

type ctxKey struct{}

func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// NewToken returns a fresh raw token and the hash to store.
func NewToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, HashToken(raw), nil
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

type Authenticator struct {
	pool  *pgxpool.Pool // nil when no database is configured
	log   *slog.Logger
	limit *limiter
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Authenticator {
	return &Authenticator{pool: pool, log: log, limit: newLimiter()}
}

// WriteRateLimited sends 429 with Retry-After for a RateLimitedError.
func WriteRateLimited(w http.ResponseWriter, e *RateLimitedError) {
	w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfterSeconds()))
	http.Error(w, "rate limit exceeded for this API client", http.StatusTooManyRequests)
}

// ErrUnauthenticated: no token, or a token that is unknown, expired, revoked, or
// belongs to a disabled client.
var ErrUnauthenticated = errors.New("unauthenticated")

// Require wraps next so it only runs for an authenticated caller holding perm.
// Pass perm "" when the handler checks permissions itself (e.g. push, where the
// required permission depends on the command type).
func (a *Authenticator) Require(perm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.pool == nil {
			http.Error(w, "database required for API authentication", http.StatusServiceUnavailable)
			return
		}
		p, err := a.Authenticate(r)
		if err != nil {
			var rl *RateLimitedError
			if errors.As(err, &rl) {
				WriteRateLimited(w, rl)
				return
			}
			if !errors.Is(err, ErrUnauthenticated) {
				a.log.Error("api auth lookup failed", "error", err.Error())
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
				return
			}
			a.log.Warn("api auth rejected", "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="aegis"`)
			http.Error(w, "missing, invalid, expired or revoked API token", http.StatusUnauthorized)
			return
		}
		if perm != "" && !p.Can(perm) {
			Deny(w, a.log, p, perm, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// Deny writes a 403 for an authenticated caller lacking perm, and logs it.
func Deny(w http.ResponseWriter, log *slog.Logger, p Principal, perm string, r *http.Request) {
	log.Warn("api permission denied", "client", p.ClientName, "permission", perm, "path", r.URL.Path)
	http.Error(w, "forbidden: this token needs the '"+perm+"' permission", http.StatusForbidden)
}

// Authenticate resolves the bearer token on r, for handlers that accept more
// than one kind of credential (e.g. agent cert OR token).
func (a *Authenticator) Authenticate(r *http.Request) (Principal, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	raw = strings.TrimSpace(raw)
	if !ok || !strings.HasPrefix(raw, tokenPrefix) {
		return Principal{}, ErrUnauthenticated
	}

	var p Principal
	var permsJSON []byte
	var perMinute int
	err := a.pool.QueryRow(r.Context(), `
		SELECT t.id, c.id, c.name, r.permissions, t.scopes, c.rate_limit_per_minute
		FROM api_tokens t
		JOIN api_clients c ON c.id = t.api_client_id
		JOIN roles r ON r.id = c.role_id
		WHERE t.token_hash = $1
		  AND t.revoked_at IS NULL AND t.expires_at > now()
		  AND c.disabled_at IS NULL`, HashToken(raw),
	).Scan(&p.TokenID, &p.ClientID, &p.ClientName, &permsJSON, &p.scopes, &perMinute)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, err
	}
	if err := json.Unmarshal(permsJSON, &p.rolePerms); err != nil {
		return Principal{}, err
	}

	// Per client (all its tokens share one bucket), before any permission check,
	// so denied requests count too.
	if ok, retry, warn := a.limit.allow(p.ClientID, perMinute); !ok {
		if warn {
			a.log.Warn("api rate limit exceeded", "client", p.ClientName, "limit_per_minute", perMinute, "path", r.URL.Path)
		}
		return Principal{}, &RateLimitedError{RetryAfter: retry}
	}

	// Throttled so a busy client doesn't turn every request into a write.
	if _, err := a.pool.Exec(r.Context(), `
		UPDATE api_tokens SET last_used_at = now()
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, p.TokenID); err != nil {
		a.log.Warn("could not update api token last_used_at", "error", err.Error())
	}
	return p, nil
}
