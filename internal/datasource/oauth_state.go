package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// oauthStateTTL bounds how long an authorization may take from "authorize URL
// issued" to "callback received".
const oauthStateTTL = 10 * time.Minute

// ErrOAuthStateNotFound means the state is unknown, already used or expired.
var ErrOAuthStateNotFound = errors.New("oauth state not found or expired")

// OAuthState is the transient data needed to complete an authorization-code
// exchange. It is keyed by the opaque OAuth state parameter and holds the PKCE
// verifier, a secret that must never reach the browser or the provider's
// authorization endpoint, hence server-side storage.
type OAuthState struct {
	TenantID         uint64 `json:"tenant_id"`
	DataSourceID     string `json:"data_source_id"`
	CodeVerifier     string `json:"code_verifier"`
	RedirectURI      string `json:"redirect_uri"`
	FrontendRedirect string `json:"frontend_redirect"`
}

// OAuthAttempt is the non-secret status of one authorization flow. It outlives
// the state, which is consumed before the code exchange finishes, so the page
// that opened the flow can tell this attempt from an older grant.
type OAuthAttempt struct {
	TenantID     uint64 `json:"tenant_id"`
	DataSourceID string `json:"data_source_id"`
	Completed    bool   `json:"completed"`
}

// OAuthStateStore persists in-flight authorizations. It is backed by Redis
// when available, so the callback can land on any replica, and by a TTL map in
// single-instance deployments.
type OAuthStateStore struct {
	rdb *redis.Client

	mu  sync.Mutex
	mem map[string]oauthMemEntry
}

type oauthMemEntry struct {
	value     []byte
	expiresAt time.Time
}

// NewOAuthStateStore creates a store. rdb may be nil.
func NewOAuthStateStore(rdb *redis.Client) *OAuthStateStore {
	return &OAuthStateStore{rdb: rdb, mem: make(map[string]oauthMemEntry)}
}

func oauthStateKey(state string) string {
	if ns := strings.TrimSpace(os.Getenv("WEKNORA_REDIS_NAMESPACE")); ns != "" {
		return "weknora:datasource_oauth_state:" + ns + ":" + state
	}
	return "weknora:datasource_oauth_state:" + state
}

func oauthAttemptKey(state string) string { return oauthStateKey(state) + ":attempt" }

func (s *OAuthStateStore) set(ctx context.Context, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if s.rdb != nil {
		return s.rdb.Set(ctx, key, data, oauthStateTTL).Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, entry := range s.mem {
		if now.After(entry.expiresAt) {
			delete(s.mem, k)
		}
	}
	s.mem[key] = oauthMemEntry{value: data, expiresAt: now.Add(oauthStateTTL)}
	return nil
}

// read loads a value; with consume set it is removed atomically, so a state
// can be redeemed only once even when two callbacks race.
func (s *OAuthStateStore) read(ctx context.Context, key string, consume bool, out any) error {
	var data []byte
	if s.rdb != nil {
		cmd := s.rdb.Get(ctx, key)
		if consume {
			cmd = s.rdb.GetDel(ctx, key)
		}
		raw, err := cmd.Bytes()
		if errors.Is(err, redis.Nil) {
			return ErrOAuthStateNotFound
		}
		if err != nil {
			return err
		}
		data = raw
	} else {
		s.mu.Lock()
		entry, ok := s.mem[key]
		if consume || (ok && time.Now().After(entry.expiresAt)) {
			delete(s.mem, key)
		}
		s.mu.Unlock()
		if !ok || time.Now().After(entry.expiresAt) {
			return ErrOAuthStateNotFound
		}
		data = entry.value
	}
	return json.Unmarshal(data, out)
}

// Put stores a state and opens its attempt record.
func (s *OAuthStateStore) Put(ctx context.Context, state string, value OAuthState) error {
	attempt := OAuthAttempt{TenantID: value.TenantID, DataSourceID: value.DataSourceID}
	if err := s.set(ctx, oauthAttemptKey(state), attempt); err != nil {
		return err
	}
	return s.set(ctx, oauthStateKey(state), value)
}

// Take retrieves and deletes a state.
func (s *OAuthStateStore) Take(ctx context.Context, state string) (OAuthState, error) {
	var value OAuthState
	err := s.read(ctx, oauthStateKey(state), true, &value)
	return value, err
}

// Attempt returns the status record of one authorization flow.
func (s *OAuthStateStore) Attempt(ctx context.Context, state string) (OAuthAttempt, error) {
	var attempt OAuthAttempt
	err := s.read(ctx, oauthAttemptKey(state), false, &attempt)
	return attempt, err
}

// CompleteAttempt marks an attempt complete. It must be called only after the
// exchanged credentials have been persisted.
func (s *OAuthStateStore) CompleteAttempt(ctx context.Context, state string) error {
	attempt, err := s.Attempt(ctx, state)
	if err != nil {
		return err
	}
	attempt.Completed = true
	return s.set(ctx, oauthAttemptKey(state), attempt)
}
