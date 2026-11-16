package datasource

import (
	"errors"
	"testing"
	"time"
)

func TestOAuthStateIsSingleUseAndAttemptOutlivesIt(t *testing.T) {
	store := NewOAuthStateStore(nil)
	ctx := t.Context()
	want := OAuthState{
		TenantID: 7, DataSourceID: "ds-1", CodeVerifier: "verifier",
		RedirectURI: "https://kb.example/api/v1/datasource-oauth/callback", FrontendRedirect: "/",
	}
	if err := store.Put(ctx, "state-1", want); err != nil {
		t.Fatal(err)
	}
	if attempt, err := store.Attempt(ctx, "state-1"); err != nil || attempt.Completed ||
		attempt.TenantID != 7 || attempt.DataSourceID != "ds-1" {
		t.Fatalf("open attempt = %+v, %v", attempt, err)
	}
	got, err := store.Take(ctx, "state-1")
	if err != nil || got != want {
		t.Fatalf("Take = %+v, %v", got, err)
	}
	if _, err := store.Take(ctx, "state-1"); !errors.Is(err, ErrOAuthStateNotFound) {
		t.Fatalf("a state must be redeemable once: %v", err)
	}
	if err := store.CompleteAttempt(ctx, "state-1"); err != nil {
		t.Fatal(err)
	}
	if attempt, err := store.Attempt(ctx, "state-1"); err != nil || !attempt.Completed {
		t.Fatalf("completed attempt = %+v, %v", attempt, err)
	}
	if _, err := store.Attempt(ctx, "unknown"); !errors.Is(err, ErrOAuthStateNotFound) {
		t.Fatalf("unknown attempt = %v", err)
	}
	if err := store.CompleteAttempt(ctx, "unknown"); !errors.Is(err, ErrOAuthStateNotFound) {
		t.Fatalf("completing an unknown attempt = %v", err)
	}
}

func TestOAuthStateExpires(t *testing.T) {
	store := NewOAuthStateStore(nil)
	ctx := t.Context()
	if err := store.Put(ctx, "old", OAuthState{DataSourceID: "ds-1"}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for key, entry := range store.mem {
		entry.expiresAt = time.Now().Add(-time.Second)
		store.mem[key] = entry
	}
	store.mu.Unlock()
	if _, err := store.Attempt(ctx, "old"); !errors.Is(err, ErrOAuthStateNotFound) {
		t.Fatalf("expired attempt = %v", err)
	}
	if _, err := store.Take(ctx, "old"); !errors.Is(err, ErrOAuthStateNotFound) {
		t.Fatalf("expired state = %v", err)
	}
	// Expired entries are swept by the next write.
	if err := store.Put(ctx, "new", OAuthState{DataSourceID: "ds-2"}); err != nil || len(store.mem) != 2 {
		t.Fatalf("sweep left %d entries, %v", len(store.mem), err)
	}
}
