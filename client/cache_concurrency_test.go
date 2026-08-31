package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stremovskyy/orionis"
)

func TestProviderCoalescesConcurrentTokenRequests(t *testing.T) {
	const callers = 16

	var hits atomic.Int32
	var startedOnce sync.Once
	var releaseOnce sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	releaseRequest := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseRequest()

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		writeTokenResponse(w, "shared-token", 900)
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "secret").For("api", "scope.read").Must()
	key := cacheKey("api", []string{"scope.read"})
	results := make(chan error, callers)
	begin := make(chan struct{})

	for range callers {
		go func() {
			<-begin
			token, err := provider.Token(context.Background(), "", nil)

			if err == nil && token != "shared-token" {
				err = errors.New("unexpected token")
			}

			results <- err
		}()
	}

	close(begin)
	waitForSignal(t, started, "token request")
	waitForWaiters(t, provider, key, callers)
	releaseRequest()

	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("token endpoint hits = %d, want 1", got)
	}
}

func TestLeaderCancellationDoesNotCancelRemainingWaiter(t *testing.T) {
	var hits atomic.Int32
	var releaseOnce sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	releaseRequest := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseRequest()

	requestCanceled := make(chan struct{}, 1)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		close(started)

		select {
		case <-release:
			writeTokenResponse(w, "follower-token", 900)
		case <-req.Context().Done():
			requestCanceled <- struct{}{}
		}
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "secret").For("api").Must()
	key := cacheKey("api", nil)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	followerResult := make(chan error, 1)

	go func() {
		_, err := provider.Token(leaderCtx, "", nil)
		leaderResult <- err
	}()

	waitForSignal(t, started, "leader token request")

	go func() {
		token, err := provider.Token(context.Background(), "", nil)

		if err == nil && token != "follower-token" {
			err = errors.New("unexpected token")
		}

		followerResult <- err
	}()

	waitForWaiters(t, provider, key, 2)
	cancelLeader()

	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}

	select {
	case <-requestCanceled:
		t.Fatal("leader cancellation canceled the shared HTTP request")
	case <-time.After(50 * time.Millisecond):
	}

	releaseRequest()

	if err := <-followerResult; err != nil {
		t.Fatal(err)
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("token endpoint hits = %d, want 1", got)
	}
}

func TestLastWaiterCancellationCancelsRequestAndAllowsRetry(t *testing.T) {
	var hits atomic.Int32
	firstStarted := make(chan struct{})
	firstCanceled := make(chan struct{})
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if hits.Add(1) == 1 {
			close(firstStarted)
			<-req.Context().Done()
			close(firstCanceled)

			return nil, req.Context().Err()
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"access_token":"retry-token","token_type":"Bearer","expires_in":900}`,
			)),
			Request: req,
		}, nil
	})}

	provider := New().
		TokenURL("https://auth.example.test/oauth/token").
		As("client", "secret").
		For("api").
		TokenHTTPClient(httpClient).
		Must()
	ctx, cancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)

	go func() {
		_, err := provider.Token(ctx, "", nil)
		firstResult <- err
	}()

	waitForSignal(t, firstStarted, "first token request")
	cancel()

	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("first error = %v, want context.Canceled", err)
	}

	waitForSignal(t, firstCanceled, "HTTP request cancellation")

	token, err := provider.Token(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}

	if token != "retry-token" {
		t.Fatalf("token = %q", token)
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("token endpoint hits = %d, want 2", got)
	}
}

func TestCachePurgesStaleEntries(t *testing.T) {
	t.Parallel()

	provider := New().TokenURL("https://auth.example.test/oauth/token").RefreshSkew(time.Second).Must()
	now := time.Now()
	expiredKey := cacheKey("expired", nil)
	freshKey := cacheKey("fresh", nil)
	provider.cache[expiredKey] = cachedToken{
		response:  orionis.TokenResponse{AccessToken: "expired", ExpiresIn: 60},
		expiresAt: now.Add(-time.Second),
	}
	provider.cache[freshKey] = cachedToken{
		response:  orionis.TokenResponse{AccessToken: "fresh", ExpiresIn: 60},
		expiresAt: now.Add(time.Minute),
	}

	token, ok := provider.cached(freshKey)

	if !ok || token.response.AccessToken != "fresh" {
		t.Fatalf("fresh token = %#v, %t", token, ok)
	}

	provider.mu.Lock()
	_, expiredStillCached := provider.cache[expiredKey]
	provider.mu.Unlock()

	if expiredStillCached {
		t.Fatal("expired cache entry was not removed")
	}
}

func TestTokenCacheKeyCannotCollideAcrossAudienceAndScope(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		hits.Add(1)

		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}

		writeTokenResponse(w, "token-for-"+request.Form.Get("audience"), 900)
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "secret").Must()

	first, err := provider.Token(context.Background(), "a|b", []string{"c"})
	if err != nil {
		t.Fatal(err)
	}

	second, err := provider.Token(context.Background(), "a", []string{"b|c"})
	if err != nil {
		t.Fatal(err)
	}

	if first != "token-for-a|b" || second != "token-for-a" {
		t.Fatalf("tokens = %q, %q; cache targets collided", first, second)
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("token endpoint hits = %d, want 2", got)
	}
}

func TestPreCanceledContextDoesNotStartTokenRequest(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writeTokenResponse(w, "token", 900)
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "secret").For("api").Must()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := provider.Token(ctx, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}

	if got := hits.Load(); got != 0 {
		t.Fatalf("token endpoint hits = %d, want 0", got)
	}
}

func waitForWaiters(t *testing.T, provider *Provider, key tokenCacheKey, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		provider.mu.Lock()
		call := provider.inflight[key]
		got := 0

		if call != nil {
			got = call.waiters
		}

		provider.mu.Unlock()

		if got == want {
			return
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatalf("inflight waiter count did not reach %d", want)
}

func waitForSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}
