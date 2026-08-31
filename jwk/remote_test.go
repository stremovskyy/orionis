/*
 * MIT License
 *
 * Copyright (c) 2022-2026 Anton Stremovskyy <stremovskyy@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package jwk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis/internal/httpjson"
)

func TestRemoteProviderFetchTriggersAndAlgorithmPolicy(t *testing.T) {
	t.Parallel()

	first, _ := testEd25519JWK(t, "first")
	second, _ := testEd25519JWK(t, "second")
	var requests atomic.Int64
	var mu sync.RWMutex
	current := Set{Keys: []Key{first}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)

		if request.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", request.Method)
		}

		if request.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want application/json", request.Header.Get("Accept"))
		}

		mu.RLock()
		defer mu.RUnlock()

		_ = json.NewEncoder(w).Encode(current)
	}))
	defer server.Close()

	provider, err := Remote(server.URL).
		RefreshEvery(time.Hour).
		MaxStale(2 * time.Hour).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Key(context.Background(), "first", jwt.SigningMethodEdDSA.Alg()); err != nil {
		t.Fatal(err)
	}

	if requests.Load() != 1 {
		t.Fatalf("lazy fetch request count = %d, want 1", requests.Load())
	}

	if _, err := provider.Key(context.Background(), "first", jwt.SigningMethodEdDSA.Alg()); err != nil {
		t.Fatal(err)
	}

	if requests.Load() != 1 {
		t.Fatalf("fresh-cache request count = %d, want 1", requests.Load())
	}

	_, err = provider.Key(context.Background(), "first", jwt.SigningMethodRS256.Alg())

	if err == nil || !strings.Contains(err.Error(), "declared for algorithm") {
		t.Fatalf("algorithm mismatch error = %v", err)
	}

	if requests.Load() != 1 {
		t.Fatalf("algorithm mismatch performed a request; count = %d", requests.Load())
	}

	_, err = provider.Key(context.Background(), "missing", jwt.SigningMethodEdDSA.Alg())

	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown kid error = %v, want ErrKeyNotFound", err)
	}

	if requests.Load() != 2 {
		t.Fatalf("unknown-kid request count = %d, want 2", requests.Load())
	}

	mu.Lock()
	current = Set{Keys: []Key{first, second}}
	mu.Unlock()

	if _, err := provider.Key(context.Background(), "second", jwt.SigningMethodEdDSA.Alg()); err != nil {
		t.Fatal(err)
	}

	if requests.Load() != 3 {
		t.Fatalf("rotated-kid request count = %d, want 3", requests.Load())
	}

	provider.mu.Lock()
	provider.expiresAt = time.Now().Add(-time.Second)
	provider.mu.Unlock()

	if _, err := provider.Key(context.Background(), "second", jwt.SigningMethodEdDSA.Alg()); err != nil {
		t.Fatal(err)
	}

	if requests.Load() != 4 {
		t.Fatalf("expired-cache request count = %d, want 4", requests.Load())
	}
}

func TestRemoteProviderCoalescesConcurrentExpiredRefresh(t *testing.T) {
	t.Parallel()

	key, _ := testEd25519JWK(t, "shared")
	var requests atomic.Int64
	refreshEntered := make(chan struct{})
	releaseRefresh := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestNumber := requests.Add(1)

		if requestNumber == 2 {
			close(refreshEntered)
			<-releaseRefresh
		}

		_ = json.NewEncoder(w).Encode(Set{Keys: []Key{key}})
	}))
	defer server.Close()

	provider, err := Remote(server.URL).RefreshEvery(time.Hour).Build()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Key(context.Background(), key.Kid, key.Alg); err != nil {
		t.Fatal(err)
	}

	provider.mu.Lock()
	provider.expiresAt = time.Now().Add(-time.Second)
	provider.mu.Unlock()

	const callers = 32
	start := make(chan struct{})
	errorsByCaller := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)

	for range callers {
		go func() {
			ready.Done()
			<-start
			_, err := provider.Key(context.Background(), key.Kid, key.Alg)
			errorsByCaller <- err
		}()
	}

	ready.Wait()
	close(start)
	<-refreshEntered

	for range callers {
		runtime.Gosched()
	}

	close(releaseRefresh)

	for range callers {
		if err := <-errorsByCaller; err != nil {
			t.Fatalf("concurrent Key failed: %v", err)
		}
	}

	if requests.Load() != 2 {
		t.Fatalf("request count = %d, want initial fetch plus one refresh", requests.Load())
	}
}

func TestRemoteProviderCoalescesFailedRefreshAttempt(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	provider, err := Remote(server.URL).Build()
	if err != nil {
		t.Fatal(err)
	}

	snapshot := provider.snapshot("missing", time.Now())
	const callers = 24
	start := make(chan struct{})
	results := make(chan error, callers)

	for range callers {
		go func() {
			<-start
			results <- provider.refreshIfUnchanged(
				context.Background(),
				snapshot.generation,
				snapshot.refreshVersion,
			)
		}()
	}

	close(start)

	for range callers {
		if err := <-results; err == nil || !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("refresh error = %v, want status 503", err)
		}
	}

	if requests.Load() != 1 {
		t.Fatalf("failed refresh request count = %d, want 1", requests.Load())
	}

	if err := provider.refreshIfUnchanged(
		context.Background(),
		provider.snapshot("missing", time.Now()).generation,
		provider.snapshot("missing", time.Now()).refreshVersion,
	); err == nil {
		t.Fatal("a later call must retry a failed completed refresh")
	}

	if requests.Load() != 2 {
		t.Fatalf("retry request count = %d, want 2", requests.Load())
	}
}

func TestRemoteProviderCoalescesHTTPClientTimeout(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		<-request.Context().Done()
	}))
	defer server.Close()

	provider, err := NewRemoteProvider(RemoteConfig{
		URL:        server.URL,
		HTTPClient: &http.Client{Timeout: 25 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}

	snapshot := provider.snapshot("missing", time.Now())
	const callers = 24
	start := make(chan struct{})
	results := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)

	for range callers {
		go func() {
			ready.Done()
			<-start
			results <- provider.refreshIfUnchanged(
				context.Background(),
				snapshot.generation,
				snapshot.refreshVersion,
			)
		}()
	}

	ready.Wait()
	close(start)

	for range callers {
		if err := <-results; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("refresh error = %v, want context.DeadlineExceeded", err)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("timeout refresh request count = %d, want 1", got)
	}

	retrySnapshot := provider.snapshot("missing", time.Now())
	err = provider.refreshIfUnchanged(
		context.Background(),
		retrySnapshot.generation,
		retrySnapshot.refreshVersion,
	)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("later retry error = %v, want context.DeadlineExceeded", err)
	}

	if got := requests.Load(); got != 2 {
		t.Fatalf("request count after a later retry = %d, want 2", got)
	}
}

func TestRemoteProviderStaleFallback(t *testing.T) {
	t.Parallel()

	key, _ := testEd25519JWK(t, "stale")
	var fail atomic.Bool
	var requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)

		if fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)

			return
		}

		_ = json.NewEncoder(w).Encode(Set{Keys: []Key{key}})
	}))
	defer server.Close()

	provider, err := Remote(server.URL).
		RefreshEvery(time.Minute).
		MaxStale(time.Hour).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Key(context.Background(), key.Kid, key.Alg); err != nil {
		t.Fatal(err)
	}

	fail.Store(true)

	provider.mu.Lock()
	provider.expiresAt = time.Now().Add(-time.Second)
	provider.mu.Unlock()

	if _, err := provider.Key(context.Background(), key.Kid, key.Alg); err != nil {
		t.Fatalf("valid stale key was not used: %v", err)
	}

	provider.mu.Lock()
	provider.fetchedAt = time.Now().Add(-provider.maxStale - time.Second)
	provider.mu.Unlock()

	_, err = provider.Key(context.Background(), key.Kid, key.Alg)

	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("expired stale cache error = %v, want status 503", err)
	}

	if requests.Load() != 3 {
		t.Fatalf("request count = %d, want 3", requests.Load())
	}
}

func TestRemoteProviderRejectsInvalidResponses(t *testing.T) {
	t.Parallel()

	valid, _ := testEd25519JWK(t, "valid")
	duplicate, _ := json.Marshal(Set{Keys: []Key{valid, valid}})
	blankKID, _ := json.Marshal(Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Kid = "" })}})
	wrongUse, _ := json.Marshal(Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Use = "enc" })}})
	wrongAlg, _ := json.Marshal(Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Alg = "RS256" })}})

	tests := []struct {
		name       string
		status     int
		body       string
		wantError  string
		wantTarget error
	}{
		{name: "status", status: http.StatusBadGateway, body: "upstream", wantError: "status 502"},
		{name: "malformed JSON", status: http.StatusOK, body: "{", wantError: "decode jwks"},
		{name: "trailing JSON", status: http.StatusOK, body: `{"keys":[]} {}`, wantTarget: httpjson.ErrTrailingData},
		{name: "empty set", status: http.StatusOK, body: `{"keys":[]}`, wantError: "no usable signing keys"},
		{name: "duplicate kid", status: http.StatusOK, body: string(duplicate), wantError: "duplicate jwk kid"},
		{name: "blank kid", status: http.StatusOK, body: string(blankKID), wantError: "without kid"},
		{name: "wrong use", status: http.StatusOK, body: string(wrongUse), wantError: "unsupported use"},
		{name: "wrong alg", status: http.StatusOK, body: string(wrongAlg), wantError: "incompatible"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			provider, err := NewRemoteProvider(RemoteConfig{URL: server.URL})
			if err != nil {
				t.Fatal(err)
			}

			err = provider.Refresh(context.Background())

			if test.wantTarget != nil {
				if !errors.Is(err, test.wantTarget) {
					t.Fatalf("error = %v, want %v", err, test.wantTarget)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRemoteProviderRefreshHonorsContext(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	provider, err := Remote(server.URL).Build()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = provider.Refresh(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh error = %v, want context.Canceled", err)
	}
}

func TestRemoteProviderCanceledLeaderDoesNotPoisonWaiter(t *testing.T) {
	t.Parallel()

	key, _ := testEd25519JWK(t, "rotation")
	var requests atomic.Int64
	firstRequest := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if requests.Add(1) == 1 {
			close(firstRequest)
			<-request.Context().Done()

			return
		}

		_ = json.NewEncoder(w).Encode(Set{Keys: []Key{key}})
	}))
	defer server.Close()

	provider, err := Remote(server.URL).Build()
	if err != nil {
		t.Fatal(err)
	}

	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	waiterResult := make(chan error, 1)

	go func() {
		_, err := provider.Key(leaderContext, key.Kid, key.Alg)
		leaderResult <- err
	}()

	<-firstRequest

	go func() {
		_, err := provider.Key(context.Background(), key.Kid, key.Alg)
		waiterResult <- err
	}()

	cancelLeader()

	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}

	if err := <-waiterResult; err != nil {
		t.Fatalf("live waiter inherited canceled leader error: %v", err)
	}

	if got := requests.Load(); got != 2 {
		t.Fatalf("request count = %d, want canceled request plus retry", got)
	}
}

func TestRemoteProviderCanceledLeaderRetriesWhenTransportReturnsCustomError(t *testing.T) {
	t.Parallel()

	key, _ := testEd25519JWK(t, "custom-transport")
	encoded, err := json.Marshal(Set{Keys: []Key{key}})
	if err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int64
	firstRequest := make(chan struct{})
	transport := remoteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(firstRequest)
			<-request.Context().Done()

			return nil, errors.New("transport aborted")
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(encoded)),
			Request:    request,
		}, nil
	})

	provider, err := NewRemoteProvider(RemoteConfig{
		URL:        "https://auth.example.test/.well-known/jwks.json",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}

	snapshot := provider.snapshot(key.Kid, time.Now())
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	waiterResult := make(chan error, 1)

	go func() {
		leaderResult <- provider.refreshIfUnchanged(
			leaderContext,
			snapshot.generation,
			snapshot.refreshVersion,
		)
	}()

	<-firstRequest

	go func() {
		waiterResult <- provider.refreshIfUnchanged(
			context.Background(),
			snapshot.generation,
			snapshot.refreshVersion,
		)
	}()

	cancelLeader()

	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}

	if err := <-waiterResult; err != nil {
		t.Fatalf("live waiter inherited canceled leader error: %v", err)
	}

	if got := requests.Load(); got != 2 {
		t.Fatalf("request count = %d, want canceled request plus retry", got)
	}
}

func TestRemoteProviderZeroValueReturnsPromptError(t *testing.T) {
	t.Parallel()

	var provider RemoteProvider

	for name, operation := range map[string]func() error{
		"key": func() error {
			_, err := provider.Key(context.Background(), "kid", "EdDSA")

			return err
		},
		"refresh": func() error {
			return provider.Refresh(context.Background())
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := make(chan error, 1)
			go func() { result <- operation() }()

			select {
			case err := <-result:
				if !errors.Is(err, errUninitializedRemoteProvider) {
					t.Fatalf("error = %v, want uninitialized provider", err)
				}
			case <-time.After(time.Second):
				t.Fatal("zero-value remote provider blocked")
			}
		})
	}
}

func TestRemoteProviderRefreshWaitIsContextAware(t *testing.T) {
	t.Parallel()

	key, _ := testEd25519JWK(t, "context-wait")
	entered := make(chan struct{})
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-entered:
		default:
			close(entered)
		}

		<-release
		_ = json.NewEncoder(w).Encode(Set{Keys: []Key{key}})
	}))
	defer server.Close()

	provider, err := Remote(server.URL).Build()
	if err != nil {
		t.Fatal(err)
	}

	leaderResult := make(chan error, 1)
	go func() {
		_, err := provider.Key(context.Background(), key.Kid, key.Alg)
		leaderResult <- err
	}()

	<-entered
	waiterContext, cancelWaiter := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)

	go func() {
		_, err := provider.Key(waiterContext, key.Kid, key.Alg)
		waiterResult <- err
	}()

	cancelWaiter()

	select {
	case err := <-waiterResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter remained blocked on refresh")
	}

	close(release)

	if err := <-leaderResult; err != nil {
		t.Fatal(err)
	}
}

type remoteRoundTripFunc func(*http.Request) (*http.Response, error)

func (f remoteRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRemoteBuilderDefaultsAndNilSafety(t *testing.T) {
	t.Parallel()

	customClient := &http.Client{Timeout: 3 * time.Second}
	provider := Remote("  https://issuer.example/jwks  ").
		HTTPClient(customClient).
		RefreshEvery(5 * time.Minute).
		MaxStale(30 * time.Minute).
		Must()

	if provider.url != "https://issuer.example/jwks" || provider.httpClient != customClient {
		t.Fatalf("provider did not preserve normalized URL and custom client")
	}

	if provider.refreshInterval != 5*time.Minute || provider.maxStale != 30*time.Minute {
		t.Fatalf("provider intervals = %s/%s", provider.refreshInterval, provider.maxStale)
	}

	defaults, err := NewRemoteProvider(RemoteConfig{URL: "https://issuer.example/jwks"})
	if err != nil {
		t.Fatal(err)
	}

	if defaults.refreshInterval != defaultRefreshInterval || defaults.maxStale != defaultMaxStale {
		t.Fatalf("defaults = %s/%s", defaults.refreshInterval, defaults.maxStale)
	}

	ignored := Remote("https://issuer.example/jwks").RefreshEvery(-1).MaxStale(0).Must()

	if ignored.refreshInterval != defaultRefreshInterval || ignored.maxStale != defaultMaxStale {
		t.Fatalf("non-positive builder values changed defaults")
	}

	if _, err := Remote().Build(); err == nil {
		t.Fatal("blank URL must fail")
	}

	assertPanics(t, func() { Remote().Must() })

	var builder *RemoteBuilder

	if builder.URL("url") != nil || builder.HTTPClient(customClient) != nil ||
		builder.RefreshEvery(time.Second) != nil || builder.MaxStale(time.Second) != nil {
		t.Fatal("nil builder mutator must return nil")
	}

	if _, err := builder.Build(); err == nil {
		t.Fatal("nil builder Build must fail")
	}

	assertPanics(t, func() { builder.Must() })
}
