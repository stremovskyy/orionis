package client

import (
	"net/http"
	"reflect"
	"testing"
	"time"
)

type authenticatorFunc func(*http.Request) error

func (f authenticatorFunc) Authenticate(req *http.Request) error {
	return f(req)
}

func TestConstructionPathsNormalizeAndCopyConfig(t *testing.T) {
	t.Parallel()

	scopes := []string{" scope.write ", "scope.read", "scope.read"}
	httpClient := &http.Client{Timeout: 3 * time.Second}
	authenticator := authenticatorFunc(func(*http.Request) error { return nil })
	cfg := Config{
		TokenURL:      " https://auth.example.test/oauth/token ",
		ClientID:      " client-id ",
		ClientSecret:  "secret",
		Audience:      " billing-api ",
		Scopes:        scopes,
		HTTPClient:    httpClient,
		Authenticator: authenticator,
		RefreshSkew:   15 * time.Second,
	}

	fromConfig, err := FromConfig(cfg).Build()
	if err != nil {
		t.Fatal(err)
	}

	direct, err := NewProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}

	scopes[0] = "mutated"
	cfg.Scopes[1] = "also-mutated"

	for name, provider := range map[string]*Provider{
		"builder": fromConfig,
		"direct":  direct,
	} {
		t.Run(name, func(t *testing.T) {
			if provider.tokenURL != "https://auth.example.test/oauth/token" {
				t.Fatalf("tokenURL = %q", provider.tokenURL)
			}

			if provider.audience != "billing-api" {
				t.Fatalf("audience = %q", provider.audience)
			}

			if !reflect.DeepEqual(provider.scopes, []string{"scope.read", "scope.write"}) {
				t.Fatalf("scopes = %#v", provider.scopes)
			}

			if provider.httpClient != httpClient {
				t.Fatal("custom HTTP client was not preserved")
			}

			if provider.refreshSkew != 15*time.Second {
				t.Fatalf("refreshSkew = %s", provider.refreshSkew)
			}

			if reflect.ValueOf(provider.authenticator).Pointer() != reflect.ValueOf(authenticator).Pointer() {
				t.Fatal("custom authenticator was not preserved")
			}
		})
	}
}

func TestBuilderCopiesScopesBeforeBuild(t *testing.T) {
	t.Parallel()

	scopes := []string{"scope.write", "scope.read"}
	builder := New().TokenURL("https://auth.example.test/oauth/token").Scopes(scopes...)
	scopes[0] = "mutated"

	provider, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(provider.scopes, []string{"scope.read", "scope.write"}) {
		t.Fatalf("scopes = %#v", provider.scopes)
	}
}

func TestBuilderCompatibilityEntrypoints(t *testing.T) {
	t.Parallel()

	provider, err := New().
		TokenURL("https://auth.example.test/oauth/token").
		Credentials(" client-id ", "secret").
		Audience(" billing-api ").
		Scope("scope.read").
		RefreshSkew(-time.Second).
		Authenticator(nil).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if provider.refreshSkew != defaultRefreshSkew {
		t.Fatalf("refreshSkew = %s, want %s", provider.refreshSkew, defaultRefreshSkew)
	}

	basic, ok := provider.authenticator.(ClientSecretBasic)

	if !ok {
		t.Fatalf("authenticator = %T", provider.authenticator)
	}

	if basic.ClientID != "client-id" || basic.ClientSecret != "secret" {
		t.Fatalf("basic credentials = %#v", basic)
	}

	httpClient, err := New().
		TokenURL("https://auth.example.test/oauth/token").
		As("client-id", "secret").
		For("billing-api", "scope.read").
		BuildHTTPClient(&http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := httpClient.Transport.(*Transport); !ok {
		t.Fatalf("transport = %T", httpClient.Transport)
	}

	if New().TokenURL("https://auth.example.test/oauth/token").Must() == nil {
		t.Fatal("Must returned nil provider")
	}

	if New().TokenURL("https://auth.example.test/oauth/token").MustHTTPClient(nil) == nil {
		t.Fatal("MustHTTPClient returned nil client")
	}
}

func TestBuilderFailures(t *testing.T) {
	t.Parallel()

	if _, err := NewProvider(Config{}); err == nil {
		t.Fatal("NewProvider accepted an empty token URL")
	}

	var builder *Builder

	if _, err := builder.Build(); err == nil {
		t.Fatal("nil Builder.Build succeeded")
	}

	if builder.TokenURL("ignored") != nil ||
		builder.ClientSecret("ignored", "ignored") != nil ||
		builder.Audience("ignored") != nil ||
		builder.Scopes("ignored") != nil ||
		builder.TokenHTTPClient(nil) != nil ||
		builder.Authenticator(nil) != nil ||
		builder.RefreshSkew(time.Second) != nil {
		t.Fatal("a nil builder method returned a non-nil builder")
	}

	assertPanics(t, func() { New().Must() })
	assertPanics(t, func() { New().MustHTTPClient(nil) })
}

func TestClientSecretBasic(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://auth.example.test/oauth/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := (ClientSecretBasic{ClientID: " client-id ", ClientSecret: "secret"}).Authenticate(req); err != nil {
		t.Fatal(err)
	}

	clientID, secret, ok := req.BasicAuth()

	if !ok || clientID != " client-id " || secret != "secret" {
		t.Fatalf("BasicAuth = %q, %q, %t", clientID, secret, ok)
	}

	for _, authenticator := range []ClientSecretBasic{
		{ClientSecret: "secret"},
		{ClientID: "client-id"},
	} {
		if err := authenticator.Authenticate(req); err == nil {
			t.Fatalf("Authenticate(%#v) succeeded", authenticator)
		}
	}
}

func TestAuthorizeRequestRejectsNilRequest(t *testing.T) {
	t.Parallel()

	provider := New().TokenURL("https://auth.example.test/oauth/token").Must()

	if err := provider.AuthorizeRequest(t.Context(), nil, "billing-api", nil); err == nil {
		t.Fatal("AuthorizeRequest accepted nil request")
	}
}

func TestTokenResponseRejectsNilProviderAndMissingAudience(t *testing.T) {
	t.Parallel()

	var provider *Provider

	if _, err := provider.TokenResponse(t.Context(), "billing-api", nil); err == nil {
		t.Fatal("nil provider succeeded")
	}

	provider = New().TokenURL("https://auth.example.test/oauth/token").Must()

	if _, err := provider.TokenResponse(t.Context(), "", nil); err == nil {
		t.Fatal("missing audience succeeded")
	}
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()

	fn()
}

var _ Authenticator = authenticatorFunc(nil)
