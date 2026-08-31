package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stremovskyy/orionis/internal/httpjson"
)

func TestTokenRequestContract(t *testing.T) {
	t.Parallel()

	requestSeen := make(chan url.Values, 1)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %s", req.Method)
		}

		if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}

		if got := req.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}

		clientID, secret, ok := req.BasicAuth()

		if !ok || clientID != "orders-service" || secret != "secret" {
			t.Errorf("BasicAuth = %q, %q, %t", clientID, secret, ok)
		}

		if err := req.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}

		requestSeen <- req.PostForm
		writeTokenResponse(w, "access-token", 900)
	}))
	defer auth.Close()

	provider, err := New().
		TokenURL(auth.URL).
		As("orders-service", "secret").
		For("billing-api", " scope.write ", "scope.read", "scope.read").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	response, err := provider.TokenResponse(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}

	if response.AccessToken != "access-token" || response.TokenType != "Bearer" || response.ExpiresIn != 900 {
		t.Fatalf("response = %#v", response)
	}

	form := <-requestSeen

	if got := form.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("grant_type = %q", got)
	}

	if got := form.Get("audience"); got != "billing-api" {
		t.Fatalf("audience = %q", got)
	}

	if got := form.Get("scope"); got != "scope.read scope.write" {
		t.Fatalf("scope = %q", got)
	}

	token, err := provider.Token(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}

	if token != "access-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestTokenRequestUsesCustomAuthenticator(t *testing.T) {
	t.Parallel()

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("X-Service-Auth"); got != "custom" {
			t.Errorf("X-Service-Auth = %q", got)
		}

		writeTokenResponse(w, "custom-token", 60)
	}))
	defer auth.Close()

	provider, err := New().
		TokenURL(auth.URL).
		For("billing-api").
		Authenticator(authenticatorFunc(func(req *http.Request) error {
			req.Header.Set("X-Service-Auth", "custom")

			return nil
		})).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Token(t.Context(), "", nil); err != nil {
		t.Fatal(err)
	}
}

func TestTokenRequestErrorsPreserveSentinel(t *testing.T) {
	t.Parallel()

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"bad credentials"}`)
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "wrong").For("api").Must()
	_, err := provider.Token(t.Context(), "", nil)

	if !errors.Is(err, ErrTokenRequestFailed) {
		t.Fatalf("error = %v, want ErrTokenRequestFailed", err)
	}

	if !strings.Contains(err.Error(), "status=401 error=invalid_client description=bad credentials") {
		t.Fatalf("error = %v", err)
	}

	transportErr := errors.New("transport failed")
	provider = New().
		TokenURL("https://auth.example.test/oauth/token").
		As("client", "secret").
		For("api").
		TokenHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, transportErr
		})}).
		Must()

	_, err = provider.Token(t.Context(), "", nil)

	if !errors.Is(err, ErrTokenRequestFailed) {
		t.Fatalf("error = %v, want ErrTokenRequestFailed", err)
	}
}

func TestTokenResponseValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "missing access token", body: `{"token_type":"Bearer","expires_in":60}`},
		{name: "wrong token type", body: `{"access_token":"token","token_type":"MAC","expires_in":60}`},
		{name: "missing expiry", body: `{"access_token":"token","token_type":"Bearer","expires_in":0}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer auth.Close()

			provider := New().TokenURL(auth.URL).As("client", "secret").For("api").Must()

			if _, err := provider.Token(t.Context(), "", nil); err == nil ||
				!strings.Contains(err.Error(), "invalid token response") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTokenResponseRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"token","token_type":"Bearer","expires_in":60} {}`)
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "secret").For("api").Must()
	_, err := provider.Token(t.Context(), "", nil)

	if !errors.Is(err, httpjson.ErrTrailingData) {
		t.Fatalf("error = %v, want ErrTrailingData", err)
	}
}

func TestTokenRequestAuthenticationFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("custom authentication failed")
	provider := New().
		TokenURL("https://auth.example.test/oauth/token").
		For("api").
		Authenticator(authenticatorFunc(func(*http.Request) error { return want })).
		Must()

	_, err := provider.Token(t.Context(), "", nil)

	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func writeTokenResponse(w http.ResponseWriter, token string, expiresIn int64) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(
		w,
		`{"access_token":%q,"token_type":"Bearer","expires_in":%d,"scope":"scope.read"}`,
		token,
		expiresIn,
	)
}
