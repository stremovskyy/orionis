package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTargetAndTransportAuthorizeClonedRequest(t *testing.T) {
	t.Parallel()

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTokenResponse(w, "transport-token", 900)
	}))
	defer auth.Close()

	provider := New().TokenURL(auth.URL).As("client", "secret").Must()
	target := provider.For("billing-api", "scope.write", "scope.read").Scopes("scope.read")
	authorized := make(chan *http.Request, 1)
	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		authorized <- req

		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	base := &http.Client{Transport: baseTransport, Timeout: 2 * time.Second}
	httpClient := target.HTTPClient(base)

	if httpClient == base {
		t.Fatal("NewHTTPClient returned the base client")
	}

	if httpClient.Timeout != base.Timeout ||
		reflect.ValueOf(base.Transport).Pointer() != reflect.ValueOf(baseTransport).Pointer() {
		t.Fatal("base client settings were not preserved")
	}

	req, err := http.NewRequest(http.MethodGet, "https://billing.example.test/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = res.Body.Close()

	got := <-authorized

	if got == req {
		t.Fatal("transport passed the original request to the base transport")
	}

	if got.Header.Get("Authorization") != "Bearer transport-token" {
		t.Fatalf("Authorization = %q", got.Header.Get("Authorization"))
	}

	if req.Header.Get("Authorization") != "" {
		t.Fatalf("original Authorization = %q", req.Header.Get("Authorization"))
	}

	token, err := target.Token(t.Context())

	if err != nil || token != "transport-token" {
		t.Fatalf("Token = %q, %v", token, err)
	}

	response, err := target.TokenResponse(t.Context())

	if err != nil || response.AccessToken != "transport-token" {
		t.Fatalf("TokenResponse = %#v, %v", response, err)
	}

	authorizeReq, err := http.NewRequest(http.MethodGet, "https://billing.example.test/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := target.AuthorizeRequest(t.Context(), authorizeReq); err != nil {
		t.Fatal(err)
	}

	if authorizeReq.Header.Get("Authorization") != "Bearer transport-token" {
		t.Fatalf("Authorization = %q", authorizeReq.Header.Get("Authorization"))
	}
}

func TestTransportAndHTTPClientCopyScopes(t *testing.T) {
	t.Parallel()

	provider := New().TokenURL("https://auth.example.test/oauth/token").Must()
	scopes := []string{"scope.write", "scope.read"}
	httpClient := NewHTTPClient(&http.Client{}, provider, "api", scopes)
	scopes[0] = "mutated"

	transport, ok := httpClient.Transport.(*Transport)

	if !ok {
		t.Fatalf("transport = %T", httpClient.Transport)
	}

	if !reflect.DeepEqual(transport.Scopes, []string{"scope.read", "scope.write"}) {
		t.Fatalf("scopes = %#v", transport.Scopes)
	}

	targetTransport, ok := provider.For("api", "scope.write", "scope.read").Transport(nil).(*Transport)

	if !ok {
		t.Fatalf("target transport = %T", targetTransport)
	}

	if !reflect.DeepEqual(targetTransport.Scopes, []string{"scope.read", "scope.write"}) {
		t.Fatalf("target scopes = %#v", targetTransport.Scopes)
	}

	if _, ok := provider.Transport(nil).(*Transport); !ok {
		t.Fatal("Provider.Transport did not return *Transport")
	}

	if _, ok := provider.HTTPClient(nil).Transport.(*Transport); !ok {
		t.Fatal("Provider.HTTPClient did not install *Transport")
	}
}

func TestTransportRejectsMissingInputs(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://api.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}

	var transport *Transport

	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("nil transport succeeded")
	}

	transport = &Transport{}

	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("transport without provider succeeded")
	}

	transport.Provider = New().TokenURL("https://auth.example.test/oauth/token").Must()

	if _, err := transport.RoundTrip(nil); err == nil {
		t.Fatal("transport accepted nil request")
	}
}

var _ http.RoundTripper = roundTripFunc(nil)
