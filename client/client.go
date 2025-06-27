package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stremovskyy/orionis"
)

var ErrTokenRequestFailed = errors.New("orionis client: token request failed")

type Authenticator interface {
	Authenticate(req *http.Request) error
}

type ClientSecretBasic struct {
	ClientID     string
	ClientSecret string
}

func (a ClientSecretBasic) Authenticate(req *http.Request) error {
	if strings.TrimSpace(a.ClientID) == "" || a.ClientSecret == "" {
		return errors.New("client_id and client_secret are required")
	}

	req.SetBasicAuth(a.ClientID, a.ClientSecret)

	return nil
}

type Config struct {
	TokenURL      string
	ClientID      string
	ClientSecret  string
	Audience      string
	Scopes        []string
	HTTPClient    *http.Client
	Authenticator Authenticator
	RefreshSkew   time.Duration
}

type Builder struct {
	cfg Config
	err error
}

func New() *Builder {
	return &Builder{cfg: Config{RefreshSkew: 60 * time.Second}}
}

func FromConfig(cfg Config) *Builder {
	return New().
		TokenURL(cfg.TokenURL).
		ClientSecret(cfg.ClientID, cfg.ClientSecret).
		Audience(cfg.Audience).
		Scopes(cfg.Scopes...).
		TokenHTTPClient(cfg.HTTPClient).
		Authenticator(cfg.Authenticator).
		RefreshSkew(cfg.RefreshSkew)
}

func NewProvider(cfg Config) (*Provider, error) {
	return FromConfig(cfg).Build()
}

func (b *Builder) TokenURL(tokenURL string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.TokenURL = strings.TrimSpace(tokenURL)

	return b
}

func (b *Builder) As(clientID, clientSecret string) *Builder {
	return b.ClientSecret(clientID, clientSecret)
}

func (b *Builder) Credentials(clientID, clientSecret string) *Builder {
	return b.ClientSecret(clientID, clientSecret)
}

func (b *Builder) ClientSecret(clientID, clientSecret string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.ClientID = strings.TrimSpace(clientID)
	b.cfg.ClientSecret = clientSecret

	return b
}

func (b *Builder) For(audience string, scopes ...string) *Builder {
	return b.Audience(audience).Scopes(scopes...)
}

func (b *Builder) Audience(audience string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.Audience = strings.TrimSpace(audience)

	return b
}

func (b *Builder) Scope(scope string) *Builder {
	return b.Scopes(scope)
}

func (b *Builder) Scopes(scopes ...string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.Scopes = append(b.cfg.Scopes, scopes...)

	return b
}

func (b *Builder) TokenHTTPClient(hc *http.Client) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.HTTPClient = hc

	return b
}

func (b *Builder) Authenticator(authenticator Authenticator) *Builder {
	if b == nil {
		return nil
	}

	if authenticator != nil {
		b.cfg.Authenticator = authenticator
	}

	return b
}

func (b *Builder) RefreshSkew(skew time.Duration) *Builder {
	if b == nil {
		return nil
	}

	if skew > 0 {
		b.cfg.RefreshSkew = skew
	}

	return b
}

func (b *Builder) Build() (*Provider, error) {
	if b == nil {
		return nil, errors.New("orionis client: nil builder")
	}

	if b.err != nil {
		return nil, b.err
	}

	cfg := b.cfg

	if strings.TrimSpace(cfg.TokenURL) == "" {
		return nil, errors.New("orionis client: token url is required")
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	if cfg.RefreshSkew <= 0 {
		cfg.RefreshSkew = 60 * time.Second
	}

	if cfg.Authenticator == nil {
		cfg.Authenticator = ClientSecretBasic{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}
	}

	return &Provider{
		tokenURL:      cfg.TokenURL,
		audience:      cfg.Audience,
		scopes:        orionis.NormalizeScopes(cfg.Scopes),
		httpClient:    cfg.HTTPClient,
		authenticator: cfg.Authenticator,
		refreshSkew:   cfg.RefreshSkew,
		cache:         make(map[string]cachedToken),
		inflight:      make(map[string]*inflightCall),
	}, nil
}

func (b *Builder) Must() *Provider {
	provider, err := b.Build()
	if err != nil {
		panic(err)
	}

	return provider
}

func (b *Builder) BuildHTTPClient(base *http.Client) (*http.Client, error) {
	provider, err := b.Build()
	if err != nil {
		return nil, err
	}

	return provider.HTTPClient(base), nil
}

func (b *Builder) MustHTTPClient(base *http.Client) *http.Client {
	hc, err := b.BuildHTTPClient(base)
	if err != nil {
		panic(err)
	}

	return hc
}

type Provider struct {
	tokenURL      string
	audience      string
	scopes        []string
	httpClient    *http.Client
	authenticator Authenticator
	refreshSkew   time.Duration

	mu       sync.Mutex
	cache    map[string]cachedToken
	inflight map[string]*inflightCall
}

type cachedToken struct {
	response  orionis.TokenResponse
	expiresAt time.Time
}

type inflightCall struct {
	done  chan struct{}
	token cachedToken
	err   error
}

func (p *Provider) For(audience string, scopes ...string) Target {
	return Target{provider: p, audience: audience, scopes: orionis.NormalizeScopes(scopes)}
}

func (p *Provider) Token(ctx context.Context, audience string, scopes []string) (string, error) {
	resp, err := p.TokenResponse(ctx, audience, scopes)
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}

func (p *Provider) TokenResponse(ctx context.Context, audience string, scopes []string) (orionis.TokenResponse, error) {
	if p == nil {
		return orionis.TokenResponse{}, errors.New("orionis client: nil provider")
	}

	audience, scopes, err := p.target(audience, scopes)
	if err != nil {
		return orionis.TokenResponse{}, err
	}

	key := cacheKey(audience, scopes)

	if tok, ok := p.cached(key); ok {
		return tok.response, nil
	}

	call, leader := p.startCall(key)

	if !leader {
		select {
		case <-call.done:
			if call.err != nil {
				return orionis.TokenResponse{}, call.err
			}

			return call.token.response, nil
		case <-ctx.Done():
			return orionis.TokenResponse{}, ctx.Err()
		}
	}

	tok, err := p.requestToken(ctx, audience, scopes)
	p.finishCall(key, call, tok, err)

	if err != nil {
		return orionis.TokenResponse{}, err
	}

	return tok.response, nil
}

func (p *Provider) AuthorizeRequest(ctx context.Context, req *http.Request, audience string, scopes []string) error {
	if req == nil {
		return errors.New("orionis client: nil request")
	}

	token, err := p.Token(ctx, audience, scopes)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

func (p *Provider) HTTPClient(base *http.Client) *http.Client {
	return NewHTTPClient(base, p, "", nil)
}

func (p *Provider) Transport(base http.RoundTripper) http.RoundTripper {
	return &Transport{Base: base, Provider: p}
}

func (p *Provider) target(audience string, scopes []string) (string, []string, error) {
	if strings.TrimSpace(audience) == "" {
		audience = p.audience
	}

	if len(scopes) == 0 {
		scopes = p.scopes
	}

	audience = strings.TrimSpace(audience)
	scopes = orionis.NormalizeScopes(scopes)

	if audience == "" {
		return "", nil, errors.New("orionis client: audience is required")
	}

	return audience, scopes, nil
}

func (p *Provider) cached(key string) (cachedToken, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	tok, ok := p.cache[key]

	if !ok {
		return cachedToken{}, false
	}

	if !p.fresh(tok) {
		return cachedToken{}, false
	}

	return tok, true
}

func (p *Provider) fresh(tok cachedToken) bool {
	if tok.response.ExpiresIn <= 0 {
		return false
	}

	skew := p.refreshSkew
	ttl := time.Duration(tok.response.ExpiresIn) * time.Second

	if skew >= ttl {
		skew = ttl / 10
	}

	return time.Until(tok.expiresAt) > skew
}

func (p *Provider) startCall(key string) (*inflightCall, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if tok, ok := p.cache[key]; ok && p.fresh(tok) {
		call := &inflightCall{done: make(chan struct{}), token: tok}
		close(call.done)

		return call, false
	}

	if call, ok := p.inflight[key]; ok {
		return call, false
	}

	call := &inflightCall{done: make(chan struct{})}
	p.inflight[key] = call

	return call, true
}

func (p *Provider) finishCall(key string, call *inflightCall, tok cachedToken, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err == nil {
		p.cache[key] = tok
	}

	call.token = tok
	call.err = err
	delete(p.inflight, key)
	close(call.done)
}

func (p *Provider) requestToken(ctx context.Context, audience string, scopes []string) (cachedToken, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", audience)

	if scope := orionis.ScopeString(scopes); scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return cachedToken{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if err := p.authenticator.Authenticate(req); err != nil {
		return cachedToken{}, err
	}

	res, err := p.httpClient.Do(req)
	if err != nil {
		return cachedToken{}, fmt.Errorf("%w: %v", ErrTokenRequestFailed, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.NewDecoder(res.Body).Decode(&oauthErr)

		if oauthErr.Error != "" {
			return cachedToken{}, fmt.Errorf(
				"%w: status=%d error=%s description=%s",
				ErrTokenRequestFailed,
				res.StatusCode,
				oauthErr.Error,
				oauthErr.ErrorDescription,
			)
		}

		return cachedToken{}, fmt.Errorf("%w: status=%d", ErrTokenRequestFailed, res.StatusCode)
	}

	var tr orionis.TokenResponse

	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return cachedToken{}, fmt.Errorf("decode token response: %w", err)
	}

	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, orionis.TokenTypeBearer) || tr.ExpiresIn <= 0 {
		return cachedToken{}, errors.New("orionis client: invalid token response")
	}

	return cachedToken{response: tr, expiresAt: time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)}, nil
}

type Target struct {
	provider *Provider
	audience string
	scopes   []string
}

func (t Target) Scopes(scopes ...string) Target {
	t.scopes = orionis.NormalizeScopes(scopes)

	return t
}

func (t Target) Token(ctx context.Context) (string, error) {
	return t.provider.Token(ctx, t.audience, t.scopes)
}

func (t Target) TokenResponse(ctx context.Context) (orionis.TokenResponse, error) {
	return t.provider.TokenResponse(ctx, t.audience, t.scopes)
}

func (t Target) AuthorizeRequest(ctx context.Context, req *http.Request) error {
	return t.provider.AuthorizeRequest(ctx, req, t.audience, t.scopes)
}

func (t Target) HTTPClient(base *http.Client) *http.Client {
	return NewHTTPClient(base, t.provider, t.audience, t.scopes)
}

func (t Target) Transport(base http.RoundTripper) http.RoundTripper {
	return &Transport{Base: base, Provider: t.provider, Audience: t.audience, Scopes: t.scopes}
}

type Transport struct {
	Base     http.RoundTripper
	Provider *Provider
	Audience string
	Scopes   []string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.Provider == nil {
		return nil, errors.New("orionis transport: provider is nil")
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	cloned := req.Clone(req.Context())

	if err := t.Provider.AuthorizeRequest(req.Context(), cloned, t.Audience, t.Scopes); err != nil {
		return nil, err
	}

	return base.RoundTrip(cloned)
}

func NewHTTPClient(base *http.Client, provider *Provider, audience string, scopes []string) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}

	copyClient := *base
	copyClient.Transport = &Transport{
		Base:     base.Transport,
		Provider: provider,
		Audience: audience,
		Scopes:   orionis.NormalizeScopes(scopes),
	}

	return &copyClient
}

func cacheKey(audience string, scopes []string) string {
	return strings.TrimSpace(audience) + "|" + orionis.ScopeString(scopes)
}
