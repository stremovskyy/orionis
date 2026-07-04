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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
)

const (
	KtyOKP  = "OKP"
	KtyRSA  = "RSA"
	KtyEC   = "EC"
	UseSig  = "sig"
	CrvEd   = "Ed25519"
	CrvP256 = "P-256"
)

var ErrKeyNotFound = errors.New("orionis jwk: key not found")

const (
	defaultRemoteHTTPTimeout = 10 * time.Second
	maxJWKSResponseBody      = 1 << 20
)

type Key struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type Set struct {
	Keys []Key `json:"keys"`
}

func NewEd25519Key(kid string, pub ed25519.PublicKey) Key {
	return Key{
		Kty: KtyOKP,
		Use: UseSig,
		Kid: strings.TrimSpace(kid),
		Alg: jwt.SigningMethodEdDSA.Alg(),
		Crv: CrvEd,
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func DecodePublicKey(k Key) (any, error) {
	switch k.Kty {
	case KtyOKP:
		if k.Crv != CrvEd {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}

		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decode ed25519 x: %w", err)
		}

		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key size: %d", len(raw))
		}

		return ed25519.PublicKey(raw), nil

	case KtyRSA:
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode rsa n: %w", err)
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode rsa e: %w", err)
		}

		if len(eBytes) == 0 {
			return nil, errors.New("empty rsa exponent")
		}

		e := 0

		for _, b := range eBytes {
			e = e<<8 + int(b)
		}

		if e == 0 {
			return nil, errors.New("invalid rsa exponent")
		}

		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil

	case KtyEC:
		if k.Crv != CrvP256 {
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decode ec x: %w", err)
		}

		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("decode ec y: %w", err)
		}

		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		encoded := make([]byte, 1, 1+len(xBytes)+len(yBytes))
		encoded[0] = 4
		encoded = append(encoded, xBytes...)
		encoded = append(encoded, yBytes...)

		if _, err := ecdh.P256().NewPublicKey(encoded); err != nil {
			return nil, errors.New("ec key is not on curve")
		}

		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

type StaticBuilder struct {
	set Set
}

func Static(keys ...Key) *StaticBuilder {
	return (&StaticBuilder{}).Keys(keys...)
}

func (b *StaticBuilder) Key(key Key) *StaticBuilder {
	if b == nil {
		return nil
	}

	b.set.Keys = append(b.set.Keys, key)

	return b
}

func (b *StaticBuilder) Keys(keys ...Key) *StaticBuilder {
	if b == nil {
		return nil
	}

	b.set.Keys = append(b.set.Keys, keys...)

	return b
}

func (b *StaticBuilder) Set(set Set) *StaticBuilder {
	if b == nil {
		return nil
	}

	b.set = set

	return b
}

func (b *StaticBuilder) Build() (*StaticProvider, error) {
	if b == nil {
		return nil, errors.New("orionis jwk: nil static builder")
	}

	return NewStaticProvider(b.set)
}

func (b *StaticBuilder) Must() *StaticProvider {
	provider, err := b.Build()
	if err != nil {
		panic(err)
	}

	return provider
}

type StaticProvider struct {
	keys map[string]any
}

func NewStaticProvider(set Set) (*StaticProvider, error) {
	keys := make(map[string]any, len(set.Keys))

	for _, item := range set.Keys {
		if strings.TrimSpace(item.Kid) == "" {
			return nil, errors.New("jwk without kid")
		}

		pub, err := DecodePublicKey(item)
		if err != nil {
			return nil, fmt.Errorf("decode key %q: %w", item.Kid, err)
		}

		keys[item.Kid] = pub
	}

	if len(keys) == 0 {
		return nil, errors.New("static jwks has no keys")
	}

	return &StaticProvider{keys: keys}, nil
}

func (p *StaticProvider) Key(ctx context.Context, kid string, alg string) (any, error) {
	_ = ctx
	_ = alg
	key, ok := p.keys[kid]

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	return key, nil
}

type RemoteConfig struct {
	URL             string
	HTTPClient      *http.Client
	RefreshInterval time.Duration
	MaxStale        time.Duration
}

type RemoteBuilder struct {
	cfg RemoteConfig
}

func Remote(url ...string) *RemoteBuilder {
	b := &RemoteBuilder{}

	if len(url) > 0 {
		b.URL(url[0])
	}

	return b
}

func (b *RemoteBuilder) URL(url string) *RemoteBuilder {
	if b == nil {
		return nil
	}

	b.cfg.URL = strings.TrimSpace(url)

	return b
}

func (b *RemoteBuilder) HTTPClient(hc *http.Client) *RemoteBuilder {
	if b == nil {
		return nil
	}

	b.cfg.HTTPClient = hc

	return b
}

func (b *RemoteBuilder) RefreshEvery(interval time.Duration) *RemoteBuilder {
	if b == nil {
		return nil
	}

	if interval > 0 {
		b.cfg.RefreshInterval = interval
	}

	return b
}

func (b *RemoteBuilder) MaxStale(maxStale time.Duration) *RemoteBuilder {
	if b == nil {
		return nil
	}

	if maxStale > 0 {
		b.cfg.MaxStale = maxStale
	}

	return b
}

func (b *RemoteBuilder) Build() (*RemoteProvider, error) {
	if b == nil {
		return nil, errors.New("orionis jwk: nil remote builder")
	}

	return NewRemoteProvider(b.cfg)
}

func (b *RemoteBuilder) Must() *RemoteProvider {
	provider, err := b.Build()
	if err != nil {
		panic(err)
	}

	return provider
}

type RemoteProvider struct {
	url             string
	httpClient      *http.Client
	refreshInterval time.Duration
	maxStale        time.Duration

	refreshMu sync.Mutex
	mu        sync.RWMutex
	keys      map[string]any
	expiresAt time.Time
	fetchedAt time.Time
}

func NewRemoteProvider(cfg RemoteConfig) (*RemoteProvider, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("jwks url is required")
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultRemoteHTTPClient()
	}

	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 10 * time.Minute
	}

	if cfg.MaxStale <= 0 {
		cfg.MaxStale = time.Hour
	}

	return &RemoteProvider{
		url:             cfg.URL,
		httpClient:      cfg.HTTPClient,
		refreshInterval: cfg.RefreshInterval,
		maxStale:        cfg.MaxStale,
		keys:            make(map[string]any),
	}, nil
}

func (p *RemoteProvider) Key(ctx context.Context, kid string, alg string) (any, error) {
	_ = alg
	now := time.Now()

	p.mu.RLock()
	key, found := p.keys[kid]
	fresh := now.Before(p.expiresAt)
	staleOK := !p.fetchedAt.IsZero() && now.Sub(p.fetchedAt) <= p.maxStale
	p.mu.RUnlock()

	if found && fresh {
		return key, nil
	}

	if err := p.Refresh(ctx); err != nil {
		if found && staleOK {
			return key, nil
		}

		return nil, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	key, found = p.keys[kid]

	if !found {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	return key, nil
}

func (p *RemoteProvider) Refresh(ctx context.Context) error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")

	res, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: unexpected status %d", res.StatusCode)
	}

	var set Set

	if err := decodeBoundedJSON(res.Body, maxJWKSResponseBody, &set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	decoded := make(map[string]any, len(set.Keys))

	for _, item := range set.Keys {
		if strings.TrimSpace(item.Kid) == "" {
			continue
		}

		pub, err := DecodePublicKey(item)
		if err != nil {
			return fmt.Errorf("decode jwk %q: %w", item.Kid, err)
		}

		decoded[item.Kid] = pub
	}

	if len(decoded) == 0 {
		return errors.New("jwks has no usable signing keys")
	}

	p.mu.Lock()
	p.keys = decoded
	p.fetchedAt = time.Now()
	p.expiresAt = p.fetchedAt.Add(p.refreshInterval)
	p.mu.Unlock()

	return nil
}

type Ed25519Builder struct {
	kid  string
	path string
}

func Ed25519() *Ed25519Builder {
	return &Ed25519Builder{kid: "orionis-ed25519-1"}
}

func (b *Ed25519Builder) KID(kid string) *Ed25519Builder {
	if b == nil {
		return nil
	}

	if strings.TrimSpace(kid) != "" {
		b.kid = strings.TrimSpace(kid)
	}

	return b
}

func (b *Ed25519Builder) Path(path string) *Ed25519Builder {
	if b == nil {
		return nil
	}

	b.path = strings.TrimSpace(path)

	return b
}

func (b *Ed25519Builder) Build() (*Ed25519Signer, error) {
	if b == nil {
		return nil, errors.New("orionis jwk: nil ed25519 builder")
	}

	return LoadOrCreateEd25519Signer(b.path, b.kid)
}

func (b *Ed25519Builder) Must() *Ed25519Signer {
	signer, err := b.Build()
	if err != nil {
		panic(err)
	}

	return signer
}

type Ed25519Signer struct {
	Kid        string
	PrivateKey ed25519.PrivateKey
}

func GenerateEd25519Signer(kid string) (*Ed25519Signer, error) {
	if strings.TrimSpace(kid) == "" {
		kid = "orionis-ed25519-1"
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	_ = pub

	return &Ed25519Signer{Kid: strings.TrimSpace(kid), PrivateKey: priv}, nil
}

func (s *Ed25519Signer) Algorithm() string { return jwt.SigningMethodEdDSA.Alg() }
func (s *Ed25519Signer) KeyID() string     { return s.Kid }

func (s *Ed25519Signer) PublicJWK() Key {
	pub := s.PrivateKey.Public().(ed25519.PublicKey)

	return NewEd25519Key(s.Kid, pub)
}

func (s *Ed25519Signer) StaticProvider() (*StaticProvider, error) {
	if s == nil {
		return nil, errors.New("nil ed25519 signer")
	}

	return Static(s.PublicJWK()).Build()
}

func (s *Ed25519Signer) Sign(claims *orionis.Claims) (string, error) {
	if s == nil || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid ed25519 signer")
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = s.Kid

	return tok.SignedString(s.PrivateKey)
}

func LoadOrCreateEd25519Signer(path string, kid string) (*Ed25519Signer, error) {
	if strings.TrimSpace(kid) == "" {
		kid = "orionis-ed25519-1"
	}

	if strings.TrimSpace(path) == "" {
		return GenerateEd25519Signer(kid)
	}

	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("decode pem %s: empty pem", path)
		}

		return ed25519SignerFromPKCS8(block.Bytes, kid, "at "+path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	signer, err := GenerateEd25519Signer(kid)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(signer.PrivateKey)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}

	return signer, nil
}

func LoadEd25519SignerPEM(raw []byte, kid string) (*Ed25519Signer, error) {
	if strings.TrimSpace(kid) == "" {
		kid = "orionis-ed25519-1"
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("decode pem: empty pem")
	}

	return ed25519SignerFromPKCS8(block.Bytes, kid, "")
}

func ed25519SignerFromPKCS8(der []byte, kid string, location string) (*Ed25519Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
	}

	priv, ok := key.(ed25519.PrivateKey)

	if !ok {
		if strings.TrimSpace(location) != "" {
			return nil, fmt.Errorf("private key %s is %T, expected ed25519.PrivateKey", location, key)
		}

		return nil, fmt.Errorf("private key is %T, expected ed25519.PrivateKey", key)
	}

	return &Ed25519Signer{Kid: strings.TrimSpace(kid), PrivateKey: priv}, nil
}

func defaultRemoteHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultRemoteHTTPTimeout}
}

func decodeBoundedJSON(r io.Reader, maxBytes int64, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return err
	}

	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("response body too large: limit=%d bytes", maxBytes)
	}

	return json.NewDecoder(bytes.NewReader(raw)).Decode(dst)
}
