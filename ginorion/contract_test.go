package ginorion_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/ginorion"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

func TestBuilderFacadesShareGuardConstruction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	token, verifier := signedTestToken(t, "billing.invoice.create")
	provider := verifierProvider(t, token, verifier)

	guard, err := ginorion.New().
		Issuer("https://auth.orionis.test/").
		Audience("billing-api").
		KeyProvider(provider).
		HTTPClient(&http.Client{Timeout: time.Second}).
		RefreshEvery(time.Minute).
		MaxStale(time.Hour).
		Scope("billing.invoice.create").
		ClaimsKey("custom.claims").
		ErrorHandler(func(c *gin.Context, status int, code string, _ error) {
			c.JSON(status, gin.H{"error": code})
		}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if guard == nil || guard.Handler() == nil || guard.Scope("billing.invoice.create") == nil {
		t.Fatal("builder did not create usable guard handlers")
	}

	if got := ginorion.FromVerifier(verifier).Must(); got == nil {
		t.Fatal("FromVerifier().Must() returned nil")
	}

	if handler, err := ginorion.FromVerifier(verifier).Handler(); err != nil || handler == nil {
		t.Fatalf("Handler() = %v, %v", handler, err)
	}

	if ginorion.FromVerifier(verifier).MustHandler() == nil {
		t.Fatal("MustHandler() returned nil")
	}
}

func TestBuilderValidation(t *testing.T) {
	t.Parallel()

	var nilBuilder *ginorion.Builder

	if _, err := nilBuilder.Build(); err == nil {
		t.Fatal("nil builder was accepted")
	}

	tests := []struct {
		name    string
		builder *ginorion.Builder
	}{
		{name: "issuer", builder: ginorion.New()},
		{name: "audience", builder: ginorion.New().Issuer("https://auth.test")},
		{
			name:    "provider",
			builder: ginorion.New().Issuer("https://auth.test").Audience("api"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.builder.Build(); err == nil {
				t.Fatal("invalid builder was accepted")
			}
		})
	}
}

func TestFunctionalOptionsPreserveClaimsAndFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	token, verifier := signedTestToken(t, "billing.invoice.create")

	var calls int
	var customClaims bool
	var defaultClaims bool

	r := gin.New()
	r.GET(
		"/protected",
		ginorion.Middleware(
			verifier,
			ginorion.WithScopes("billing.invoice.create"),
			ginorion.WithClaimsKey("custom.claims"),
			ginorion.WithErrorHandler(func(c *gin.Context, status int, code string, _ error) {
				c.JSON(status, gin.H{"error": code})
			}),
		),
		func(c *gin.Context) {
			calls++
			_, customClaims = c.Get("custom.claims")
			_, defaultClaims = c.Get(ginorion.DefaultClaimsKey)
			c.Status(http.StatusNoContent)
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)

	if res.Code != http.StatusNoContent || calls != 1 || !customClaims || !defaultClaims {
		t.Fatalf(
			"status=%d calls=%d custom=%v default=%v",
			res.Code,
			calls,
			customClaims,
			defaultClaims,
		)
	}
}

func TestAuthRoutesMountReadyzAndCustomPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	r := gin.New()
	returned := ginorion.Auth(auth).Mount(r)
	if returned == nil {
		t.Fatal("Mount returned nil routes")
	}

	for _, path := range []string{
		"/healthz",
		"/readyz",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
	} {
		res := httptest.NewRecorder()
		r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))

		if res.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, res.Code, res.Body.String())
		}
	}

	tokenRoute := httptest.NewRecorder()
	r.ServeHTTP(tokenRoute, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))

	if tokenRoute.Code == http.StatusNotFound {
		t.Fatal("token route was not mounted")
	}

	custom := gin.New()
	ginorion.Auth(auth).
		TokenPath("/token").
		JWKSPath("/keys").
		DiscoveryPath("/discovery").
		HealthPath("/live").
		ReadyPath("/ready").
		Mount(custom)

	for _, path := range []string{"/keys", "/discovery", "/live", "/ready"} {
		res := httptest.NewRecorder()
		custom.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))

		if res.Code != http.StatusOK {
			t.Fatalf("custom GET %s = %d", path, res.Code)
		}
	}
}

func TestAuthRoutesReadyzKeepsExistingRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	router.GET("/readyz", func(c *gin.Context) {
		c.String(http.StatusAccepted, "application-ready")
	})

	ginorion.Auth(auth).Mount(router)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusAccepted || response.Body.String() != "application-ready" {
		t.Fatalf("existing /readyz route was replaced: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuthRoutesReadyzKeepsRouteRegisteredAfterMount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	ginorion.Auth(auth).Mount(router)
	router.GET("/readyz", func(c *gin.Context) {
		c.String(http.StatusAccepted, "application-ready")
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusAccepted || response.Body.String() != "application-ready" {
		t.Fatalf("later /readyz route did not win: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuthRoutesReadyzKeepsLegacyCustomPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	ginorion.Auth(auth).JWKSPath("/readyz").Mount(router)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	var set jwk.Set

	if err := json.Unmarshal(response.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}

	if response.Code != http.StatusOK || len(set.Keys) != 1 || set.Keys[0].Kid != "routes-key" {
		t.Fatalf("legacy custom JWKS route did not win: status=%d keys=%+v", response.Code, set.Keys)
	}
}

func TestAuthRoutesReadyzKeepsExistingRouterGroupRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	routes := router.Group("/api")
	routes.GET("/readyz", func(c *gin.Context) {
		c.String(http.StatusAccepted, "group-ready")
	})

	ginorion.Auth(auth).Mount(routes)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/readyz", nil))

	if response.Code != http.StatusAccepted || response.Body.String() != "group-ready" {
		t.Fatalf("existing group route was replaced: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuthRoutesDefaultReadyzDoesNotReserveRouterGroupRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	routes := router.Group("/api")
	ginorion.Auth(auth).Mount(routes)
	routes.GET("/readyz", func(c *gin.Context) {
		c.String(http.StatusAccepted, "group-ready")
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/readyz", nil))

	if response.Code != http.StatusAccepted || response.Body.String() != "group-ready" {
		t.Fatalf("later group route did not win: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuthRoutesExplicitReadyPathMountsOnRouterGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	routes := router.Group("/api")
	ginorion.Auth(auth).ReadyPath("/ready").Mount(routes)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/ready", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("explicit group readiness route was not mounted: status=%d", response.Code)
	}
}

func TestAuthRoutesReadyzKeepsExistingWildcardRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	router.GET("/application/:probe", func(c *gin.Context) {
		c.String(http.StatusAccepted, c.Param("probe"))
	})

	ginorion.Auth(auth).ReadyPath("/application/ready").Mount(router)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/application/ready", nil))

	if response.Code != http.StatusAccepted || response.Body.String() != "ready" {
		t.Fatalf("existing wildcard route was replaced: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuthRoutesReadyzCanUseWildcardParentPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	router := gin.New()
	router.GET("/assets/*path", func(c *gin.Context) {
		c.String(http.StatusAccepted, c.Param("path"))
	})

	ginorion.Auth(auth).ReadyPath("/assets").Mount(router)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("exact readiness route was not mounted beside catch-all: status=%d", response.Code)
	}
}

func TestAuthRoutesReadyzDoesNotHideInvalidPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	defer func() {
		if recover() == nil {
			t.Fatal("invalid readiness path did not panic")
		}
	}()

	ginorion.Auth(auth).ReadyPath("/ready/:").Mount(gin.New())
}

func TestAuthRoutesReadyzRejectsUnreachableStaticPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := authServerForRoutes(t)

	for _, path := range []string{"readyz", "/ready?probe=1", "/ready#fragment", "/ready path"} {
		t.Run(path, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("invalid readiness path %q did not panic", path)
				}
			}()

			ginorion.Auth(auth).ReadyPath(path).Mount(gin.New())
		})
	}
}

func TestClaimsAndBearerCompatibilityHelpers(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	if claims, ok := ginorion.Claims(ctx); ok || claims != nil {
		t.Fatal("Claims unexpectedly found claims")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("MustClaims did not panic")
		}
	}()

	if token, err := ginorion.BearerToken("Bearer token"); err != nil || token != "token" {
		t.Fatalf("BearerToken() = %q, %v", token, err)
	}

	ginorion.MustClaims(ctx)
}

func authServerForRoutes(t *testing.T) *server.Server {
	t.Helper()

	signer, err := jwk.GenerateEd25519Signer("routes-key")
	if err != nil {
		t.Fatal(err)
	}

	auth, err := server.New().
		Issuer("https://auth.orionis.test").
		Signer(signer).
		Client(server.NewClient("orders").Secret("secret").Audience("api").Scope("api.read")).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

func verifierProvider(t *testing.T, token string, verifier *orionis.Verifier) orionis.KeyProvider {
	t.Helper()

	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	signer, err := jwk.GenerateEd25519Signer("unused")
	if err != nil {
		t.Fatal(err)
	}

	provider, err := signer.StaticProvider()
	if err != nil {
		t.Fatal(err)
	}

	return provider
}
