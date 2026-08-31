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

package ginorion

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/internal/authroute"
	"github.com/stremovskyy/orionis/server"
)

type AuthRoutes struct {
	auth          *server.Server
	tokenPath     string
	jwksPath      string
	discoveryPath string
	healthPath    string
	readyPath     string
	readyExplicit bool
}

func Auth(auth *server.Server) *AuthRoutes {
	return &AuthRoutes{
		auth:          auth,
		tokenPath:     authroute.Token,
		jwksPath:      authroute.JWKS,
		discoveryPath: authroute.Discovery,
		healthPath:    authroute.Health,
		readyPath:     authroute.Ready,
	}
}

func (r *AuthRoutes) TokenPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.tokenPath = path
	}

	return r
}

func (r *AuthRoutes) JWKSPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.jwksPath = path
	}

	return r
}

func (r *AuthRoutes) DiscoveryPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.discoveryPath = path
	}

	return r
}

func (r *AuthRoutes) HealthPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.healthPath = path
	}

	return r
}

func (r *AuthRoutes) ReadyPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.readyPath = path
		r.readyExplicit = true
	}

	return r
}

func (r *AuthRoutes) Mount(routes gin.IRoutes) gin.IRoutes {
	if r == nil || r.auth == nil {
		return routes
	}

	routes.POST(r.tokenPath, gin.WrapF(r.auth.TokenHTTP))
	routes.GET(r.jwksPath, gin.WrapF(r.auth.JWKSHTTP))
	routes.GET(r.discoveryPath, gin.WrapF(r.auth.DiscoveryHTTP))
	routes.GET(r.healthPath, gin.WrapF(r.auth.HealthHTTP))

	if r.readyExplicit {
		mountCompatibleGET(routes, r.readyPath, gin.WrapF(r.auth.HealthHTTP))
	} else if engine, ok := routes.(*gin.Engine); ok {
		mountEngineFallbackGET(engine, r.readyPath, gin.WrapF(r.auth.HealthHTTP))
	}

	return routes
}

// mountCompatibleGET adds routes introduced after v0.3.2 without replacing a
// route already owned by the application or one of the legacy auth endpoints.
func mountCompatibleGET(routes gin.IRoutes, path string, handler gin.HandlerFunc) {
	validateReadyPath(path)

	if hasExistingGETRoute(routes, path) {
		return
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			if isGinRouteConflict(recovered) {
				return
			}

			panic(recovered)
		}
	}()

	routes.GET(path, handler)
}

// mountEngineFallbackGET leaves ownership of an application route independent
// of whether it is registered before or after the Orionis routes. The handler
// runs only for an otherwise unmatched static GET path.
func mountEngineFallbackGET(engine *gin.Engine, path string, handler gin.HandlerFunc) {
	validateReadyPath(path)

	engine.Use(func(c *gin.Context) {
		if c.Request.Method == http.MethodGet && c.Request.URL.Path == path && c.FullPath() == "" {
			handler(c)
			c.Abort()

			return
		}

		c.Next()
	})
}

func validateReadyPath(path string) {
	invalidRune := strings.IndexFunc(path, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0

	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, ":*?#") || invalidRune {
		panic("ginorion: readiness path must be a static absolute URL path")
	}
}

type routesInfoProvider interface {
	Routes() gin.RoutesInfo
}

func hasExistingGETRoute(routes gin.IRoutes, target string) bool {
	provider, ok := routes.(routesInfoProvider)

	if !ok {
		return false
	}

	target = "/" + strings.TrimPrefix(target, "/")

	for _, route := range provider.Routes() {
		if route.Method == http.MethodGet && ginRouteCovers(route.Path, target) {
			return true
		}
	}

	return false
}

func ginRouteCovers(pattern, target string) bool {
	patternParts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	targetParts := strings.Split(strings.TrimPrefix(target, "/"), "/")

	for index, part := range patternParts {
		if index >= len(targetParts) {
			return false
		}

		if strings.HasPrefix(part, "*") {
			return true
		}

		if strings.HasPrefix(part, ":") {
			if targetParts[index] == "" {
				return false
			}

			continue
		}

		if part != targetParts[index] {
			return false
		}
	}

	return len(patternParts) == len(targetParts)
}

func isGinRouteConflict(recovered any) bool {
	message := fmt.Sprint(recovered)

	return strings.Contains(message, "handlers are already registered for path") ||
		strings.Contains(message, "conflicts with existing wildcard") ||
		strings.Contains(message, "conflicts with existing path segment")
}

func RegisterAuthRoutes(routes gin.IRoutes, auth *server.Server) {
	Auth(auth).Mount(routes)
}
