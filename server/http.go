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

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
)

func (s *Server) TokenHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")

		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxTokenRequestBody)

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")

		return
	}

	clientID, clientSecret, basic := r.BasicAuth()

	if !basic {
		clientID = r.PostForm.Get("client_id")
		clientSecret = r.PostForm.Get("client_secret")
	}

	response, err := s.tokens.issue(r.Context(), tokenRequest{
		grantType:    r.Form.Get("grant_type"),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: clientSecret,
		audience:     firstNonEmpty(r.Form.Get("audience"), r.Form.Get("resource")),
		scopes:       orionis.NormalizeScopes([]string{r.Form.Get("scope")}),
	})
	if err != nil {
		var oauthErr *oauthError

		if errors.As(err, &oauthErr) {
			if oauthErr.code == "invalid_client" {
				w.Header().Set("WWW-Authenticate", `Basic realm="orionis"`)
			}

			writeOAuthError(w, oauthErr.status, oauthErr.code, oauthErr.description)

			return
		}

		writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot issue token")

		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) JWKSHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})

		return
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	keys := make([]jwk.Key, len(s.signers))

	for index, signer := range s.signers {
		keys[index] = signer.PublicJWK()
	}

	writeJSON(w, http.StatusOK, jwk.Set{Keys: keys})
}

func (s *Server) DiscoveryHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"token_endpoint":                        s.TokenEndpoint(),
		"jwks_uri":                              s.JWKSURI(),
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"response_types_supported":              []string{"token"},
		"id_token_signing_alg_values_supported": []string{s.activeSigner.Algorithm()},
	})
}

func (s *Server) HealthHTTP(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "orionis-auth"})
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
