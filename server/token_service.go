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
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
)

type tokenRequest struct {
	grantType    string
	clientID     string
	clientSecret string
	audience     string
	scopes       []string
}

type tokenService struct {
	issuer         string
	store          ClientStore
	signer         Signer
	accessTokenTTL time.Duration

	now func() time.Time
}

type oauthError struct {
	status      int
	code        string
	description string
}

func (e *oauthError) Error() string {
	return e.code + ": " + e.description
}

func (s tokenService) issue(ctx context.Context, request tokenRequest) (orionis.TokenResponse, error) {
	if request.grantType != "client_credentials" {
		return orionis.TokenResponse{}, newOAuthError(
			http.StatusBadRequest,
			"unsupported_grant_type",
			"grant_type must be client_credentials",
		)
	}

	client, err := s.authenticate(ctx, request.clientID, request.clientSecret)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrClientNotFound) {
			return orionis.TokenResponse{}, newOAuthError(
				http.StatusUnauthorized,
				"invalid_client",
				"invalid client credentials",
			)
		}

		return orionis.TokenResponse{}, fmt.Errorf("authenticate client: %w", err)
	}

	if request.audience == "" {
		return orionis.TokenResponse{}, newOAuthError(
			http.StatusBadRequest,
			"invalid_request",
			"audience is required",
		)
	}

	if !contains(client.AllowedAudiences, request.audience) {
		return orionis.TokenResponse{}, newOAuthError(
			http.StatusForbidden,
			"invalid_target",
			"client is not allowed to request this audience",
		)
	}

	requestedScopes := request.scopes

	if len(requestedScopes) == 0 {
		requestedScopes = client.DefaultScopes
	}

	issuedScopes, ok := resolveRequestedScopes(requestedScopes, client.AllowedScopes)

	if !ok {
		return orionis.TokenResponse{}, newOAuthError(
			http.StatusBadRequest,
			"invalid_scope",
			"client requested a scope that is not allowed",
		)
	}

	return s.issueAccessToken(client, request.audience, issuedScopes)
}

func (s tokenService) authenticate(ctx context.Context, id, secret string) (Client, error) {
	if id == "" || secret == "" {
		return Client{}, ErrUnauthorized
	}

	client, err := s.store.FindClient(ctx, id)
	if err != nil {
		return Client{}, err
	}

	if client.Disabled || !client.VerifySecret(secret) {
		return Client{}, ErrUnauthorized
	}

	return client.Normalize(), nil
}

func (s tokenService) issueAccessToken(client Client, audience string, scopes []string) (orionis.TokenResponse, error) {
	now := s.now().UTC()
	jti, err := randomID()
	if err != nil {
		return orionis.TokenResponse{}, err
	}

	claims := &orionis.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   client.ID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		ClientID: client.ID,
		Scope:    orionis.ScopeString(scopes),
		TokenUse: orionis.TokenUseAccess,
	}

	signed, err := s.signer.Sign(claims)
	if err != nil {
		return orionis.TokenResponse{}, err
	}

	return orionis.TokenResponse{
		AccessToken: signed,
		TokenType:   orionis.TokenTypeBearer,
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       claims.Scope,
	}, nil
}

func newOAuthError(status int, code, description string) *oauthError {
	return &oauthError{status: status, code: code, description: description}
}
