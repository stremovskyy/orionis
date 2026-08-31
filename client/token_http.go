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

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/internal/httpjson"
)

func (p *Provider) requestToken(
	ctx context.Context,
	audience string,
	scopes []string,
) (cachedToken, error) {
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
		return cachedToken{}, fmt.Errorf("%w: %w", ErrTokenRequestFailed, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return cachedToken{}, tokenResponseError(res)
	}

	var response orionis.TokenResponse

	if err := httpjson.Decode(res.Body, maxTokenResponseBody, &response); err != nil {
		return cachedToken{}, fmt.Errorf("decode token response: %w", err)
	}

	if response.AccessToken == "" ||
		!strings.EqualFold(response.TokenType, orionis.TokenTypeBearer) ||
		response.ExpiresIn <= 0 {
		return cachedToken{}, errors.New("orionis client: invalid token response")
	}

	return cachedToken{
		response:  response,
		expiresAt: time.Now().Add(time.Duration(response.ExpiresIn) * time.Second),
	}, nil
}

func tokenResponseError(res *http.Response) error {
	raw, err := httpjson.Read(res.Body, maxTokenResponseBody)
	if err != nil {
		return fmt.Errorf("%w: status=%d: %w", ErrTokenRequestFailed, res.StatusCode, err)
	}

	var oauthErr struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	if err := json.Unmarshal(raw, &oauthErr); err == nil && oauthErr.Error != "" {
		return fmt.Errorf(
			"%w: status=%d error=%s description=%s",
			ErrTokenRequestFailed,
			res.StatusCode,
			oauthErr.Error,
			oauthErr.ErrorDescription,
		)
	}

	return fmt.Errorf("%w: status=%d", ErrTokenRequestFailed, res.StatusCode)
}
