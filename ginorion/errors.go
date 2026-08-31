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
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func defaultErrorHandler(c *gin.Context, status int, code string, err error) {
	attrs := []any{"status", status, "code", code}

	if err != nil {
		attrs = append(attrs, "error", err)
	}

	if status >= http.StatusInternalServerError {
		slog.ErrorContext(c.Request.Context(), "orionis auth middleware error", attrs...)
	} else {
		slog.WarnContext(c.Request.Context(), "orionis auth request rejected", attrs...)
	}

	c.JSON(status, gin.H{"error": code, "message": publicErrorMessage(status, code)})
}

func publicErrorMessage(status int, code string) string {
	switch code {
	case "missing_bearer_token":
		return "missing bearer token"
	case "invalid_token":
		return "invalid token"
	case "insufficient_scope":
		return "insufficient scope"
	case "auth_misconfigured":
		return "authentication service unavailable"

	default:
		if status >= http.StatusInternalServerError {
			return "authentication service unavailable"
		}

		return "authentication request rejected"
	}
}
