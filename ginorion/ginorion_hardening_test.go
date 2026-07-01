package ginorion_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/ginorion"
)

func TestDefaultErrorHandlerDoesNotExposeInternalVerifierErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/protected", ginorion.Middleware(nil), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", res.Code, res.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	if body["error"] != "auth_misconfigured" {
		t.Fatalf("unexpected error code: %q", body["error"])
	}

	if strings.Contains(body["message"], "ginorion: nil verifier") {
		t.Fatalf("default error handler exposed internal verifier error: %q", body["message"])
	}
}
