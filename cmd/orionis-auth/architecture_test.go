package main

import (
	"os"
	"strings"
	"testing"
)

func TestMainEntrypointStaysThin(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}

	source := string(raw)

	for _, forbidden := range []string{
		"type config struct",
		"func loadConfig",
		"func validateSigningConfig",
		"func buildAuthServer",
		"func loadSigningKey",
		"func mountAuthRoutes",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("main.go should delegate %q outside package main", forbidden)
		}
	}

	if lines := strings.Count(source, "\n") + 1; lines > 180 {
		t.Fatalf("main.go should stay thin; got %d lines", lines)
	}
}
