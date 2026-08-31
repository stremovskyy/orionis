package httpjson

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeSingleValue(t *testing.T) {
	t.Parallel()

	var payload struct {
		Value string `json:"value"`
	}

	if err := Decode(strings.NewReader(`{"value":"ok"}`), 128, &payload); err != nil {
		t.Fatal(err)
	}

	if payload.Value != "ok" {
		t.Fatalf("value = %q, want ok", payload.Value)
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	t.Parallel()

	var payload map[string]any
	err := Decode(strings.NewReader(`{} {}`), 128, &payload)

	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("error = %v, want ErrTrailingData", err)
	}
}

func TestReadRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	_, err := Read(strings.NewReader("12345"), 4)

	if err == nil || !strings.Contains(err.Error(), "limit=4 bytes") {
		t.Fatalf("error = %v, want size error", err)
	}
}
