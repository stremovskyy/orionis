package stringset

import (
	"reflect"
	"testing"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	got := Normalize([]string{" write read ", "read", "admin\twrite", ""})
	want := []string{"admin", "read", "write"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize() = %#v, want %#v", got, want)
	}
}

func TestNormalizeEmpty(t *testing.T) {
	t.Parallel()

	if got := Normalize(nil); got != nil {
		t.Fatalf("Normalize(nil) = %#v, want nil", got)
	}

	if got := Normalize([]string{" ", "\t"}); got == nil || len(got) != 0 {
		t.Fatalf("Normalize(blank values) = %#v, want non-nil empty slice", got)
	}
}
