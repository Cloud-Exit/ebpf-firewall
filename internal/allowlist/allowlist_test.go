package allowlist

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAllowlist(t *testing.T) {
	prefixes, err := Parse(strings.NewReader(`
# comment
192.0.2.10
192.0.2.0/24
192.0.2.10/32 # duplicate
`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(prefixes), 2; got != want {
		t.Fatalf("len(prefixes) = %d, want %d", got, want)
	}
	if prefixes[0].String() != "192.0.2.10/32" {
		t.Fatalf("prefixes[0] = %s", prefixes[0])
	}
	if prefixes[1].String() != "192.0.2.0/24" {
		t.Fatalf("prefixes[1] = %s", prefixes[1])
	}
}

func TestParseRejectsIPv6(t *testing.T) {
	_, err := Parse(strings.NewReader("2001:db8::/32\n"))
	if err == nil {
		t.Fatal("expected IPv6 rejection")
	}
}

func TestFetchMultipleSources(t *testing.T) {
	dir := t.TempDir()
	first := writeAllowlistFile(t, dir, "first.txt", "192.0.2.10\n198.51.100.0/24\n")
	second := writeAllowlistFile(t, dir, "second.txt", "192.0.2.10/32\n203.0.113.0/24\n")

	prefixes, err := Fetch(context.Background(), "file://"+first+", file://"+second)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"192.0.2.10/32", "198.51.100.0/24", "203.0.113.0/24"}
	if len(prefixes) != len(want) {
		t.Fatalf("len(prefixes) = %d, want %d: %v", len(prefixes), len(want), prefixes)
	}
	for i, wantPrefix := range want {
		if prefixes[i].String() != wantPrefix {
			t.Fatalf("prefixes[%d] = %s, want %s", i, prefixes[i], wantPrefix)
		}
	}
}

func TestFetchRejectsEmptySourceList(t *testing.T) {
	_, err := Fetch(context.Background(), " , ")
	if err == nil {
		t.Fatal("expected empty source list rejection")
	}
}

func writeAllowlistFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
