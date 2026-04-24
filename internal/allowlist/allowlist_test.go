package allowlist

import (
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
