package firewall

import (
	"net/netip"
	"testing"
)

func TestMatchesAny(t *testing.T) {
	tests := []struct {
		name  string
		globs []string
		want  bool
	}{
		{name: "eth0", globs: []string{"eth0"}, want: true},
		{name: "vethabc", globs: []string{"eth0", "veth*"}, want: true},
		{name: "lo", globs: []string{"eth*", "veth*"}, want: false},
	}

	for _, tt := range tests {
		if got := matchesAny(tt.name, tt.globs); got != tt.want {
			t.Fatalf("matchesAny(%q, %v) = %v, want %v", tt.name, tt.globs, got, tt.want)
		}
	}
}

func TestLPMKeyFromPrefixUsesNetworkOrderBytes(t *testing.T) {
	prefix := netip.MustParsePrefix("10.244.0.0/16")

	key := lpmKeyFromPrefix(prefix)

	if key.PrefixLen != 16 {
		t.Fatalf("PrefixLen = %d, want 16", key.PrefixLen)
	}
	if key.Addr != [4]byte{10, 244, 0, 0} {
		t.Fatalf("Addr = %v, want [10 244 0 0]", key.Addr)
	}
}
