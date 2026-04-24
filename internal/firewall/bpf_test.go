package firewall

import "testing"

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
