package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "source_url", "file:///tmp/allowlist.txt\n")
	writeFile(t, dir, "protected_ports", "22, 443\n")
	writeFile(t, dir, "interface_globs", "eth0,veth*\n")
	writeFile(t, dir, "refresh_interval", "5s\n")
	writeFile(t, dir, "max_entries", "64\n")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.SourceURL != "file:///tmp/allowlist.txt" {
		t.Fatalf("SourceURL = %q", cfg.SourceURL)
	}
	if got, want := cfg.ProtectedPorts, []uint16{22, 443}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ProtectedPorts = %v, want %v", got, want)
	}
	if got, want := cfg.InterfaceGlobs, []string{"eth0", "veth*"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("InterfaceGlobs = %v, want %v", got, want)
	}
	if cfg.RefreshInterval != 5*time.Second {
		t.Fatalf("RefreshInterval = %s", cfg.RefreshInterval)
	}
	if cfg.MaxEntries != 64 {
		t.Fatalf("MaxEntries = %d", cfg.MaxEntries)
	}
}

func TestLoadRequiresSourceURL(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePortsRejectsInvalidPorts(t *testing.T) {
	if _, _, err := ParsePorts("22,0"); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestParsePortsSupportsWildcard(t *testing.T) {
	ports, allPorts, err := ParsePorts("*")
	if err != nil {
		t.Fatal(err)
	}
	if !allPorts {
		t.Fatal("expected allPorts")
	}
	if len(ports) != 0 {
		t.Fatalf("ports = %v, want none", ports)
	}
}

func TestEnvOverridesConfigDirectory(t *testing.T) {
	t.Setenv("SOURCE_URL", "file:///env.txt")

	dir := t.TempDir()
	writeFile(t, dir, "source_url", "file:///configmap.txt\n")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SourceURL != "file:///env.txt" {
		t.Fatalf("SourceURL = %q", cfg.SourceURL)
	}
}

func writeFile(t *testing.T, dir, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}
