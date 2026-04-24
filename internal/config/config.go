package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultConfigDir = "/etc/ebpf-firewall"

type Config struct {
	SourceURL       string
	ProtectedPorts  []uint16
	ProtectAllPorts bool
	InterfaceGlobs  []string
	RefreshInterval time.Duration
	MaxEntries      uint32
}

func Load(dir string) (Config, error) {
	if dir == "" {
		dir = getenv("CONFIG_DIR", DefaultConfigDir)
	}

	cfg := Config{
		SourceURL:       readValue(dir, "source_url", "SOURCE_URL", ""),
		ProtectedPorts:  []uint16{22},
		InterfaceGlobs:  []string{"eth0"},
		RefreshInterval: 30 * time.Second,
		MaxEntries:      4096,
	}

	if raw := readValue(dir, "protected_ports", "PROTECTED_PORTS", ""); raw != "" {
		ports, allPorts, err := ParsePorts(raw)
		if err != nil {
			return Config{}, err
		}
		cfg.ProtectedPorts = ports
		cfg.ProtectAllPorts = allPorts
	}

	if raw := readValue(dir, "interface_globs", "INTERFACE_GLOBS", ""); raw != "" {
		cfg.InterfaceGlobs = splitCSV(raw)
	}

	if raw := readValue(dir, "refresh_interval", "REFRESH_INTERVAL", ""); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid refresh_interval %q: %w", raw, err)
		}
		cfg.RefreshInterval = interval
	}

	if raw := readValue(dir, "max_entries", "MAX_ENTRIES", ""); raw != "" {
		entries, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || entries == 0 {
			return Config{}, fmt.Errorf("invalid max_entries %q", raw)
		}
		cfg.MaxEntries = uint32(entries)
	}

	if cfg.SourceURL == "" {
		return Config{}, fmt.Errorf("source_url is required")
	}
	if len(cfg.ProtectedPorts) == 0 && !cfg.ProtectAllPorts {
		return Config{}, fmt.Errorf("at least one protected port is required")
	}
	if len(cfg.InterfaceGlobs) == 0 {
		return Config{}, fmt.Errorf("at least one interface glob is required")
	}
	if cfg.RefreshInterval <= 0 {
		return Config{}, fmt.Errorf("refresh_interval must be positive")
	}

	return cfg, nil
}

func ParsePorts(raw string) ([]uint16, bool, error) {
	parts := splitCSV(raw)
	if len(parts) == 1 && parts[0] == "*" {
		return nil, true, nil
	}

	ports := make([]uint16, 0, len(parts))
	seen := map[uint16]struct{}{}

	for _, part := range parts {
		if part == "*" {
			return nil, false, fmt.Errorf("protected port wildcard must be the only value")
		}

		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil || value == 0 {
			return nil, false, fmt.Errorf("invalid protected port %q", part)
		}

		port := uint16(value)
		if _, ok := seen[port]; ok {
			continue
		}
		ports = append(ports, port)
		seen[port] = struct{}{}
	}

	return ports, false, nil
}

func readValue(dir, fileName, envName, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
		return value
	}

	data, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(data))
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func splitCSV(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	})

	values := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			values = append(values, field)
		}
	}
	return values
}
