package allowlist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

func Fetch(ctx context.Context, sourceURL string) ([]netip.Prefix, error) {
	var reader io.ReadCloser

	if strings.HasPrefix(sourceURL, "file://") {
		file, err := os.Open(strings.TrimPrefix(sourceURL, "file://"))
		if err != nil {
			return nil, err
		}
		reader = file
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
		if err != nil {
			return nil, err
		}

		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			resp.Body.Close()
			return nil, fmt.Errorf("allowlist fetch failed: %s", resp.Status)
		}
		reader = resp.Body
	}
	defer reader.Close()

	return Parse(reader)
}

func Parse(reader io.Reader) ([]netip.Prefix, error) {
	scanner := bufio.NewScanner(reader)
	prefixes := []netip.Prefix{}
	seen := map[netip.Prefix]struct{}{}
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}

		prefix, err := parsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("line %d: only IPv4 allowlist entries are supported", lineNumber)
		}

		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		prefixes = append(prefixes, prefix)
		seen[prefix] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return prefixes, nil
}

func parsePrefix(raw string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix, nil
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 or CIDR entry %q", raw)
	}

	addr, ok := netip.AddrFromSlice(ip.To4())
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 entry %q", raw)
	}
	return netip.PrefixFrom(addr, 32), nil
}
