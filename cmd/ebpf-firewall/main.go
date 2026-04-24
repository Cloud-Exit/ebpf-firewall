package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/ebpf-allowlist-firewall/internal/allowlist"
	"github.com/example/ebpf-allowlist-firewall/internal/config"
	"github.com/example/ebpf-allowlist-firewall/internal/firewall"
)

func main() {
	var configDir string
	flag.StringVar(&configDir, "config-dir", "", "directory containing projected ConfigMap files")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, configDir, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configDir string, logger *log.Logger) error {
	cfg, err := config.Load(configDir)
	if err != nil {
		return err
	}

	engine, err := firewall.New(cfg.MaxEntries, logger)
	if err != nil {
		return err
	}
	defer engine.Close()

	ticker := time.NewTicker(cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		if err := syncOnce(ctx, configDir, engine, logger); err != nil {
			logger.Printf("sync failed: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			nextCfg, err := config.Load(configDir)
			if err != nil {
				logger.Printf("config reload failed: %v", err)
				continue
			}
			if nextCfg.RefreshInterval != cfg.RefreshInterval {
				ticker.Reset(nextCfg.RefreshInterval)
			}
			cfg = nextCfg
		}
	}
}

func syncOnce(ctx context.Context, configDir string, engine *firewall.Engine, logger *log.Logger) error {
	cfg, err := config.Load(configDir)
	if err != nil {
		return err
	}

	prefixes, err := allowlist.Fetch(ctx, cfg.SourceURL)
	if err != nil {
		return err
	}
	if uint32(len(prefixes)) > cfg.MaxEntries {
		return errors.New("allowlist exceeds max_entries")
	}

	if err := engine.Reconcile(ctx, cfg.ProtectedPorts, cfg.ProtectAllPorts, prefixes, cfg.InterfaceGlobs); err != nil {
		return err
	}

	logger.Printf(
		"synced firewall prefixes=%d protected_ports=%v protect_all_ports=%t interface_globs=%v refresh_interval=%s",
		len(prefixes),
		cfg.ProtectedPorts,
		cfg.ProtectAllPorts,
		cfg.InterfaceGlobs,
		cfg.RefreshInterval,
	)
	return nil
}
