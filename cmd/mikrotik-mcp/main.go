package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/mcphttp"
	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/engine"
	"github.com/Primexz/netops-mcp/internal/mikrotik/mcpserver"
	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, logger); err != nil {
		logger.Error("mikrotik-mcp stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, logger *slog.Logger) error {
	flags := flag.NewFlagSet("mikrotik-mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", ".local/mikrotik.toml", "router profiles TOML file")
	transport := flags.String("transport", "", "override server.transport: stdio or http")
	check := flags.Bool("check", false, "validate configuration and catalog offline")
	version := flags.Bool("version", false, "print version")
	printCatalog := flags.Bool("catalog", false, "print embedded operation catalog")
	discover := flags.String("discover", "", "read-only firmware/package discovery for a profile, then exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	modes := 0
	for _, b := range []bool{*check, *version, *printCatalog, *discover != ""} {
		if b {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("--check, --version, --catalog and --discover are mutually exclusive")
	}
	if *version {
		_, err := fmt.Fprintln(stdout, mcpserver.Version)
		return err
	}
	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	if *printCatalog {
		_, err := stdout.Write(catalog.Data)
		return err
	}
	c := new(config.Config)
	base, err := serverconfig.Load(*configPath, c)
	if err != nil {
		return err
	}
	if *transport != "" {
		c.Server.Transport = *transport
	}
	if err := c.Normalize(base); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(stderr, nil))
	}
	e := engine.New(c, cat, logger)
	defer e.Close()
	server, err := mcpserver.New(e)
	if err != nil {
		return err
	}
	if *check {
		return json.NewEncoder(stdout).Encode(map[string]any{"valid": true, "profiles": len(c.Profiles), "catalog_operations": len(cat.Operations), "transport": c.Server.Transport})
	}
	if *discover != "" {
		out, err := e.Discover(ctx, *discover)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(out)
	}
	if c.Server.Transport == "http" {
		return mcphttp.Serve(ctx, server, c.Server.HTTP, logger)
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}
