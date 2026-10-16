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
	"slices"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/mcphttp"
	"github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
	"github.com/Primexz/netops-mcp/internal/securepoint/engine"
	"github.com/Primexz/netops-mcp/internal/securepoint/mcpserver"
	"github.com/Primexz/netops-mcp/internal/securepoint/transport"
	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, logger); err != nil {
		logger.Error("sp-utm-mcp stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, logger *slog.Logger) error {
	flags := flag.NewFlagSet("sp-utm-mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFile := flags.String("config", ".local/sp-utm.toml", "appliance profiles TOML")
	check := flags.Bool("check", false, "validate configuration and catalog without contacting appliances")
	version := flags.Bool("version", false, "print version")
	printCatalog := flags.Bool("catalog", false, "print the embedded operation catalog as JSON")
	transportMode := flags.String("transport", "", "MCP transport: stdio or http (overrides configuration)")
	discover := flags.String("discover", "", "read-only firmware/command discovery for a named profile, then exit")
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
	for _, enabled := range []bool{*check, *version, *printCatalog, *discover != ""} {
		if enabled {
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
	base, err := serverconfig.Load(*configFile, c)
	if err != nil {
		return err
	}
	if *transportMode != "" {
		c.Server.Transport = *transportMode
	}
	if err := c.Normalize(base); err != nil {
		return err
	}
	for _, groups := range append([][]string{c.Groups}, profileGroups(c)...) {
		for _, g := range groups {
			if !slices.Contains(cat.Groups(), g) {
				return fmt.Errorf("unknown feature group %q", g)
			}
		}
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(stderr, nil))
	}
	e := engine.New(c, cat, transport.SSH{}, logger)
	server, err := mcpserver.New(e)
	if err != nil {
		return err
	}
	if *check {
		return json.NewEncoder(stdout).Encode(map[string]any{"valid": true, "transport": c.Server.Transport, "profiles": len(c.Profiles), "catalog_operations": len(cat.Operations)})
	}
	if *discover != "" {
		capabilities, err := e.Discover(ctx, *discover)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(capabilities)
	}
	if c.Server.Transport == "http" {
		return mcphttp.Serve(ctx, server, c.Server.HTTP, logger)
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}

func profileGroups(c *config.Config) [][]string {
	var result [][]string
	for _, p := range c.Profiles {
		result = append(result, p.Groups)
	}
	return result
}
