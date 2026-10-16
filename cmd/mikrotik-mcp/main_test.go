package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestOfflineModes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, args := range [][]string{{"--version"}, {"--catalog"}, {"--config", "../../configs/mikrotik.example.toml", "--check"}, {"--config", "../../configs/mikrotik.example.toml", "--transport", "http", "--check"}} {
		var out, stderr bytes.Buffer
		if err := run(t.Context(), args, &out, &stderr, logger); err != nil {
			t.Fatal(args, err)
		}
		if len(args) > 1 && !json.Valid(out.Bytes()) {
			t.Fatalf("not JSON: %s", out.Bytes())
		}
	}
	for _, args := range [][]string{{"--check", "--version"}, {"--config", "../../configs/mikrotik.example.toml", "--transport", "invalid"}, {"unexpected"}} {
		if err := run(t.Context(), args, io.Discard, io.Discard, logger); err == nil {
			t.Fatal("invalid mode accepted", args)
		}
	}
}

func TestBuiltBinaryStdio(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "mikrotik-mcp")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	configuration := filepath.Join(dir, "profiles.toml")
	if err := os.WriteFile(configuration, []byte("[profiles.test]\nhost='192.0.2.1'\nusername='mcp'\npassword_env='UNSET_BINARY_SMOKE_PASSWORD'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "--config", configuration)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "binary-smoke", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatalf("stdio initialize: %v", err)
	}
	if got := cs.InitializeResult().ServerInfo.Name; got != "mikrotik-mcp" {
		t.Fatalf("server identity %q, want mikrotik-mcp", got)
	}
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "mikrotik_profiles_list", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("profile call: %v %v", result, err)
	}
	count := 0
	for _, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 106 {
		t.Fatalf("expected 106 tools, got %d", count)
	}
	if err := cs.Close(); err != nil {
		t.Fatal(err)
	}
}
