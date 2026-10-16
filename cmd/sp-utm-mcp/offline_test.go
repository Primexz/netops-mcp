package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpAndExclusiveOutputModes(t *testing.T) {
	var output, diagnostics bytes.Buffer
	if err := run(t.Context(), []string{"--help"}, &output, &diagnostics, nil); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 || !strings.Contains(diagnostics.String(), "Usage of sp-utm-mcp:") || !strings.Contains(diagnostics.String(), ".local/sp-utm.toml") {
		t.Fatalf("incorrect help: stdout=%s stderr=%s", output.String(), diagnostics.String())
	}
	modes := [][]string{{"--check"}, {"--version"}, {"--catalog"}, {"--discover", "fixture"}}
	for i, first := range modes {
		for _, second := range modes[i+1:] {
			args := append(append([]string{}, first...), second...)
			if err := run(t.Context(), args, io.Discard, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
				t.Fatalf("conflicting modes %v: %v", args, err)
			}
		}
	}
}

func TestCheckRegistersSchemasOfflineForBothTransports(t *testing.T) {
	dir := t.TempDir()
	configuration := filepath.Join(dir, "profiles.toml")
	const fixture = `[server]
transport = 'invalid-until-overridden'
[server.http]
listen = '127.0.0.1:0'
token_env = 'OFFLINE_SCHEMA_CHECK_HTTP_TOKEN'
tls_cert_file = 'missing/cert.pem'
tls_key_file = 'missing/key.pem'
[profiles.fixture]
host = '192.0.2.1'
username = 'admin'
password_env = 'OFFLINE_SCHEMA_CHECK_DEVICE_PASSWORD'
known_hosts = 'missing/known_hosts'
key_file = 'missing/id_ed25519'
`
	if err := os.WriteFile(configuration, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	// Invalid secret values and nonexistent credential/TLS files must not affect
	// configuration or schema validation. Engine/server construction stays lazy.
	t.Setenv("OFFLINE_SCHEMA_CHECK_HTTP_TOKEN", "invalid token with spaces")
	t.Setenv("OFFLINE_SCHEMA_CHECK_DEVICE_PASSWORD", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, transport := range []string{"stdio", "http"} {
		var output, diagnostics bytes.Buffer
		args := []string{"--config", configuration, "--transport", transport, "--check"}
		if err := run(t.Context(), args, &output, &diagnostics, logger); err != nil {
			t.Fatal(args, err)
		}
		var result struct {
			Valid      bool
			Transport  string
			Profiles   int
			Operations int `json:"catalog_operations"`
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Valid || result.Transport != transport || result.Profiles != 1 || result.Operations == 0 || diagnostics.Len() != 0 {
			t.Fatalf("offline schema check: %s; stderr=%s", output.String(), diagnostics.String())
		}
	}
	if err := run(t.Context(), []string{"--config", configuration, "--check"}, io.Discard, io.Discard, logger); err == nil {
		t.Fatal("invalid configured transport accepted without override")
	}
}
