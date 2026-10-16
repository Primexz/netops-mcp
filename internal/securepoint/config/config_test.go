package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAndUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "profiles.toml")
	content := "[profiles.main]\nhost='192.0.2.1'\nusername='admin'\npassword_env='UTM_PASS'\n"
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(name)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Profiles["main"]
	if !p.IsReadOnly() || p.Port != 22 || p.TimeoutSeconds != 30 || c.ArtifactDir != filepath.Join(dir, "artifacts") || c.Server.Transport != "stdio" || c.Server.HTTP.Listen != "127.0.0.1:8080" || c.Server.HTTP.TokenEnv != "SP_UTM_MCP_HTTP_TOKEN" {
		t.Fatalf("defaults %#v", p)
	}
	if err := os.WriteFile(name, []byte(content+"allow_lifecyle=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(name); err == nil {
		t.Fatal("misspelled permission was ignored")
	}
}

func TestRootProfileMustBeExplicit(t *testing.T) {
	c := Config{Profiles: map[string]Profile{"root": {Host: "192.0.2.1", Username: "root", PasswordEnv: "PASS"}}}
	if err := c.Normalize(t.TempDir()); err == nil || !strings.Contains(err.Error(), "root_cli") {
		t.Fatal(err)
	}
}

func TestFreshServerSyntaxAndOfflineDefaults(t *testing.T) {
	profile := "[profiles.headquarters]\nhost='192.0.2.10'\nusername='admin'\npassword_env='SP_UTM_CONFIG_TEST_PASSWORD'\nknown_hosts='known_hosts/sp-utm'\nkey_file='keys/admin'\n"
	for _, tc := range []struct {
		name   string
		prefix string
		valid  bool
	}{
		{"defaults", "", true},
		{"http defaults", "[server]\ntransport='http'\n", true},
		{"explicit token", "[server]\ntransport='http'\n[server.http]\ntoken='checked at startup only'\n", true},
		{"top level transport", "transport='http'\n", false},
		{"top level http", "[http]\nlisten='127.0.0.1:8080'\n", false},
		{"bearer token env", "[server.http]\nbearer_token_env='TOKEN'\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SP_UTM_MCP_HTTP_TOKEN", "")
			t.Setenv("SP_UTM_CONFIG_TEST_PASSWORD", "")
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(path, []byte(tc.prefix+profile), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if !tc.valid {
				if err == nil {
					t.Fatal("unknown field accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Server.HTTP.TokenEnv != "SP_UTM_MCP_HTTP_TOKEN" || c.Server.HTTP.Listen != "127.0.0.1:8080" {
				t.Fatal(c.Server)
			}
			p := c.Profiles["headquarters"]
			if p.KnownHosts != filepath.Join(dir, "known_hosts/sp-utm") || p.KeyFile != filepath.Join(dir, "keys/admin") {
				t.Fatalf("unresolved paths: %+v", p)
			}
		})
	}
}

func TestProfileValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"invalid profile name", func(c *Config) { c.Profiles["../router"] = c.Profiles["main"] }},
		{"host url", func(c *Config) { p := c.Profiles["main"]; p.Host = "https://router"; c.Profiles["main"] = p }},
		{"host port", func(c *Config) { p := c.Profiles["main"]; p.Host = "router:22"; c.Profiles["main"] = p }},
		{"password env", func(c *Config) { p := c.Profiles["main"]; p.PasswordEnv = "${PASSWORD}"; c.Profiles["main"] = p }},
		{"passphrase env", func(c *Config) { p := c.Profiles["main"]; p.KeyPassphraseEnv = "BAD NAME"; c.Profiles["main"] = p }},
		{"username", func(c *Config) { p := c.Profiles["main"]; p.Username = "admin\n"; c.Profiles["main"] = p }},
		{"auth missing", func(c *Config) { p := c.Profiles["main"]; p.PasswordEnv = ""; c.Profiles["main"] = p }},
		{"json without root", func(c *Config) { p := c.Profiles["main"]; p.JSONOutput = true; c.Profiles["main"] = p }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Profiles: map[string]Profile{"main": {Host: "router.example", Username: "admin", PasswordEnv: "PASS"}}}
			tc.change(&c)
			if err := c.Normalize(t.TempDir()); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}

func TestPreservesPermissionsAndSSHAuthentication(t *testing.T) {
	for _, auth := range []string{"password", "key", "agent"} {
		t.Run(auth, func(t *testing.T) {
			p := Profile{Host: "2001:db8::1", Username: "root", RootCLI: true, JSONOutput: true, ReadOnly: new(false), AllowDiagnostics: true, AllowSensitiveExports: true, AllowFileTransfer: true, AllowLifecycle: true, AllowUnverified: true, Groups: []string{"system"}}
			switch auth {
			case "password":
				p.PasswordEnv = "SP_UTM_CONFIG_TEST_PASSWORD"
			case "key":
				p.KeyFile = "key"
				p.KeyPassphraseEnv = "SP_UTM_CONFIG_TEST_PASSPHRASE"
			case "agent":
				p.SSHAgent = true
			}
			c := Config{Profiles: map[string]Profile{"main": p}}
			if err := c.Normalize(t.TempDir()); err != nil {
				t.Fatal(err)
			}
			p = c.Profiles["main"]
			if p.IsReadOnly() || !p.RootCLI || !p.JSONOutput || !p.AllowDiagnostics || !p.AllowSensitiveExports || !p.AllowFileTransfer || !p.AllowLifecycle || !p.AllowUnverified || len(p.Groups) != 1 || p.Address() != "[2001:db8::1]:22" {
				t.Fatalf("profile behavior changed: %+v", p)
			}
		})
	}
}

func TestStandaloneExample(t *testing.T) {
	c, err := Load("../../../configs/sp-utm.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Profiles) != 2 || c.Profiles["headquarters"].PasswordEnv != "SP_UTM_HQ_PASSWORD" || !c.Profiles["headquarters"].IsReadOnly() || !c.Profiles["branch"].IsReadOnly() || c.Server.HTTP.Listen != "127.0.0.1:8080" {
		t.Fatalf("example settings: %+v", c)
	}
}
