package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	text := "[profiles.main]\nhost='2001:db8::1'\nusername='mcp'\npassword_env='NOT_SET_FOR_OFFLINE_CHECK'\nca_file='certs/router.pem'\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Profiles["main"]
	if !p.IsReadOnly() || p.Scheme != "https" || p.Port != 443 || p.TimeoutSeconds != 30 || p.MaxOutputBytes != 4<<20 {
		t.Fatalf("wrong defaults: %+v", p)
	}
	if p.Address() != "[2001:db8::1]:443" || p.CAFile != filepath.Join(dir, "certs/router.pem") {
		t.Fatalf("wrong paths/address: %+v", p)
	}
	if c.Server.Transport != "stdio" || c.Server.HTTP.Listen != "127.0.0.1:8081" || c.Server.HTTP.TokenEnv != "MIKROTIK_MCP_HTTP_TOKEN" {
		t.Fatal(c.Server)
	}
	if err := os.WriteFile(path, []byte(text+"read_onyl=false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestRESTSchemesAndPorts(t *testing.T) {
	for _, tc := range []struct {
		name, settings, scheme string
		port                   int
		wantError              string
	}{
		{name: "default", scheme: "https", port: 443},
		{name: "https", settings: "scheme='https'\n", scheme: "https", port: 443},
		{name: "http", settings: "scheme='http'\n", scheme: "http", port: 80},
		{name: "custom https port", settings: "scheme='https'\nport=8443\n", scheme: "https", port: 8443},
		{name: "custom http port", settings: "scheme='http'\nport=8080\n", scheme: "http", port: 8080},
		{name: "http explicit 443", settings: "scheme='http'\nport=443\n", scheme: "http", port: 443},
		{name: "invalid scheme", settings: "scheme='ftp'\n", wantError: "scheme must be http or https"},
		{name: "uppercase scheme", settings: "scheme='HTTP'\n", wantError: "scheme must be http or https"},
		{name: "http ca conflict", settings: "scheme='http'\nca_file='missing.pem'\n", wantError: "ca_file requires scheme=https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			text := "[profiles.main]\nhost='2001:db8::1'\nusername='mcp'\npassword_env='UNSET_OFFLINE_PASSWORD'\n" + tc.settings
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := c.Profiles["main"]
			if p.Scheme != tc.scheme || p.Port != tc.port {
				t.Fatalf("endpoint = %s://%s, want %s on port %d", p.Scheme, p.Address(), tc.scheme, tc.port)
			}
		})
	}
}

func TestValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"empty profiles", func(c *Config) { c.Profiles = nil }},
		{"unknown global group", func(c *Config) { c.Groups = []string{"typo"} }},
		{"unknown profile group", func(c *Config) { p := c.Profiles["main"]; p.Groups = []string{"typo"}; c.Profiles["main"] = p }},
		{"url as host", func(c *Config) { p := c.Profiles["main"]; p.Host = "https://router/rest"; c.Profiles["main"] = p }},
		{"invalid port", func(c *Config) { p := c.Profiles["main"]; p.Port = 65536; c.Profiles["main"] = p }},
		{"negative timeout", func(c *Config) { p := c.Profiles["main"]; p.TimeoutSeconds = -1; c.Profiles["main"] = p }},
		{"small limit", func(c *Config) { p := c.Profiles["main"]; p.MaxOutputBytes = 1; c.Profiles["main"] = p }},
		{"bad env name", func(c *Config) { p := c.Profiles["main"]; p.PasswordEnv = "a=b"; c.Profiles["main"] = p }},
		{"bad user", func(c *Config) { p := c.Profiles["main"]; p.Username = "user:pass"; c.Profiles["main"] = p }},
		{"bad token env", func(c *Config) { c.Server.HTTP.TokenEnv = "not valid" }},
		{"bad transport", func(c *Config) { c.Server.Transport = "sse" }},
		{"bad listen", func(c *Config) { c.Server.HTTP.Listen = "8080" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Profiles: map[string]Profile{"main": {Host: "router.example", Username: "mcp", PasswordEnv: "PASS"}}}
			tc.change(&c)
			if err := c.Normalize(t.TempDir()); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestHomePathsAndHTTPCheckWithoutSecrets(t *testing.T) {
	c := Config{Server: Server{Transport: "http", HTTP: HTTP{TokenEnv: "MCP_TOKEN_NOT_SET"}}, Profiles: map[string]Profile{"main": {Host: "192.0.2.1", Username: "mcp", PasswordEnv: "ROUTER_PASS_NOT_SET", CAFile: "~/router.pem", ReadOnly: new(false)}}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if c.Profiles["main"].CAFile != filepath.Join(homeDir, "router.pem") || c.Profiles["main"].IsReadOnly() {
		t.Fatal(c.Profiles["main"])
	}
}

func TestFreshServerSyntaxAndOfflineDefaults(t *testing.T) {
	profile := "[profiles.headquarters]\nhost='192.0.2.10'\nusername='mcp'\npassword_env='MIKROTIK_CONFIG_TEST_PASSWORD'\n"
	for _, tc := range []struct {
		name   string
		prefix string
		valid  bool
	}{
		{"http defaults", "[server]\ntransport='http'\n", true},
		{"shared http fields", "[server]\ntransport='http'\n[server.http]\nlisten='0.0.0.0:8443'\ntoken='checked at startup only'\nallowed_hosts=['MCP.EXAMPLE.COM']\nallowed_origins=['https://CLIENT.EXAMPLE.COM']\ntls_cert_file='missing.pem'\ntls_key_file='missing.key'\nmax_request_bytes=1024\n", true},
		{"top level transport", "transport='http'\n", false},
		{"top level http", "[http]\nlisten='127.0.0.1:8081'\n", false},
		{"bearer token env", "[server.http]\nbearer_token_env='TOKEN'\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MIKROTIK_MCP_HTTP_TOKEN", "")
			t.Setenv("MIKROTIK_CONFIG_TEST_PASSWORD", "")
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
			if c.Server.HTTP.TokenEnv != "MIKROTIK_MCP_HTTP_TOKEN" {
				t.Fatal(c.Server)
			}
			if tc.name == "http defaults" && c.Server.HTTP.Listen != "127.0.0.1:8081" {
				t.Fatal(c.Server)
			}
			if tc.name == "shared http fields" && (c.Server.HTTP.TLSCertFile != filepath.Join(dir, "missing.pem") || c.Server.HTTP.TLSKeyFile != filepath.Join(dir, "missing.key") || c.Server.HTTP.AllowedHosts[0] != "mcp.example.com" || c.Server.HTTP.AllowedOrigins[0] != "https://client.example.com" || c.Server.HTTP.MaxRequestBytes != 1024) {
				t.Fatal(c.Server)
			}
		})
	}
}

func TestStandaloneExample(t *testing.T) {
	c, err := Load("../../../configs/mikrotik.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Profiles) != 2 || c.Profiles["headquarters"].PasswordEnv != "MIKROTIK_HQ_PASSWORD" || !c.Profiles["headquarters"].IsReadOnly() || !c.Profiles["branch"].IsReadOnly() || c.Server.HTTP.Listen != "127.0.0.1:8081" {
		t.Fatalf("example settings: %+v", c)
	}
}

func TestSafeModeOfflineConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, settings string
		valid          bool
	}{
		{"defaults", "", true},
		{"protected", "required=true\nknown_hosts='known_hosts/router'\n", true},
		{"missing host keys", "required=true\n", false},
		{"bad SSH port", "ssh_port=65536\n", false},
		{"short deadline", "timeout_seconds=29\n", false},
		{"long deadline", "timeout_seconds=601\n", false},
		{"minimum deadline", "timeout_seconds=30\n", true},
		{"maximum deadline", "timeout_seconds=600\n", true},
		{"unknown field", "enabled=true\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			text := "[profiles.main]\nhost='router.example'\nusername='mcp'\npassword_env='NO_SECRET_NEEDED'\n[profiles.main.safe_mode]\n" + tc.settings
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid safe mode accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s := c.Profiles["main"].SafeMode
			if s.SSHPort != 22 {
				t.Fatal(s)
			}
			if tc.name == "defaults" && (s.Required || s.TimeoutSeconds != 300) {
				t.Fatal(s)
			}
			if tc.name == "protected" && s.KnownHosts != filepath.Join(dir, "known_hosts/router") {
				t.Fatal(s)
			}
		})
	}
}
