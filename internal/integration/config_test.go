package integration_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	mtconfig "github.com/Primexz/netops-mcp/internal/mikrotik/config"
	spconfig "github.com/Primexz/netops-mcp/internal/securepoint/config"
)

// A common configuration must mean the same thing to both independently runnable servers.
func TestCommonConfigurationContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network.toml")
	const text = `groups = ["system"]
[server]
transport = "http"
[server.http]
listen = "127.0.0.1:8443"
token_env = "NETOPS_TEST_HTTP_TOKEN"
allowed_hosts = ["MCP.EXAMPLE.COM"]
allowed_origins = ["https://CLIENT.EXAMPLE.COM"]
tls_cert_file = "certs/server.pem"
tls_key_file = "certs/server-key.pem"
max_request_bytes = 2048
[profiles.main]
host = "192.0.2.10"
port = 12345
username = "mcp"
password_env = "NETOPS_TEST_DEVICE_PASSWORD"
read_only = true
timeout_seconds = 45
max_output_bytes = 2048
groups = ["system"]
`
	// Neither invalid secret values nor absent certificate files may prevent an offline check.
	t.Setenv("NETOPS_TEST_HTTP_TOKEN", "invalid-for-http-startup")
	t.Setenv("NETOPS_TEST_DEVICE_PASSWORD", "")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	sp, err := spconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	mt, err := mtconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sp.Server, mt.Server) || !reflect.DeepEqual(sp.Groups, mt.Groups) {
		t.Fatalf("common server configuration differs: SP=%+v MT=%+v", sp.Server, mt.Server)
	}
	if sp.Server.HTTP.TLSCertFile != filepath.Join(dir, "certs/server.pem") || sp.Server.HTTP.AllowedHosts[0] != "mcp.example.com" {
		t.Fatal("shared paths or authorities were not normalized")
	}
	a, b := sp.Profiles["main"], mt.Profiles["main"]
	if a.Host != b.Host || a.Port != b.Port || a.Username != b.Username || a.PasswordEnv != b.PasswordEnv ||
		a.Timeout() != b.Timeout() || a.MaxOutputBytes != b.MaxOutputBytes || !a.IsReadOnly() || !b.IsReadOnly() ||
		!reflect.DeepEqual(a.Groups, b.Groups) {
		t.Fatal("common profile settings differ")
	}
}

func TestIndependentServerDefaults(t *testing.T) {
	sp := spconfig.Config{Profiles: map[string]spconfig.Profile{"main": {Host: "192.0.2.1", Username: "mcp", PasswordEnv: "UNSET_NETOPS_PASSWORD"}}}
	mt := mtconfig.Config{Profiles: map[string]mtconfig.Profile{"main": {Host: "192.0.2.1", Username: "mcp", PasswordEnv: "UNSET_NETOPS_PASSWORD"}}}
	if err := sp.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := mt.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if sp.Server.HTTP.Listen != "127.0.0.1:8080" || mt.Server.HTTP.Listen != "127.0.0.1:8081" ||
		sp.Server.HTTP.TokenEnv == mt.Server.HTTP.TokenEnv ||
		sp.Server.Transport != "stdio" || mt.Server.Transport != "stdio" {
		t.Fatal("servers must default to separate HTTP listeners and secrets, with stdio selected")
	}
}
