package serverconfig

import (
	"path/filepath"
	"testing"
)

func TestHTTPDefaultsAndRemoteTLS(t *testing.T) {
	var h HTTP
	if err := h.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if h.Listen != "127.0.0.1:8080" || h.TokenEnv != "NETOPS_MCP_HTTP_TOKEN" || h.MaxRequestBytes != 16<<20 {
		t.Fatalf("defaults: %#v", h)
	}
	base := t.TempDir()
	secure := HTTP{Listen: "0.0.0.0:8443", AllowedHosts: []string{"MCP.EXAMPLE.COM"}, TLSCertFile: "cert.pem", TLSKeyFile: "key.pem"}
	if err := secure.Normalize(base); err != nil {
		t.Fatal(err)
	}
	if secure.TLSCertFile != filepath.Join(base, "cert.pem") || secure.AllowedHosts[0] != "mcp.example.com" {
		t.Fatalf("normalized: %#v", secure)
	}
	for _, h := range []HTTP{
		{Listen: "0.0.0.0:8080"},
		{Listen: "10.0.0.1:8080"},
		{Listen: "0.0.0.0:8443", TLSCertFile: "cert", TLSKeyFile: "key"},
		{TLSCertFile: "cert"},
		{Listen: "127.0.0.1:99999"},
		{AllowedHosts: []string{"*.example.com"}},
		{AllowedHosts: []string{"example.com:443"}},
		{AllowedOrigins: []string{"https://example.com/path"}},
		{AllowedOrigins: []string{"null"}},
		{AllowedOrigins: []string{"https://user:pass@example.com"}},
		{MaxRequestBytes: -1},
	} {
		if err := h.Normalize(base); err == nil {
			t.Errorf("accepted invalid HTTP settings: %#v", h)
		}
	}
}

func TestHTTPOriginsAndHostnames(t *testing.T) {
	for raw, want := range map[string]string{"https://MCP.EXAMPLE.COM:8443": "https://mcp.example.com:8443", "http://[::1]:8080": "http://[::1]:8080"} {
		got, err := Origin(raw)
		if err != nil || got != want {
			t.Fatalf("%s: %s %v", raw, got, err)
		}
	}
	for _, raw := range []string{"*", "https://example.com/", "https://example.com?", "https://example.com#x", "https://example.com#", "https://example.com:0", "file://example.com"} {
		if _, err := Origin(raw); err == nil {
			t.Errorf("accepted origin %q", raw)
		}
	}
}

func TestHTTPStrictHostAndOriginValidation(t *testing.T) {
	for _, name := range []string{"", ".", "-router", "router-", "router..example", "router_name", "router:8080", "[::1]", "fe80::1%en0", "user@router", "router\n", "*.example"} {
		if _, err := HostName(name); err == nil {
			t.Errorf("accepted invalid hostname %q", name)
		}
	}
	for raw, want := range map[string]string{"LOCALHOST": "localhost", "MCP.Example.": "mcp.example.", "2001:0db8::1": "2001:db8::1", "192.0.2.1": "192.0.2.1"} {
		if got, err := HostName(raw); err != nil || got != want {
			t.Errorf("HostName(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, origin := range []string{"https://example.com:", "http://::1", "https://[example.com]", "https://example.com:65536", "https://example.com:abc", "https://example.com?token=secret", "https://example.com\\path", "https://*.example.com"} {
		if _, err := Origin(origin); err == nil {
			t.Errorf("accepted invalid origin %q", origin)
		}
	}
	for _, settings := range []HTTP{
		{Listen: "bad host:8080", TLSCertFile: "cert", TLSKeyFile: "key"},
		{Listen: "[::]:8443", TLSCertFile: "cert", TLSKeyFile: "key"},
		{Listen: ":8443", TLSCertFile: "cert", TLSKeyFile: "key"},
		{TokenEnv: "TOKEN WITH SPACES"},
		{TokenEnv: "2TOKEN"},
		{MaxRequestBytes: 64<<20 + 1},
	} {
		if err := settings.Normalize(t.TempDir()); err == nil {
			t.Errorf("accepted invalid settings: %+v", settings)
		}
	}
}

func TestHTTPValidListenerPolicies(t *testing.T) {
	for _, settings := range []HTTP{
		{Listen: "[::1]:0"},
		{Listen: "localhost:8080"},
		{Listen: "192.0.2.1:8443", TLSCertFile: "cert", TLSKeyFile: "key"},
		{Listen: "0.0.0.0:8443", AllowedHosts: []string{"mcp.example.com"}, TLSCertFile: "cert", TLSKeyFile: "key"},
		{Listen: "[::]:8443", AllowedHosts: []string{"2001:db8::1"}, TLSCertFile: "cert", TLSKeyFile: "key"},
		{MaxRequestBytes: 1024},
		{MaxRequestBytes: 64 << 20},
	} {
		if err := settings.Normalize(t.TempDir()); err != nil {
			t.Errorf("rejected valid settings %+v: %v", settings, err)
		}
	}
}
