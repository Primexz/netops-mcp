// Package testutil supplies local RouterOS fixtures for offline tests.
package testutil

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
)

func Router(t testing.TB, handler http.HandlerFunc) (*httptest.Server, config.Profile) {
	t.Helper()
	return RouterWithScheme(t, "https", handler)
}

func RouterWithScheme(t testing.TB, scheme string, handler http.HandlerFunc) (*httptest.Server, config.Profile) {
	t.Helper()
	var s *httptest.Server
	switch scheme {
	case "https":
		s = httptest.NewTLSServer(handler)
	case "http":
		s = httptest.NewServer(handler)
	default:
		t.Fatalf("unsupported fixture scheme %q", scheme)
	}
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	var ca string
	if scheme == "https" {
		ca = filepath.Join(t.TempDir(), "router-ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MIKROTIK_FIXTURE_PASSWORD", "fixture-password")
	return s, config.Profile{Scheme: scheme, Host: host, Port: n, Username: "fixture-user", PasswordEnv: "MIKROTIK_FIXTURE_PASSWORD", CAFile: ca, ReadOnly: new(false), TimeoutSeconds: 3, MaxOutputBytes: 4 << 20}
}
