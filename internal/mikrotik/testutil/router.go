// Package testutil supplies a local TLS RouterOS fixture for offline tests.
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
	s := httptest.NewTLSServer(handler)
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
	ca := filepath.Join(t.TempDir(), "router-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MIKROTIK_FIXTURE_PASSWORD", "fixture-password")
	return s, config.Profile{Host: host, Port: n, Username: "fixture-user", PasswordEnv: "MIKROTIK_FIXTURE_PASSWORD", CAFile: ca, ReadOnly: new(false), TimeoutSeconds: 3, MaxOutputBytes: 4 << 20}
}
