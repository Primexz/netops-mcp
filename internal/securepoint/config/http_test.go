package config

import (
	"testing"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

func TestHTTPSharedContract(t *testing.T) {
	h := serverconfig.HTTP{TokenEnv: "SP_UTM_HTTP_TEST_TOKEN"}
	if err := h.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if host, err := HostName("MCP.EXAMPLE.COM"); err != nil || host != "mcp.example.com" {
		t.Fatalf("hostname: %q, %v", host, err)
	}
	if origin, err := Origin("https://MCP.EXAMPLE.COM"); err != nil || origin != "https://mcp.example.com" {
		t.Fatalf("origin: %q, %v", origin, err)
	}
}
