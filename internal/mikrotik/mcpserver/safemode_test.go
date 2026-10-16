package mcpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/mcphttp"
	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/engine"
	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

func toolBody(t *testing.T, r *mcp.CallToolResult) map[string]any {
	t.Helper()
	b, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "fixture-password") {
		t.Fatal("credentials leaked")
	}
	return out
}

func TestSafeModeWorkflowOverBothTransports(t *testing.T) {
	for _, transport := range []string{"stdio", "http"} {
		t.Run(transport, func(t *testing.T) {
			f := testutil.NewSafeRouter(t)
			c := &config.Config{Groups: []string{"address"}, Profiles: map[string]config.Profile{"main": f.Profile, "other": f.Profile}}
			if err := c.Normalize(t.TempDir()); err != nil {
				t.Fatal(err)
			}
			cat, err := catalog.Load()
			if err != nil {
				t.Fatal(err)
			}
			e := engine.New(c, cat, nil)
			defer e.Close()
			s, err := New(e)
			if err != nil {
				t.Fatal(err)
			}
			var cs *mcp.ClientSession
			if transport == "stdio" {
				cs = inMemory(t, s)
			} else {
				h, err := mcphttp.NewHandler(s, config.HTTP{Token: "safe-mode-test-token-0123456789abcdefghijklmnopqrstuvwxyz"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				hs := httptest.NewServer(h)
				defer hs.Close()
				client := mcp.NewClient(&mcp.Implementation{Name: "safe-mode-fixture", Version: "1"}, nil)
				cs, err = client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: hs.URL + "/mcp", MaxRetries: -1, DisableStandaloneSSE: true, HTTPClient: &http.Client{Transport: bearerTransport{token: "safe-mode-test-token-0123456789abcdefghijklmnopqrstuvwxyz", base: http.DefaultTransport}}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = cs.Close() }()
			}
			write := func(id string) *mcp.CallToolResult {
				a := map[string]any{"profile": "main", "id": "*A", "parameters": map[string]any{"comment": "changed"}}
				if id != "" {
					a["safe_mode_id"] = id
				}
				return call(t, cs, "mikrotik_ip_address_update", a)
			}
			if r := write(""); !r.IsError || f.Writes.Load() != 0 {
				t.Fatal("unprotected write reached router", r)
			}
			r := call(t, cs, "mikrotik_safe_mode_begin", map[string]any{"profile": "main"})
			if r.IsError {
				t.Fatal(r)
			}
			v := toolBody(t, r)
			id := v["safe_mode_id"].(string)
			if _, err := time.Parse(time.RFC3339Nano, v["expires_at"].(string)); err != nil {
				t.Fatal(err)
			}
			if r := call(t, cs, "mikrotik_safe_mode_confirm", map[string]any{"profile": "other", "safe_mode_id": id}); !r.IsError {
				t.Fatal("cross-profile confirmation accepted")
			}
			if r := call(t, cs, "mikrotik_safe_mode_begin", map[string]any{"profile": "other"}); !r.IsError {
				t.Fatal("another profile took over router safe mode")
			}
			if r := write(id); r.IsError {
				t.Fatal(r)
			}
			r = call(t, cs, "mikrotik_safe_mode_status", map[string]any{"profile": "main"})
			if r.IsError || toolBody(t, r)["state"] != "active" || f.Commits.Load() != 0 {
				t.Fatal("window did not survive tool requests", r)
			}
			r = call(t, cs, "mikrotik_safe_mode_confirm", map[string]any{"profile": "main", "safe_mode_id": id})
			if r.IsError || toolBody(t, r)["state"] != "committed" || f.Value() != "changed" {
				t.Fatal(r)
			}
			if r := write(id); !r.IsError {
				t.Fatal("committed session reused")
			}
			// A second window can be explicitly rolled back without affecting the
			// first window's committed configuration.
			r = call(t, cs, "mikrotik_safe_mode_begin", map[string]any{"profile": "main"})
			if r.IsError {
				t.Fatal(r)
			}
			id = toolBody(t, r)["safe_mode_id"].(string)
			r = call(t, cs, "mikrotik_safe_mode_rollback", map[string]any{"profile": "main", "safe_mode_id": id})
			if r.IsError || toolBody(t, r)["state"] != "rollback_requested" {
				t.Fatal(r)
			}
		})
	}
}
