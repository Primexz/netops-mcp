package mcpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/mcphttp"
	"github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
	"github.com/Primexz/netops-mcp/internal/securepoint/engine"
)

const httpTestToken = "test-token-0123456789abcdefghijklmnopqrstuvwxyz"

func httpFixture(t *testing.T, write bool) (*mcp.Server, *fixtureRunner) {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	c := &config.Config{Groups: []string{"node", "system"}, ArtifactDir: t.TempDir(), Profiles: map[string]config.Profile{"main": {Host: "192.0.2.1", Username: "admin", PasswordEnv: "PASS", ReadOnly: new(!write)}}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	f := &fixtureRunner{}
	s, err := New(engine.New(c, cat, f, nil))
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

func httpSettings(t *testing.T) config.HTTP {
	t.Helper()
	t.Setenv("MCP_HTTP_TEST_TOKEN", httpTestToken)
	return config.HTTP{TokenEnv: "MCP_HTTP_TEST_TOKEN", AllowedOrigins: []string{"https://client.example"}}
}

type bearerTransport struct{ base http.RoundTripper }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+httpTestToken)
	return b.base.RoundTrip(clone)
}

func httpSession(t *testing.T, s *mcp.Server, secure bool) (*mcp.ClientSession, *httptest.Server) {
	t.Helper()
	handler, err := mcphttp.NewHandler(s, httpSettings(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var host *httptest.Server
	if secure {
		host = httptest.NewTLSServer(handler)
	} else {
		host = httptest.NewServer(handler)
	}
	t.Cleanup(host.Close)
	client := host.Client()
	client.Transport = bearerTransport{base: client.Transport}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "http-test", Version: "1"}, nil)
	cs, err := mcpClient.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: host.URL + "/mcp", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, host
}

func TestHTTPToolsResourcesAndReadOnlyPolicy(t *testing.T) {
	s, f := httpFixture(t, false)
	client, _ := httpSession(t, s, false)
	tools, err := client.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) == 0 {
		t.Fatalf("discovery %v %v", tools, err)
	}
	result := call(t, client, "utm_node_get", map[string]any{"profile": "main"})
	if result.IsError || result.StructuredContent == nil {
		t.Fatal(result)
	}
	resource, err := client.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "securepoint://operations-guide"})
	if err != nil || len(resource.Contents) != 1 {
		t.Fatalf("resource %v %v", resource, err)
	}
	result = call(t, client, "utm_node_new", map[string]any{"profile": "main", "parameters": map[string]any{"name": "web", "address": "192.0.2.9", "zone": "internal"}})
	if !result.IsError {
		t.Fatal("HTTP bypassed the read-only profile")
	}
	for _, cmd := range f.calls {
		if strings.HasPrefix(cmd, "node new") {
			t.Fatal("HTTP mutated a read-only appliance")
		}
	}
}

func TestHTTPSPreviewExecuteAcrossRequests(t *testing.T) {
	s, f := httpFixture(t, true)
	client, _ := httpSession(t, s, true)
	preview := call(t, client, "utm_node_new", map[string]any{"profile": "main", "parameters": map[string]any{"name": "web", "address": "192.0.2.9", "zone": "internal"}})
	if preview.IsError {
		t.Fatal(preview)
	}
	data, _ := json.Marshal(preview.StructuredContent)
	var result struct {
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Plan.ID == "" {
		t.Fatal("missing plan")
	}
	execution := call(t, client, "utm_changes_execute", map[string]any{"profile": "main", "plan_id": result.Plan.ID, "activate": true, "save": true})
	if execution.IsError {
		t.Fatal(execution)
	}
	if f.calls[len(f.calls)-1] != "system config save" {
		t.Fatal("HTTP plan did not persist through execution request")
	}
	if replay := call(t, client, "utm_changes_execute", map[string]any{"profile": "main", "plan_id": result.Plan.ID, "activate": true, "save": true}); !replay.IsError {
		t.Fatal("HTTP replay accepted")
	}
}
