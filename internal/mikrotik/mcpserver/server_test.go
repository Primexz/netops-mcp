package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/mcphttp"
	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/engine"
	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

func fixtureServer(t *testing.T, write bool, groups []string) (*mcp.Server, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == "GET" {
			_, _ = fmt.Fprint(w, `[{".id":"*A","address":"192.0.2.1/24","interface":"ether2"}]`)
		} else {
			_, _ = fmt.Fprint(w, `{".id":"*B"}`)
		}
	})
	p.ReadOnly = new(!write)
	c := &config.Config{Groups: groups, Profiles: map[string]config.Profile{"main": p}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(c, cat, nil)
	t.Cleanup(e.Close)
	s, err := New(e)
	if err != nil {
		t.Fatal(err)
	}
	return s, calls
}

func inMemory(t *testing.T, s *mcp.Server) *mcp.ClientSession {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		_ = ss.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs
}
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func checkToolsAndCalls(t *testing.T, cs *mcp.ClientSession, calls *atomic.Int32) {
	t.Helper()
	var names []string
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
		if tool.Name == "mikrotik_ip_address_create" && tool.Annotations.ReadOnlyHint {
			t.Fatal("mutation advertised as read-only")
		}
	}
	if len(names) != 106 || !slices.Contains(names, "mikrotik_profiles_list") || !slices.Contains(names, "mikrotik_safe_mode_confirm") {
		t.Fatalf("wrong tools: %d", len(names))
	}
	if r := call(t, cs, "mikrotik_ip_address_list", map[string]any{"profile": "main"}); r.IsError || r.StructuredContent == nil {
		t.Fatal(r)
	}
	if r := call(t, cs, "mikrotik_ip_address_create", map[string]any{"profile": "main", "parameters": map[string]any{"address": "192.0.2.2/24", "interface": "ether2"}}); r.IsError {
		t.Fatal(r)
	}
	before := calls.Load()
	for _, args := range []map[string]any{
		{"profile": "main", "id": "*A", "parameters": map[string]any{"dynamic": true}},
		{"profile": "main", "id": "*A", "parameters": map[string]any{"address": "192.0.2.1/24"}, "command": "system/reboot"},
		{"profile": "main", "id": "0", "parameters": map[string]any{"comment": "wrong selector"}},
	} {
		if r := call(t, cs, "mikrotik_ip_address_update", args); !r.IsError {
			t.Fatal("invalid mutation accepted")
		}
	}
	if calls.Load() != before {
		t.Fatal("invalid request reached router")
	}
}

func TestProtocolDiscoverySchemasAndCalls(t *testing.T) {
	s, calls := fixtureServer(t, true, nil)
	checkToolsAndCalls(t, inMemory(t, s), calls)
}

func TestGroupExposureAndReadOnly(t *testing.T) {
	s, calls := fixtureServer(t, false, []string{"address"})
	cs := inMemory(t, s)
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(tool.Name, "firewall") {
			t.Fatal("disabled tool exposed")
		}
	}
	r := call(t, cs, "mikrotik_ip_address_create", map[string]any{"profile": "main", "parameters": map[string]any{"address": "192.0.2.2/24", "interface": "ether2"}})
	if !r.IsError || calls.Load() != 0 {
		t.Fatal("read-only bypass", r)
	}
	r = call(t, cs, "mikrotik_operation_schema", map[string]any{"operation": "mikrotik_ip_address_update"})
	if r.IsError {
		t.Fatal(r)
	}
	b, _ := json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), "manual.mikrotik.com") || !strings.Contains(string(b), "read_only") {
		t.Fatal("missing provenance/schema", string(b))
	}
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func TestStreamableHTTPProtocol(t *testing.T) {
	s, calls := fixtureServer(t, true, nil)
	t.Setenv("MIKROTIK_TEST_HTTP_TOKEN", "test-token-0123456789abcdefghijklmnopqrstuvwxyz")
	h, err := mcphttp.NewHandler(s, config.HTTP{TokenEnv: "MIKROTIK_TEST_HTTP_TOKEN", MaxRequestBytes: 1 << 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(h)
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "http-fixture", Version: "1"}, nil)
	cs, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL + "/mcp", MaxRetries: -1, DisableStandaloneSSE: true, HTTPClient: &http.Client{Transport: bearerTransport{token: "test-token-0123456789abcdefghijklmnopqrstuvwxyz", base: http.DefaultTransport}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	checkToolsAndCalls(t, cs, calls)
}

func TestHTTPAuthenticationEveryRequestAndOrigins(t *testing.T) {
	s, _ := fixtureServer(t, false, nil)
	t.Setenv("MIKROTIK_TEST_HTTP_TOKEN", "")
	settings := config.HTTP{TokenEnv: "MIKROTIK_TEST_HTTP_TOKEN"}
	if _, err := mcphttp.NewHandler(s, settings, nil); err == nil {
		t.Fatal("empty token accepted")
	}
	t.Setenv("MIKROTIK_TEST_HTTP_TOKEN", "test-token-0123456789abcdefghijklmnopqrstuvwxyz")
	h, err := mcphttp.NewHandler(s, settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"POST", "GET", "DELETE", "OPTIONS"} {
		for _, auth := range []string{"", "Bearer wrong", "Basic dGVzdA=="} {
			r := httptest.NewRequest(method, "http://localhost/mcp", nil)
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal(method, auth, w.Code)
			}
		}
	}
	for _, origin := range []string{"https://attacker.example", "null"} {
		r := httptest.NewRequest("POST", "http://localhost/mcp", nil)
		r.Header.Set("Authorization", "Bearer test-token-0123456789abcdefghijklmnopqrstuvwxyz")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal(origin, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://localhost/sse", nil)
	r.Header.Set("Authorization", "Bearer test-token-0123456789abcdefghijklmnopqrstuvwxyz")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("legacy SSE route exposed")
	}
}

func TestHTTPLegacyProtocolAndInputLimit(t *testing.T) {
	s, _ := fixtureServer(t, false, nil)
	t.Setenv("MIKROTIK_TEST_HTTP_TOKEN", "test-token-0123456789abcdefghijklmnopqrstuvwxyz")
	h, err := mcphttp.NewHandler(s, config.HTTP{TokenEnv: "MIKROTIK_TEST_HTTP_TOKEN", MaxRequestBytes: 1 << 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-token-0123456789abcdefghijklmnopqrstuvwxyz")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy","version":"1"}}}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("legacy initialize: %d %s", w.Code, w.Body.String())
	}
	w = post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mikrotik_profiles_list","arguments":{}}}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"profiles"`) {
		t.Fatalf("legacy call: %d %s", w.Code, w.Body.String())
	}
	w = post(strings.Repeat(" ", 1<<20) + `{}`)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request: %d", w.Code)
	}
	// The cap also applies when Content-Length is not known (chunked uploads).
	r := httptest.NewRequest("POST", "http://localhost/mcp", io.NopCloser(strings.NewReader(strings.Repeat(" ", 1<<20)+`{}`)))
	r.Header.Set("Authorization", "Bearer test-token-0123456789abcdefghijklmnopqrstuvwxyz")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked request: %d", w.Code)
	}
}
