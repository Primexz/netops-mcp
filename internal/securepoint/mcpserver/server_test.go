package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
	"github.com/Primexz/netops-mcp/internal/securepoint/engine"
	"github.com/Primexz/netops-mcp/internal/securepoint/transport"
)

type fixtureRunner struct {
	calls []string
	fail  string
}

func (f *fixtureRunner) Run(_ context.Context, _ config.Profile, r transport.Request) (transport.Result, error) {
	f.calls = append(f.calls, r.Command)
	if f.fail == r.Command {
		return transport.Result{Started: true}, errors.New("simulated disconnect")
	}
	output := "OK"
	switch r.Command {
	case "system info":
		output = "attribute|value\n---------+-----\nversion|14.1.3"
	case "help":
		output = "node get\nnode new\nrule get\nservice get\nsystem info"
	case "node get":
		output = "id|name|address\n--+----+-------\n1|server|192.0.2.1"
	case "interface zone get":
		output = "id|name\n--+----\n1|internal"
	}
	return transport.Result{Output: output, Started: true}, nil
}

func session(t *testing.T, write bool) (*mcp.ClientSession, *fixtureRunner) {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	c := &config.Config{ArtifactDir: t.TempDir(), Profiles: map[string]config.Profile{"main": {Host: "192.0.2.1", Username: "admin", PasswordEnv: "PASS", ReadOnly: new(!write)}}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	f := &fixtureRunner{}
	e := engine.New(c, cat, f, nil)
	s, err := New(e)
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs, f
}

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	r, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSDKDiscoveryResourcesAndValidatedCalls(t *testing.T) {
	s, f := session(t, false)
	var names []string
	for tool, err := range s.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	if len(names) < 480 || !slices.Contains(names, "utm_rule_new") {
		t.Fatalf("missing tools: %d", len(names))
	}
	r := call(t, s, "utm_node_get", map[string]any{"profile": "main"})
	if r.IsError || r.StructuredContent == nil {
		t.Fatalf("query %#v", r)
	}
	if !slices.Contains(f.calls, "node get") {
		t.Fatal("query never reached transport")
	}
	r = call(t, s, "utm_node_new", map[string]any{"profile": "main", "parameters": map[string]any{"name": "x", "address": "192.0.2.4", "zone": "internal"}})
	if !r.IsError {
		t.Fatal("read-only profile prepared a write")
	}
	for _, cmd := range f.calls {
		if strings.HasPrefix(cmd, "node new") {
			t.Fatal("mutation reached transport")
		}
	}
	before := len(f.calls)
	r = call(t, s, "utm_node_get", map[string]any{"profile": "main", "arbitrary_command": "system reboot"})
	if !r.IsError || len(f.calls) != before {
		t.Fatal("unknown schema property was accepted")
	}
	resource, err := s.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "securepoint://catalog"})
	if err != nil || len(resource.Contents) != 1 || !json.Valid([]byte(resource.Contents[0].Text)) {
		t.Fatalf("resource %v %v", resource, err)
	}
}

func TestSDKPreviewAndExecute(t *testing.T) {
	s, f := session(t, true)
	r := call(t, s, "utm_node_new", map[string]any{"profile": "main", "parameters": map[string]any{"name": "web", "address": "192.0.2.9", "zone": "internal"}})
	if r.IsError {
		t.Fatalf("preview %v", r.Content)
	}
	b, _ := json.Marshal(r.StructuredContent)
	var out struct {
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Plan.ID == "" {
		t.Fatal("no preview ID")
	}
	r = call(t, s, "utm_changes_execute", map[string]any{"profile": "main", "plan_id": out.Plan.ID, "activate": true})
	if !r.IsError {
		t.Fatal("missing save choice accepted")
	}
	r = call(t, s, "utm_changes_execute", map[string]any{"profile": "main", "plan_id": out.Plan.ID, "activate": true, "save": true})
	if r.IsError || !slices.Contains(f.calls, "system config save") {
		t.Fatalf("execute %v", r.Content)
	}
}

func TestSDKPartialExecutionSignalsError(t *testing.T) {
	s, f := session(t, true)
	r := call(t, s, "utm_node_new", map[string]any{"profile": "main", "parameters": map[string]any{"name": "web", "address": "192.0.2.9", "zone": "internal"}})
	b, _ := json.Marshal(r.StructuredContent)
	var result struct {
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
	}
	_ = json.Unmarshal(b, &result)
	f.fail = "system update rule"
	r = call(t, s, "utm_changes_execute", map[string]any{"profile": "main", "plan_id": result.Plan.ID, "activate": true, "save": true})
	if !r.IsError || r.StructuredContent == nil {
		t.Fatal("partial execution lost its MCP error signal or step evidence")
	}
}
