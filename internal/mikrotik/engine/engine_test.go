package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

func fixture(t *testing.T, h http.HandlerFunc) *Engine {
	t.Helper()
	_, p := testutil.Router(t, h)
	c := &config.Config{Profiles: map[string]config.Profile{"main": p}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, cat, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	return e
}
func operation(t *testing.T, e *Engine, name string) catalog.Operation {
	t.Helper()
	o, ok := e.Catalog.Get(name)
	if !ok {
		t.Fatal(name)
	}
	return o
}

func TestPermissionsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	e := fixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = fmt.Fprint(w, `[]`) })
	p := e.Config.Profiles["main"]
	p.ReadOnly = new(true)
	e.Config.Profiles["main"] = p
	o := operation(t, e, "mikrotik_ip_address_create")
	if _, err := e.Call(t.Context(), o, map[string]any{"profile": "main", "parameters": map[string]any{"address": "192.0.2.1/24", "interface": "ether2"}}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatal(err)
	}
	p.ReadOnly = new(false)
	p.Groups = []string{"system"}
	e.Config.Profiles["main"] = p
	if _, err := e.Call(t.Context(), o, map[string]any{"profile": "main"}); err == nil {
		t.Fatal("group bypass")
	}
	if _, err := e.Call(t.Context(), o, map[string]any{"profile": "unknown"}); err == nil {
		t.Fatal("unknown profile accepted")
	}
	e.Config.Groups = []string{"address"}
	if _, err := e.Discover(t.Context(), "main"); err == nil {
		t.Fatal("discovery bypassed groups")
	}
	if calls.Load() != 0 {
		t.Fatal("permission failure contacted router")
	}
}

func TestListFilteringAndPagination(t *testing.T) {
	e := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/rest/interface" || r.URL.Query().Get("name") != "WAN & guests" || r.URL.Query().Get(".proplist") != ".id,name" {
			t.Errorf("bad query: %s", r.URL)
		}
		_, _ = fmt.Fprint(w, `[{".id":"*1","name":"a"},{".id":"*2","name":"b"},{".id":"*3","name":"c"}]`)
	})
	out, err := e.Call(t.Context(), operation(t, e, "mikrotik_interface_list"), map[string]any{"profile": "main", "filters": map[string]any{"name": "WAN & guests"}, "properties": []any{".id", "name"}, "offset": float64(1), "limit": float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["more"] != true || result["total"] != 3 || result["records"].([]any)[0].(map[string]any)[".id"] != "*2" {
		t.Fatal(result)
	}
}

func TestSingletonUpdateAndRuleMove(t *testing.T) {
	var seen atomic.Int32
	e := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		var params map[string]string
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			t.Error(err)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST: %s", r.Method)
		}
		switch r.URL.Path {
		case "/rest/ip/dns/set":
			if params["servers"] != "192.0.2.53" {
				t.Error(params)
			}
		case "/rest/ip/firewall/filter/move":
			if params[".id"] != "*A" || params["destination"] != "*B" || params["numbers"] != "" {
				t.Error(params)
			}
		default:
			t.Error(r.URL.Path)
		}
		_, _ = fmt.Fprint(w, `[]`)
	})
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"mikrotik_ip_dns_update", map[string]any{"profile": "main", "parameters": map[string]any{"servers": "192.0.2.53"}}},
		{"mikrotik_ip_firewall_filter_move", map[string]any{"profile": "main", "id": "*A", "destination": "*B"}},
	} {
		if _, err := e.Call(t.Context(), operation(t, e, tc.name), tc.args); err != nil {
			t.Fatal(err)
		}
	}
	if seen.Load() != 2 {
		t.Fatal(seen.Load())
	}
}

func TestStaticOnlyPrecondition(t *testing.T) {
	for _, dynamic := range []string{"true", "false", "missing"} {
		t.Run(dynamic, func(t *testing.T) {
			var writes atomic.Int32
			e := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					if dynamic == "missing" {
						_, _ = fmt.Fprint(w, `{".id":"*1"}`)
					} else {
						_, _ = fmt.Fprintf(w, `{".id":"*1","dynamic":%q}`, dynamic)
					}
					return
				}
				writes.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			_, err := e.Call(t.Context(), operation(t, e, "mikrotik_ip_dhcp_server_lease_delete"), map[string]any{"profile": "main", "id": "*1"})
			if dynamic == "false" {
				if err != nil || writes.Load() != 1 {
					t.Fatal(err, writes.Load())
				}
			} else if err == nil || writes.Load() != 0 {
				t.Fatal("dynamic mutation sent", err, writes.Load())
			}
		})
	}
}

func TestProfileIsolationAndDiscovery(t *testing.T) {
	var first, second atomic.Int32
	e := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		if r.URL.Path == "/rest/system/resource" {
			_, _ = fmt.Fprint(w, `{"version":"7.26"}`)
		} else {
			_, _ = fmt.Fprint(w, `[]`)
		}
	})
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) { second.Add(1); _, _ = fmt.Fprint(w, `{"name":"branch"}`) })
	e.Config.Profiles["branch"] = p
	if _, err := e.Call(t.Context(), operation(t, e, "mikrotik_system_identity_get"), map[string]any{"profile": "branch"}); err != nil {
		t.Fatal(err)
	}
	if first.Load() != 0 || second.Load() != 1 {
		t.Fatal("profile routed incorrectly")
	}
	out, err := e.Discover(t.Context(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["complete_capability_probe"] != false || first.Load() != 2 {
		t.Fatal(out)
	}
	b, _ := json.Marshal(e.Profiles())
	if strings.Contains(string(b), "PASSWORD") || strings.Contains(string(b), "fixture-password") {
		t.Fatal("profile listing contains credential information")
	}
}
