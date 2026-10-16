package engine

import (
	"testing"

	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/safemode"
	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

func TestAllProtectedMutationPathsRequireWindow(t *testing.T) {
	f := testutil.NewSafeRouter(t)
	c := &config.Config{Profiles: map[string]config.Profile{"main": f.Profile}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, cat, nil)
	defer e.Close()
	cases := []struct {
		name string
		args map[string]any
	}{
		{"mikrotik_ip_address_create", map[string]any{"parameters": map[string]any{"address": "192.0.2.1/24", "interface": "ether2"}}},
		{"mikrotik_ip_address_update", map[string]any{"id": "*A", "parameters": map[string]any{"comment": "changed"}}},
		{"mikrotik_ip_dhcp_server_lease_delete", map[string]any{"id": "*A"}},
		{"mikrotik_ip_dns_update", map[string]any{"parameters": map[string]any{"servers": "192.0.2.53"}}},
		{"mikrotik_ip_firewall_filter_move", map[string]any{"id": "*A", "destination": "*B"}},
	}
	for _, tc := range cases {
		tc.args["profile"] = "main"
		if _, err := e.Call(t.Context(), operation(t, e, tc.name), tc.args); err == nil {
			t.Fatal("unprotected write accepted", tc.name)
		}
	}
	if f.Writes.Load() != 0 {
		t.Fatal("missing ID reached REST writes")
	}
	v, err := e.SafeMode.Begin(t.Context(), "main")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		tc.args["safe_mode_id"] = v.ID
		out, err := e.Call(t.Context(), operation(t, e, tc.name), tc.args)
		if err != nil {
			t.Fatal(tc.name, err)
		}
		view := out.(map[string]any)["safe_mode"].(safemode.View)
		if view.ID != v.ID || view.State != "active" || f.Commits.Load() != 0 {
			t.Fatal("write implicitly committed", view)
		}
	}
	if f.Writes.Load() != int32(len(cases)) {
		t.Fatal("wrong mutation count")
	}
	state, err := e.ConfirmSafeMode(t.Context(), "main", v.ID)
	if err != nil || state.State != "committed" {
		t.Fatal(state, err)
	}
}
