package catalog_test

import (
	"testing"

	"github.com/Primexz/netops-mcp/internal/mcpschema"
	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
)

func TestAllGeneratedSchemas(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range c.Operations {
		if _, err := mcpschema.Resolve(o.InputSchema()); err != nil {
			t.Errorf("%s: %v", o.Name, err)
		}
		if o.LiveVerified {
			t.Errorf("unsubstantiated live verification: %s", o.Name)
		}
		if o.ReadOnly() {
			continue
		}
		params := o.InputSchema()["properties"].(map[string]any)["parameters"]
		if params == nil {
			continue
		}
		fields := params.(map[string]any)["properties"].(map[string]any)
		for _, p := range o.Properties {
			if p.ReadOnly && fields[p.Name] != nil {
				t.Errorf("read-only property writable: %s %s", o.Name, p.Name)
			}
		}
		for _, field := range []string{"all", "static", "dynamic", "script"} {
			if fields[field] != nil {
				t.Errorf("selector/script writable: %s %s", o.Name, field)
			}
		}
	}
}

func TestArgumentContracts(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		args  map[string]any
		valid bool
	}{
		{"mikrotik_ip_address_create", map[string]any{"profile": "main", "parameters": map[string]any{"address": "192.0.2.1/24", "interface": "ether2"}}, true},
		{"mikrotik_ip_address_create", map[string]any{"profile": "main", "parameters": map[string]any{"address": "192.0.2.1/24"}}, false},
		{"mikrotik_ip_address_update", map[string]any{"profile": "main", "id": "*A", "parameters": map[string]any{"comment": "new"}}, true},
		{"mikrotik_ip_address_update", map[string]any{"profile": "main", "id": "*A", "parameters": map[string]any{}}, false},
		{"mikrotik_ip_address_update", map[string]any{"profile": "main", "id": "0", "parameters": map[string]any{"comment": "new"}}, false},
		{"mikrotik_ip_address_update", map[string]any{"profile": "main", "id": "*A", "parameters": map[string]any{"dynamic": false}}, false},
		{"mikrotik_interface_update", map[string]any{"profile": "main", "id": "*1", "parameters": map[string]any{"name": "renamed"}}, false},
		{"mikrotik_interface_update", map[string]any{"profile": "main", "id": "*1", "parameters": map[string]any{"disabled": true}}, true},
		{"mikrotik_ip_dns_update", map[string]any{"profile": "main", "parameters": map[string]any{"servers": "192.0.2.53"}}, true},
		{"mikrotik_ip_address_list", map[string]any{"profile": "main", "filters": map[string]any{".query": "evil"}}, false},
		{"mikrotik_log_list", map[string]any{"profile": "main", "filters": map[string]any{"topics": "info"}, "properties": []any{"message", "time"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, ok := c.Get(tc.name)
			if !ok {
				t.Fatal("missing tool")
			}
			schema, err := mcpschema.Resolve(o.InputSchema())
			if err != nil {
				t.Fatal(err)
			}
			if got := schema.Validate(tc.args) == nil; got != tc.valid {
				t.Fatalf("validation=%v, want %v", got, tc.valid)
			}
		})
	}
}
