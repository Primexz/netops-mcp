package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func TestCatalogSchemasAndActivation(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Operations) < 400 {
		t.Fatalf("incomplete catalog: %d", len(c.Operations))
	}
	for _, o := range c.Operations {
		b, _ := json.Marshal(o.InputSchema())
		var s jsonschema.Schema
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s: %v", o.ID, err)
		}
		if _, err := s.Resolve(nil); err != nil {
			t.Fatalf("%s: %v", o.ID, err)
		}
		for _, cmd := range append(o.Activation, o.Snapshot...) {
			if _, ok := c.Command(cmd); !ok {
				t.Errorf("%s refers to missing command %q", o.ID, cmd)
			}
		}
	}
}

func TestInputSchemaValueContracts(t *testing.T) {
	o := Operation{Parameters: []Parameter{
		{Name: "scalar", Type: "scalar"},
		{Name: "list", Type: "array"},
		{Name: "value", Type: "value"},
		{Name: "entries", Type: "entries"},
	}}
	data, err := json.Marshal(o.InputSchema())
	if err != nil {
		t.Fatal(err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name       string
		parameters map[string]any
		valid      bool
	}{
		{"optional omitted", map[string]any{}, true},
		{"scalar string", map[string]any{"scalar": "12"}, true},
		{"scalar integer", map[string]any{"scalar": float64(12)}, true},
		{"scalar fraction", map[string]any{"scalar": 1.5}, true},
		{"scalar boolean", map[string]any{"scalar": false}, true},
		{"mixed scalar list", map[string]any{"list": []any{"value", 1.5, true}}, true},
		{"empty list", map[string]any{"list": []any{}}, true},
		{"value string", map[string]any{"value": "value"}, true},
		{"value number", map[string]any{"value": 1.5}, true},
		{"value boolean", map[string]any{"value": false}, true},
		{"recursive value", map[string]any{"value": map[string]any{"nested": []any{"value", 1.5, true, map[string]any{"enabled": false}}}}, true},
		{"entry recursive value", map[string]any{"entries": []any{map[string]any{"application": "app", "values": []any{map[string]any{"variable": "SETTING", "value": []any{"value", 1.5, true}}}}}}, true},
		{"null scalar", map[string]any{"scalar": nil}, false},
		{"array scalar", map[string]any{"scalar": []any{"value"}}, false},
		{"object scalar", map[string]any{"scalar": map[string]any{}}, false},
		{"null list item", map[string]any{"list": []any{nil}}, false},
		{"object list item", map[string]any{"list": []any{map[string]any{}}}, false},
		{"nested list item", map[string]any{"list": []any{[]any{"value"}}}, false},
		{"null value", map[string]any{"value": nil}, false},
		{"nested null value", map[string]any{"value": map[string]any{"nested": []any{nil}}}, false},
		{"invalid value key", map[string]any{"value": map[string]any{"invalid key": "value"}}, false},
		{"null entry value", map[string]any{"entries": []any{map[string]any{"values": []any{map[string]any{"variable": "SETTING", "value": nil}}}}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := resolved.Validate(map[string]any{"profile": "main", "parameters": tt.parameters})
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%t, want %t: %v", err == nil, tt.valid, err)
			}
		})
	}
}

func TestRealCommands(t *testing.T) {
	c, _ := Load()
	tests := []struct {
		id     string
		params map[string]any
		want   string
	}{
		{"utm_node_new", map[string]any{"name": "webserver", "address": "192.0.2.4/32", "zone": "internal"}, `node new name "webserver" address "192.0.2.4/32" zone "internal"`},
		{"utm_rule_new", map[string]any{"group": "default", "src": "internal-network", "dst": "internet", "service": "https", "flags": []any{"ACCEPT", "LOG"}}, `rule new group "default" src "internal-network" dst "internet" service "https" flags [ "ACCEPT" "LOG" ]`},
		{"utm_service_new", map[string]any{"name": "custom", "proto": "tcp", "dst-ports": "4443"}, `service new name "custom" proto "tcp" dst-ports "4443"`},
		{"utm_cert_delete_cert", map[string]any{"id": "207"}, `cert delete cert id "207"`},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			o, ok := c.Get(tt.id)
			if !ok {
				t.Fatal("missing operation")
			}
			r, err := o.Build(tt.params)
			if err != nil || r.Command != tt.want {
				t.Fatalf("got %q, %v; want %q", r.Command, err, tt.want)
			}
		})
	}
	o, _ := c.Get("utm_node_new")
	for _, args := range []map[string]any{{"name": "x"}, {"name": "x", "address": "x", "zone": "internal", "raw": "rule delete id 3"}, {"name": "x\nrule delete id 3", "address": "x", "zone": "internal"}} {
		if _, err := o.Build(args); err == nil {
			t.Fatal("accepted invalid arguments")
		}
	}
	o, _ = c.Get("utm_rule_new")
	if _, err := o.Build(map[string]any{"group": "default", "src": "a", "dst": "b", "service": "http", "flags": []any{"ACCEPT", "DROP"}}); err == nil {
		t.Fatal("accepted conflicting actions")
	}
}

func TestBulkExtcAndMultiline(t *testing.T) {
	c, _ := Load()
	o, _ := c.Get("utm_extc_valuelist_set")
	r, err := o.Build(map[string]any{"entries": []any{map[string]any{"application": "spupdater", "values": []any{map[string]any{"variable": "AUTO_UPDATE_ENABLE", "value": []any{"1"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Command, "extc valuelist set [ {") || strings.Contains(r.Command, " entries ") {
		t.Fatal(r.Command)
	}
	o, _ = c.Get("utm_system_register")
	r, err = o.Build(map[string]any{"input": "-----BEGIN LICENSE-----\nYWJj\n-----END LICENSE-----"})
	if err != nil || r.Command != "system register" || len(r.Input) == 0 {
		t.Fatalf("%#v %v", r, err)
	}
	if _, err := o.Build(map[string]any{"input": "-----BEGIN LICENSE-----\nYWJj\n-----END LICENSE-----\nsystem reboot"}); err == nil {
		t.Fatal("multiline trailing-command injection accepted")
	}
}

func TestDiagnosticInjectionIsQuoted(t *testing.T) {
	c, _ := Load()
	o, _ := c.Get("utm_diagnostics_tcpdump")
	if _, err := o.Build(map[string]any{"interface": "eth0; reboot", "count": 1}); err == nil {
		t.Fatal("accepted invalid interface")
	}
	r, err := o.Build(map[string]any{"interface": "eth0", "count": 5, "filter": "tcp port 443; $(reboot)"})
	if err != nil || !r.Shell || !strings.Contains(r.Command, `'tcp port 443; $(reboot)'`) {
		t.Fatalf("%s %v", r.Command, err)
	}
}
