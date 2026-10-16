package mcpserver

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSDKToolSchemasUseSingleTypeBranches(t *testing.T) {
	client, runner := session(t, false)
	var check func(string, any)
	check = func(path string, value any) {
		t.Helper()
		switch value := value.(type) {
		case map[string]any:
			if types, ok := value["type"].([]any); ok {
				t.Fatalf("%s.type is an array %v; use anyOf branches with a single type", path, types)
			}
			for key, child := range value {
				check(path+"."+key, child)
			}
		case []any:
			for i, child := range value {
				check(fmt.Sprintf("%s[%d]", path, i), child)
			}
		}
	}
	count := 0
	for tool, err := range client.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		check(tool.Name+".inputSchema", schema)
		count++
	}
	if count < 480 {
		t.Fatalf("expected the complete tool catalog, got %d tools", count)
	}
	if len(runner.calls) != 0 {
		t.Fatal("schema discovery contacted an appliance")
	}
}
