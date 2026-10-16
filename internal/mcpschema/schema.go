// Package mcpschema builds and resolves the input schemas shared by the MCP servers.
package mcpschema

import (
	"encoding/json"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// Resolve compiles a tool schema once, before the tool is registered.
func Resolve(schema map[string]any) (*jsonschema.Resolved, error) {
	b, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return s.Resolve(nil)
}

// Object rejects fields that the operation has not explicitly declared.
func Object(properties map[string]any, required ...string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func Text(description string) map[string]any {
	return map[string]any{"type": "string", "maxLength": 4096, "description": strings.TrimSpace(description)}
}
