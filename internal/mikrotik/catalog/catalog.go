// Package catalog embeds documentation-derived, explicitly approved RouterOS operations.
package catalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Primexz/netops-mcp/internal/mcpschema"
	"net/http"
	"regexp"
	"slices"
)

//go:embed operations.json
var Data []byte

type Catalog struct {
	Sources    []Source    `json:"sources"`
	Operations []Operation `json:"operations"`
}

type Source struct {
	URL         string `json:"url"`
	Version     string `json:"version"`
	RetrievedAt string `json:"retrieved_at"`
	SHA256      string `json:"sha256"`
}

type Property struct {
	Name        string         `json:"name"`
	CLIType     string         `json:"cli_type"`
	Description string         `json:"description"`
	Required    bool           `json:"required,omitzero"`
	ReadOnly    bool           `json:"read_only,omitzero"`
	Schema      map[string]any `json:"schema"`
}

type Operation struct {
	Name          string     `json:"name"`
	Group         string     `json:"group"`
	Path          string     `json:"path"`
	Action        string     `json:"action"`
	Method        string     `json:"method"`
	Singleton     bool       `json:"singleton,omitzero"`
	StaticOnly    bool       `json:"static_only,omitzero"`
	Description   string     `json:"description"`
	Properties    []Property `json:"properties"`
	SourceURL     string     `json:"source_url"`
	OverrideNotes []string   `json:"override_notes,omitempty"`
}

func Load() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(Data, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

var safePath = regexp.MustCompile(`^[a-z0-9-]+(/[a-z0-9-]+)*$`)
var safeTool = regexp.MustCompile(`^mikrotik_[a-z0-9_]{1,55}$`)

func (c *Catalog) Validate() error {
	if len(c.Operations) == 0 {
		return errors.New("empty operation catalog")
	}
	seen := map[string]bool{}
	for _, o := range c.Operations {
		if seen[o.Name] {
			return fmt.Errorf("tool name collision: %s", o.Name)
		}
		seen[o.Name] = true
		if !safeTool.MatchString(o.Name) || !safePath.MatchString(o.Path) {
			return fmt.Errorf("invalid tool name/path: %s", o.Name)
		}
		expected := map[string]string{"list": http.MethodGet, "get": http.MethodGet, "create": http.MethodPut, "update": http.MethodPatch, "delete": http.MethodDelete, "move": http.MethodPost}[o.Action]
		if expected == "" || o.Method != expected {
			if !o.Singleton || o.Action != "update" || o.Method != http.MethodPost {
				return fmt.Errorf("invalid method/action: %s", o.Name)
			}
		}
		if o.SourceURL == "" || o.Group == "" {
			return fmt.Errorf("missing provenance/group: %s", o.Name)
		}
		fields := map[string]bool{}
		for _, p := range o.Properties {
			if p.Name == "" || p.Schema == nil || fields[p.Name] {
				return fmt.Errorf("invalid property in %s", o.Name)
			}
			fields[p.Name] = true
		}
	}
	return nil
}

func (c *Catalog) Get(name string) (Operation, bool) {
	i := slices.IndexFunc(c.Operations, func(o Operation) bool { return o.Name == name })
	if i < 0 {
		return Operation{}, false
	}
	return c.Operations[i], true
}

func (o Operation) ReadOnly() bool { return o.Method == http.MethodGet }

// InputSchema separates MCP controls from RouterOS configuration properties.
func (o Operation) InputSchema() map[string]any {
	props := map[string]any{"profile": mcpschema.Text("Configured router profile name.")}
	required := []string{"profile"}
	if !o.ReadOnly() {
		props["safe_mode_id"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "Active safe-mode session ID; required when the profile requires safe mode. This control is never sent to RouterOS."}
	}
	if o.Action == "list" {
		// Property names are constrained to this menu; special API options are not filters.
		filters := map[string]any{}
		for _, p := range o.Properties {
			filters[p.Name] = mcpschema.Text(p.Description)
		}
		props["filters"] = mcpschema.Object(filters)
		props["properties"] = map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": o.PropertyNames()}, "maxItems": 128, "uniqueItems": true}
		props["offset"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 1000000}
		props["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
	}
	if (o.Action == "update" || o.Action == "delete") && !o.Singleton || o.Action == "move" {
		props["id"] = map[string]any{"type": "string", "pattern": `^\*[0-9A-Fa-f]+$`, "maxLength": 64, "description": "RouterOS .id from a fresh list result; row numbers and names are not accepted."}
		required = append(required, "id")
	}
	if o.Action == "move" {
		props["destination"] = map[string]any{"type": "string", "pattern": `^\*[0-9A-Fa-f]+$`, "maxLength": 64, "description": "Move this rule immediately before the rule with this .id."}
		required = append(required, "destination")
	}
	if o.Action == "create" || o.Action == "update" {
		parameters := map[string]any{}
		var mandatory []string
		for _, p := range o.Properties {
			if p.ReadOnly {
				continue
			}
			if p.Name == "place-before" && o.Action != "create" {
				continue
			}
			parameters[p.Name] = p.Schema
			if p.Required && o.Action == "create" {
				mandatory = append(mandatory, p.Name)
			}
		}
		params := mcpschema.Object(parameters, mandatory...)
		params["minProperties"] = 1
		props["parameters"] = params
		required = append(required, "parameters")
	}
	return mcpschema.Object(props, required...)
}

func (o Operation) PropertyNames() []string {
	names := make([]string, 0, len(o.Properties))
	for _, p := range o.Properties {
		names = append(names, p.Name)
	}
	slices.Sort(names)
	return names
}
