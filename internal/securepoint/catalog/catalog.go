// Package catalog defines the finite, versioned appliance management surface.
package catalog

import (
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Primexz/netops-mcp/internal/securepoint/cli"
	"github.com/Primexz/netops-mcp/internal/securepoint/transport"
)

//go:embed operations.json
var Data []byte

type Parameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Positional  bool   `json:"positional,omitzero"`
}

type Operation struct {
	ID                string      `json:"id"`
	Command           string      `json:"command"`
	Group             string      `json:"group"`
	Kind              string      `json:"kind"`
	Description       string      `json:"description"`
	Parameters        []Parameter `json:"parameters"`
	Source            string      `json:"source"`
	Revision          int         `json:"revision"`
	MinimumFirmware   string      `json:"minimum_firmware"`
	SensitiveOutput   bool        `json:"sensitive_output,omitzero"`
	Diagnostic        bool        `json:"diagnostic,omitzero"`
	Lifecycle         bool        `json:"lifecycle,omitzero"`
	Shell             bool        `json:"shell,omitzero"`
	Activation        []string    `json:"activation,omitempty"`
	Snapshot          []string    `json:"snapshot,omitempty"`
	Persistable       bool        `json:"persistable"`
	UnavailableReason string      `json:"unavailable_reason,omitempty"`
}

type Catalog struct {
	Operations []Operation
	byID       map[string]Operation
	byCommand  map[string]Operation
}

func Load() (*Catalog, error) {
	var operations []Operation
	if err := json.Unmarshal(Data, &operations); err != nil {
		return nil, err
	}
	c := &Catalog{Operations: operations, byID: map[string]Operation{}, byCommand: map[string]Operation{}}
	for _, o := range operations {
		if _, exists := c.byID[o.ID]; exists {
			return nil, fmt.Errorf("duplicate operation %s", o.ID)
		}
		if o.ID == "" || o.Source == "" || o.Revision == 0 {
			return nil, errors.New("catalog entry lacks identity or provenance")
		}
		c.byID[o.ID], c.byCommand[o.Command] = o, o
	}
	return c, nil
}

func (c *Catalog) Get(id string) (Operation, bool) { o, ok := c.byID[id]; return o, ok }
func (c *Catalog) Command(command string) (Operation, bool) {
	o, ok := c.byCommand[command]
	return o, ok
}

func (c *Catalog) Groups() []string {
	var groups []string
	for _, o := range c.Operations {
		if !slices.Contains(groups, o.Group) {
			groups = append(groups, o.Group)
		}
	}
	slices.Sort(groups)
	return groups
}

func (o Operation) InputSchema() map[string]any {
	props := map[string]any{}
	var required []string
	for _, p := range o.Parameters {
		s := map[string]any{"description": p.Description}
		switch p.Type {
		case "array":
			s["type"] = "array"
			s["items"] = map[string]any{"anyOf": scalarTypeBranches()}
		case "entries":
			s["type"] = "array"
			s["minItems"] = 1
			s["items"] = map[string]any{"type": "object", "properties": map[string]any{
				"application": map[string]any{"type": "string"}, "variables": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"values": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{"variable": map[string]any{"type": "string"}, "value": map[string]any{"$ref": "#/$defs/cliValue"}}, "required": []string{"variable", "value"}, "additionalProperties": false}},
			}, "additionalProperties": false}
		case "value":
			s["$ref"] = "#/$defs/cliValue"
		case "multiline":
			s["type"] = "string"
			s["minLength"] = 1
			s["maxLength"] = 1 << 20
		case "integer":
			s["type"] = "integer"
			s["minimum"] = 1
			s["maximum"] = 1000
		default:
			s["anyOf"] = scalarTypeBranches()
		}
		props[p.Name] = s
		if p.Required {
			required = append(required, p.Name)
		}
	}
	parameters := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		parameters["required"] = required
	}
	return map[string]any{"type": "object", "properties": map[string]any{
		"profile":    map[string]any{"type": "string", "minLength": 1},
		"parameters": parameters,
		"offset":     map[string]any{"type": "integer", "minimum": 0},
		"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 1000},
	}, "required": []string{"profile"}, "additionalProperties": false,
		"$defs": map[string]any{"cliValue": map[string]any{"anyOf": append(scalarTypeBranches(),
			map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/cliValue"}},
			map[string]any{"type": "object", "propertyNames": map[string]any{"pattern": "^[a-zA-Z_][a-zA-Z0-9_-]*$"}, "additionalProperties": map[string]any{"$ref": "#/$defs/cliValue"}},
		)}},
	}
}

// Single-type branches preserve scalar unions for clients that reject type arrays.
func scalarTypeBranches() []any {
	return []any{
		map[string]any{"type": "string"},
		map[string]any{"type": "number"},
		map[string]any{"type": "boolean"},
	}
}

func (o Operation) Build(args map[string]any) (transport.Request, error) {
	if o.UnavailableReason != "" {
		return transport.Request{}, fmt.Errorf("operation unavailable: %s", o.UnavailableReason)
	}
	known := map[string]Parameter{}
	for _, p := range o.Parameters {
		known[p.Name] = p
		if p.Required {
			if v, ok := args[p.Name]; !ok || v == "" {
				return transport.Request{}, fmt.Errorf("parameter %s is required", p.Name)
			}
		}
	}
	for k := range args {
		if _, ok := known[k]; !ok {
			return transport.Request{}, fmt.Errorf("unknown parameter %s for %s", k, o.ID)
		}
	}
	if o.Shell {
		return o.buildDiagnostic(args)
	}
	var command strings.Builder
	command.WriteString(o.Command)
	var input []byte
	for _, p := range o.Parameters {
		v, ok := args[p.Name]
		if !ok {
			continue
		}
		if p.Type == "multiline" {
			s, ok := v.(string)
			if !ok || len(s) == 0 || len(s) > 1<<20 {
				return transport.Request{}, errors.New("multiline input must be a nonempty string of at most 1 MiB")
			}
			if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) {
				return transport.Request{}, errors.New("unsupported control character in multiline input")
			}
			block, rest := pem.Decode([]byte(s))
			if block == nil || len(strings.TrimSpace(string(rest))) != 0 || len(block.Headers) != 0 {
				return transport.Request{}, errors.New("multiline input must be a single PEM block without headers or trailing commands")
			}
			input = pem.EncodeToMemory(block)
			continue
		}
		if p.Type == "array" {
			switch v.(type) {
			case []any, []string:
			default:
				return transport.Request{}, fmt.Errorf("parameter %s must be an array", p.Name)
			}
		} else if p.Type == "entries" {
			if err := validateEntries(v); err != nil {
				return transport.Request{}, err
			}
		} else if p.Type != "value" {
			switch v.(type) {
			case string, bool, json.Number, float64, int:
			default:
				return transport.Request{}, fmt.Errorf("parameter %s must be a scalar", p.Name)
			}
		}
		encoded, err := cli.Value(v)
		if err != nil {
			return transport.Request{}, fmt.Errorf("parameter %s: %w", p.Name, err)
		}
		if !p.Positional {
			command.WriteString(" " + p.Name)
		}
		command.WriteString(" " + encoded)
	}
	if command.Len() > 2<<20 {
		return transport.Request{}, errors.New("encoded command exceeds 2 MiB")
	}
	if err := o.validateSemantics(args); err != nil {
		return transport.Request{}, err
	}
	return transport.Request{Command: command.String(), Input: input}, nil
}

func validateEntries(v any) error {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return errors.New("entries must be a nonempty array of objects")
	}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return errors.New("each EXTC entry must be an object")
		}
		for key := range m {
			if !slices.Contains([]string{"application", "variables", "values"}, key) {
				return fmt.Errorf("unknown EXTC entry field %s", key)
			}
		}
		if app, ok := m["application"]; ok {
			if s, ok := app.(string); !ok || s == "" {
				return errors.New("application must be a nonempty string")
			}
		}
		if values, ok := m["values"]; ok {
			list, ok := values.([]any)
			if !ok {
				return errors.New("values must be an array")
			}
			for _, item := range list {
				value, ok := item.(map[string]any)
				if !ok {
					return errors.New("each value must be an object")
				}
				if _, ok := value["variable"].(string); !ok {
					return errors.New("each value requires a variable name")
				}
				if _, ok := value["value"]; !ok {
					return errors.New("each value requires value")
				}
				for k := range value {
					if k != "variable" && k != "value" {
						return fmt.Errorf("unknown EXTC value field %s", k)
					}
				}
			}
		}
	}
	return nil
}

func (o Operation) validateSemantics(args map[string]any) error {
	// Destructive commands with alternative identifiers must never become
	// accidentally unqualified deletes when neither identifier was provided.
	if len(o.Parameters) > 0 && (strings.HasSuffix(o.Command, " delete") || strings.HasSuffix(o.Command, " set") || strings.HasSuffix(o.Command, " rem")) {
		var identifiers []string
		for _, p := range o.Parameters {
			if slices.Contains([]string{"id", "name", "pool", "host", "service", "peer_id", "interface_id", "zone_id", "record_id", "variable"}, p.Name) {
				identifiers = append(identifiers, p.Name)
			}
		}
		if len(identifiers) > 0 {
			found := false
			for _, key := range identifiers {
				if v, ok := args[key]; ok && v != "" {
					found = true
				}
			}
			if !found {
				return errors.New("an object identifier is required")
			}
		}
	}
	if o.Command == "rule new" || o.Command == "rule set" {
		if f, ok := args["flags"].([]any); ok {
			allowed := []string{"ACCEPT", "REJECT", "DROP", "LOG", "LOG_ALL", "STATELESS", "RELATED", "DISABLED", "QOS", "HIDENAT", "HIDENAT_EXCLUDE", "DESTNAT", "NETMAP", "FULLCONENAT", "TRACE"}
			actions := 0
			for _, v := range f {
				s, ok := v.(string)
				if !ok || !slices.Contains(allowed, s) {
					return errors.New("unknown firewall rule flag")
				}
				if slices.Contains([]string{"ACCEPT", "REJECT", "DROP"}, s) {
					actions++
				}
			}
			if actions > 1 {
				return errors.New("firewall rule cannot combine ACCEPT, REJECT and DROP")
			}
		}
	}
	return nil
}

func (o Operation) buildDiagnostic(args map[string]any) (transport.Request, error) {
	iface, ok := args["interface"].(string)
	if !ok || !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,64}$`).MatchString(iface) {
		return transport.Request{}, errors.New("invalid capture interface")
	}
	n, err := strconv.Atoi(fmt.Sprint(args["count"]))
	if err != nil || n < 1 || n > 1000 {
		return transport.Request{}, errors.New("capture count must be 1..1000")
	}
	cmd := "tcpdump -nn -c " + strconv.Itoa(n) + " -i " + cli.ShellQuote(iface)
	if filter, ok := args["filter"]; ok {
		s, ok := filter.(string)
		if !ok || len(s) > 4096 || strings.ContainsFunc(s, unicode.IsControl) {
			return transport.Request{}, errors.New("invalid capture filter")
		}
		cmd += " -- " + cli.ShellQuote(s)
	}
	return transport.Request{Command: cmd, Shell: true}, nil
}

func VersionAtLeast(version, minimum string) bool {
	a, b := strings.Split(version, "."), strings.Split(minimum, ".")
	for i := range max(len(a), len(b)) {
		av, bv := 0, 0
		if i < len(a) {
			av, _ = strconv.Atoi(a[i])
		}
		if i < len(b) {
			bv, _ = strconv.Atoi(b[i])
		}
		if av != bv {
			return av > bv
		}
	}
	return true
}
