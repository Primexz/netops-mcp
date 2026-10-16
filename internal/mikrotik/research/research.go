// Package research translates the current RouterOS manual into a reviewed catalog.
// It is used only by the maintenance command, never while serving MCP requests.
package research

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/Primexz/netops-mcp/internal/mcpschema"
	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
)

const Manual = "https://manual.mikrotik.com/docs/cli-reference/"
const REST = "https://manual.mikrotik.com/docs/developer-guides/rest-api/"

type Spec struct {
	Resources []Resource `json:"resources"`
}
type Resource struct {
	Path          string            `json:"path"`
	Group         string            `json:"group"`
	Actions       []string          `json:"actions"`
	Singleton     bool              `json:"singleton"`
	StaticOnly    bool              `json:"static_only"`
	Ordered       bool              `json:"ordered"`
	Required      []string          `json:"required"`
	WriteFields   []string          `json:"write_fields"`
	ExcludeFields []string          `json:"exclude_fields"`
	TypeOverrides map[string]string `json:"type_overrides"`
}

func LoadSpec(path string) (Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&spec); err != nil {
		return spec, err
	}
	if len(spec.Resources) == 0 {
		return spec, errors.New("empty resource specification")
	}
	return spec, nil
}

func CacheName(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:]) + ".html"
}

// Fetch writes only the ignored cache. A failed refresh leaves the old manifest
// intact; Build checks every hash before consuming a page.
func Fetch(ctx context.Context, spec Spec, cacheDir string) error {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}
	urls := []string{REST}
	for _, r := range spec.Resources {
		urls = append(urls, Manual+r.Path+"/")
	}
	urls = slices.Compact(slices.Sorted(slices.Values(urls)))
	sources := make([]catalog.Source, len(urls))
	errs := make([]error, len(urls))
	client := &http.Client{Timeout: 30 * time.Second}
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for i, url := range urls {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				errs[i] = err
				return
			}
			req.Header.Set("User-Agent", "mikrotik-mcp-catalog/0.1 (+documentation refresh)")
			resp, err := client.Do(req)
			if err != nil {
				errs[i] = fmt.Errorf("fetch %s: %w", url, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				errs[i] = fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
				return
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, 12<<20+1))
			if err != nil {
				errs[i] = err
				return
			}
			if len(b) > 12<<20 {
				errs[i] = fmt.Errorf("page too large: %s", url)
				return
			}
			version := Version(b)
			if version == "" {
				errs[i] = fmt.Errorf("missing manual version: %s", url)
				return
			}
			sum := sha256.Sum256(b)
			sources[i] = catalog.Source{URL: url, Version: version, RetrievedAt: time.Now().UTC().Format(time.RFC3339), SHA256: hex.EncodeToString(sum[:])}
			errs[i] = WriteFile(filepath.Join(cacheDir, CacheName(url)), b)
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	b, err := json.MarshalIndent(sources, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(filepath.Join(cacheDir, "manifest.json"), append(b, '\n'))
}

func WriteFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".catalog-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), 0644); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

var versionPattern = regexp.MustCompile(`Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

func Version(b []byte) string {
	m := versionPattern.FindSubmatch(b)
	if len(m) != 2 {
		return ""
	}
	return string(m[1])
}

func Build(spec Spec, cacheDir string) (*catalog.Catalog, error) {
	b, err := os.ReadFile(filepath.Join(cacheDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var sources []catalog.Source
	if err := json.Unmarshal(b, &sources); err != nil {
		return nil, err
	}
	pages := map[string][]byte{}
	for _, s := range sources {
		b, err := os.ReadFile(filepath.Join(cacheDir, CacheName(s.URL)))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != s.SHA256 {
			return nil, fmt.Errorf("cached source hash mismatch: %s", s.URL)
		}
		pages[s.URL] = b
	}
	if len(pages[REST]) == 0 {
		return nil, errors.New("REST documentation missing from manifest")
	}
	c := &catalog.Catalog{Sources: sources}
	for _, r := range spec.Resources {
		url := Manual + r.Path + "/"
		b, ok := pages[url]
		if !ok {
			return nil, fmt.Errorf("missing cached page: %s", url)
		}
		properties, err := ParseProperties(b, r.TypeOverrides)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Path, err)
		}
		properties, notes, err := applyOverrides(r, properties)
		if err != nil {
			return nil, err
		}
		for _, action := range r.Actions {
			method := map[string]string{"get": "GET", "list": "GET", "create": "PUT", "update": "PATCH", "delete": "DELETE", "move": "POST"}[action]
			if r.Singleton && action == "update" {
				method = "POST"
			}
			fields := slices.Clone(properties)
			if len(r.WriteFields) > 0 && (action == "update" || action == "create") {
				fields = slices.DeleteFunc(fields, func(p catalog.Property) bool { return !p.ReadOnly && !slices.Contains(r.WriteFields, p.Name) })
			}
			name := "mikrotik_" + strings.NewReplacer("/", "_", "-", "_").Replace(r.Path) + "_" + action
			desc := fmt.Sprintf("%s /%s on the named RouterOS profile. Documentation-derived; live compatibility unverified.", strings.ToUpper(action[:1])+action[1:], r.Path)
			if method != "GET" {
				desc += " Applies immediately; requires read_only=false."
			}
			c.Operations = append(c.Operations, catalog.Operation{Name: name, Group: r.Group, Path: r.Path, Action: action, Method: method, Singleton: r.Singleton, StaticOnly: r.StaticOnly, Description: desc, Properties: fields, SourceURL: url, OverrideNotes: notes})
		}
	}
	slices.SortFunc(c.Operations, func(a, b catalog.Operation) int { return strings.Compare(a.Name, b.Name) })
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func applyOverrides(r Resource, properties []catalog.Property) ([]catalog.Property, []string, error) {
	byName := map[string]catalog.Property{}
	for _, p := range properties {
		byName[p.Name] = p
	}
	var notes []string
	add := func(name, typ, desc string, read bool) {
		if _, ok := byName[name]; ok {
			return
		}
		schema, _ := TypeSchema(typ, desc)
		byName[name] = catalog.Property{Name: name, CLIType: typ, Description: desc, ReadOnly: read, Schema: schema}
		notes = append(notes, "Added standard property omitted by this page: "+name)
	}
	if !r.Singleton {
		add(".id", "string", "RouterOS internal record identifier.", true)
		if slices.Contains(r.Actions, "create") || r.Path == "interface" {
			add("dynamic", "bool", "Whether this record was created dynamically.", true)
			p := byName["dynamic"]
			p.ReadOnly = true
			p.CLIType = "bool"
			p.Schema, _ = TypeSchema("bool", "Whether this record was created dynamically.")
			byName["dynamic"] = p
			notes = append(notes, "dynamic is a read-only record flag, not a writable configuration property.")
		}
	}
	for _, name := range []string{"all", "static"} {
		if _, ok := byName[name]; ok {
			delete(byName, name)
			notes = append(notes, "Removed console print selector from property schema: "+name)
		}
	}
	if slices.Contains(r.Actions, "create") || slices.Contains(r.Actions, "update") {
		if !r.Singleton {
			add("comment", "string", "Administrative comment.", false)
			add("disabled", "bool", "Disable this configuration record.", false)
			p := byName["disabled"]
			p.ReadOnly = false
			byName["disabled"] = p
		}
	}
	if r.Ordered {
		add("place-before", "string", "On creation, insert before this RouterOS .id; omitted means append.", false)
	}
	for _, name := range r.ExcludeFields {
		delete(byName, name)
		notes = append(notes, "Excluded property by reviewed scope override: "+name)
	}
	for _, name := range r.Required {
		p, ok := byName[name]
		if !ok || p.ReadOnly {
			return nil, nil, fmt.Errorf("%s: required creation property missing or read-only: %s", r.Path, name)
		}
		p.Required = true
		byName[name] = p
	}
	if len(r.Required) > 0 {
		notes = append(notes, "Reviewed creation requirements: "+strings.Join(r.Required, ", "))
	}
	if len(r.WriteFields) > 0 {
		notes = append(notes, "Writable fields restricted to: "+strings.Join(r.WriteFields, ", "))
	}
	if len(r.TypeOverrides) > 0 {
		notes = append(notes, "Explicit argument type mappings applied; see tools/mikrotik/catalog-spec.json.")
	}
	notes = append(notes, "Operations explicitly selected in tools/mikrotik/catalog-spec.json; generic REST method mapping comes from the REST guide.")
	properties = nil
	for _, p := range byName {
		properties = append(properties, p)
	}
	slices.SortFunc(properties, func(a, b catalog.Property) int { return strings.Compare(a.Name, b.Name) })
	return properties, notes, nil
}

// ParseProperties reads only argument tables within the documentation article.
// Navigation links and command examples are never treated as schema definitions.
func ParseProperties(b []byte, overrides map[string]string) ([]catalog.Property, error) {
	root, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	article := find(root, func(n *html.Node) bool { return n.Type == html.ElementNode && n.Data == "article" })
	if article == nil {
		return nil, errors.New("documentation article missing")
	}
	fields := map[string]catalog.Property{}
	flagOnly := map[string]bool{}
	var parseErr error
	walk(article, func(n *html.Node) {
		if parseErr != nil || n.Type != html.ElementNode || n.Data != "table" {
			return
		}
		var rows []*html.Node
		walk(n, func(x *html.Node) {
			if x.Type == html.ElementNode && x.Data == "tr" {
				rows = append(rows, x)
			}
		})
		if len(rows) < 2 {
			return
		}
		header := cells(rows[0])
		if len(header) < 3 {
			return
		}
		kind := nodeText(header[0])
		if kind == "Flag" && nodeText(header[1]) == "Name" {
			for _, row := range rows[1:] {
				cols := cells(row)
				if len(cols) < 3 {
					continue
				}
				name := nodeText(cols[1])
				if name == "" {
					continue
				}
				if _, ok := fields[name]; ok {
					continue
				}
				desc := nodeText(cols[2])
				schema, _ := TypeSchema("bool", desc)
				fields[name] = catalog.Property{Name: name, CLIType: "bool", Description: desc, ReadOnly: true, Schema: schema}
				flagOnly[name] = true
			}
			return
		}
		if kind != "Argument" && kind != "Read-only Argument" {
			return
		}
		for _, row := range rows[1:] {
			cols := cells(row)
			if len(cols) < 3 {
				continue
			}
			first := nodeText(cols[0])
			name, _, _ := strings.Cut(first, " ")
			if name == "" {
				continue
			}
			typ := nodeText(cols[1])
			if t, ok := overrides[name]; ok {
				typ = t
			}
			desc := nodeText(cols[2])
			if desc == "" {
				desc = "RouterOS " + name + " property."
			}
			schema, err := TypeSchema(typ, desc)
			if err != nil {
				parseErr = fmt.Errorf("property %s: %w", name, err)
				return
			}
			p := catalog.Property{Name: name, CLIType: typ, Description: desc, Required: strings.Contains(first, "mandatory"), ReadOnly: kind == "Read-only Argument", Schema: schema}
			if old, ok := fields[name]; ok {
				// A flag table alone must not turn a documented configuration
				// argument such as disabled into a read-only field.
				if !flagOnly[name] {
					p.ReadOnly = p.ReadOnly || old.ReadOnly
				}
				p.Required = p.Required || old.Required
			}
			fields[name] = p
			delete(flagOnly, name)
		}
	})
	if parseErr != nil {
		return nil, parseErr
	}
	if len(fields) == 0 {
		return nil, errors.New("no documented properties found; review changed page structure")
	}
	var properties []catalog.Property
	for _, p := range fields {
		properties = append(properties, p)
	}
	slices.SortFunc(properties, func(a, b catalog.Property) int { return strings.Compare(a.Name, b.Name) })
	return properties, nil
}

var typeWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*`)
var knownTypes = []string{"address", "alt", "as", "bool", "cfg", "composite", "date", "enum", "expr", "file", "iface_enum", "ipAddr", "ip6Addr", "ipPrefix", "ip6Prefix", "ipRange", "macAddr", "meter", "multi", "num", "numericon", "object", "pic", "range", "remote", "string", "super", "switch", "time", "timezone", "ubit", "value", "varName"}

// Complex CLI values stay strings: translating RouterOS composite expressions to
// JSON objects would invent a REST wire format. Simple booleans/numbers also
// accept their native JSON types, which the transport encodes as decimal strings.
func TypeSchema(typ, description string) (map[string]any, error) {
	root := typeWord.FindString(strings.TrimLeft(typ, "[ "))
	if !slices.Contains(knownTypes, root) {
		return nil, fmt.Errorf("unmapped CLI type %q; add a reviewed override", typ)
	}
	s := mcpschema.Text(description + " CLI type: " + typ)
	switch root {
	case "bool":
		s = map[string]any{"description": description, "anyOf": []any{map[string]any{"type": "boolean"}, map[string]any{"type": "string", "enum": []string{"true", "false", "yes", "no"}}}}
	case "num", "as":
		s = map[string]any{"description": description + " CLI type: " + typ, "anyOf": []any{map[string]any{"type": "integer", "minimum": 0, "maximum": 9007199254740991}, mcpschema.Text("RouterOS numeric syntax.")}}
	case "switch":
		s = map[string]any{"description": description, "type": "string", "enum": []string{""}}
	case "enum":
		// Only closed bare lists are safe to enforce; annotated enum grammars
		// retain their documented RouterOS syntax in the description.
		if start := strings.Index(typ, "("); start >= 0 && strings.HasSuffix(typ, ")") && !strings.Contains(typ, "{") {
			items := strings.FieldsFunc(typ[start+1:len(typ)-1], func(r rune) bool { return r == ',' || r == '|' })
			var values []string
			for _, v := range items {
				v = strings.TrimSpace(v)
				if v != "" {
					values = append(values, v)
				}
			}
			if len(values) > 1 {
				s["enum"] = values
			}
		}
	}
	return s, nil
}

func cells(row *html.Node) []*html.Node {
	var out []*html.Node
	for n := row.FirstChild; n != nil; n = n.NextSibling {
		if n.Type == html.ElementNode && (n.Data == "th" || n.Data == "td") {
			out = append(out, n)
		}
	}
	return out
}
func walk(n *html.Node, f func(*html.Node)) {
	f(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, f)
	}
}
func find(n *html.Node, f func(*html.Node) bool) *html.Node {
	if f(n) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := find(c, f); found != nil {
			return found
		}
	}
	return nil
}
func nodeText(n *html.Node) string {
	var b strings.Builder
	walk(n, func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
			b.WriteByte(' ')
		}
	})
	return strings.Join(strings.Fields(b.String()), " ")
}
