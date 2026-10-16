package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
)

// Synthetic HTML keeps tests independent of live documentation and its copyright.
const page = `<html><body><nav><table><tr><th>Argument<th>Type<th>Description<tr><td>ignored<td>futureType<td>navigation</table></nav><article>Version: 7.26<h1>Example</h1><table><tr><th>Argument<th>Type<th>Description<tr><td>address ( mandatory )<td>composite { address: ipAddr, netmask: [ num [ .. 32]] }<td><tr><td>interface ( mandatory )<td>iface_enum<td>Choose interface<tr><td>dynamic<td>switch<td>Print selector</table><table><tr><th>Read-only Argument<th>Type<th>Description<tr><td>actual-interface<td>iface_enum<td>Actual interface</table></article></body></html>`

func TestParsePropertiesAndTypes(t *testing.T) {
	props, err := ParseProperties([]byte(page), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(props) != 4 {
		t.Fatalf("wrong fields: %+v", props)
	}
	if !props[0].ReadOnly || props[1].Name != "address" || !props[1].Required || props[1].Description == "" {
		t.Fatal(props)
	}
	for _, typ := range []string{"super { value: num, [to] -num }", "enum (none | arp | ping | bfd)", "bool", "multi { iface_enum }", "[ num [ .. 32]]"} {
		if _, err := TypeSchema(typ, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := TypeSchema("futureType", ""); err == nil {
		t.Fatal("unknown type accepted")
	}
	if _, err := ParseProperties([]byte(`<article><p>changed layout</p></article>`), nil); err == nil {
		t.Fatal("missing argument tables accepted")
	}
	_, err = ParseProperties([]byte(`<article><table><tr><th>Argument<th>Type<th>Description<tr><td>foo<td>futureType<td>unknown</table></article>`), nil)
	if err == nil {
		t.Fatal("unknown table type accepted")
	}
	props, err = ParseProperties([]byte(`<article><table><tr><th>Argument<th>Type<th>Description<tr><td>foo<td>futureType<td>unknown</table></article>`), map[string]string{"foo": "string"})
	if err != nil || len(props) != 1 {
		t.Fatal(props, err)
	}
}

func TestBuildDeterministicAndHashChecked(t *testing.T) {
	dir := t.TempDir()
	var sources []catalog.Source
	for _, url := range []string{Manual + "ip/address/", REST} {
		b := []byte(page)
		hash := sha256.Sum256(b)
		sources = append(sources, catalog.Source{URL: url, Version: "7.26", RetrievedAt: "2026-10-16T00:00:00Z", SHA256: hex.EncodeToString(hash[:])})
		if err := WriteFile(filepath.Join(dir, CacheName(url)), b); err != nil {
			t.Fatal(err)
		}
	}
	manifest, _ := json.Marshal(sources)
	if err := WriteFile(filepath.Join(dir, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	spec := Spec{Resources: []Resource{{Path: "ip/address", Group: "address", Actions: []string{"list", "create", "update", "delete"}, Required: []string{"address", "interface"}}}}
	a, err := Build(spec, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(spec, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("catalog generation is not deterministic")
	}
	if len(a.Operations) != 4 {
		t.Fatal(len(a.Operations))
	}
	for _, o := range a.Operations {
		for _, p := range o.Properties {
			if p.Name == "dynamic" && !p.ReadOnly {
				t.Fatal("dynamic selector became writable")
			}
		}
	}
	if err := WriteFile(filepath.Join(dir, CacheName(REST)), []byte("changed")); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(spec, dir); err == nil {
		t.Fatal("cache hash mismatch accepted")
	}
}
