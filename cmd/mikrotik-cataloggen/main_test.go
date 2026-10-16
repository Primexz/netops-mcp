package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/research"
)

func TestIdenticalRefreshKeepsPublishedFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	originalFlags, originalArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = originalFlags, originalArgs })
	generate := func() {
		t.Helper()
		flag.CommandLine = flag.NewFlagSet("cataloggen-test", flag.ContinueOnError)
		os.Args = []string{"cataloggen-test", "--cache", "cache"}
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := research.WriteFile(path, data); err != nil {
			t.Fatal(err)
		}
	}
	writeCache := func(page, timestamp string) {
		t.Helper()
		sum := sha256.Sum256([]byte(page))
		var sources []catalog.Source
		for _, url := range []string{research.Manual + "ip/address/", research.REST} {
			write(filepath.Join("cache", research.CacheName(url)), []byte(page))
			sources = append(sources, catalog.Source{URL: url, Version: "7.26", RetrievedAt: timestamp, SHA256: hex.EncodeToString(sum[:])})
		}
		data, err := json.Marshal(sources)
		if err != nil {
			t.Fatal(err)
		}
		write("cache/manifest.json", data)
	}
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write("tools/mikrotik/catalog-spec.json", []byte(`{"resources":[{"path":"ip/address","group":"address","actions":["list"]}]}`))
	const page = `<article>Version: 7.26<table><tr><th>Argument<th>Type<th>Description<tr><td>name<td>string<td>Example field</table></article>`
	writeCache(page, "2026-01-01T00:00:00Z")
	generate()
	paths := []string{"internal/mikrotik/catalog/operations.json", "docs/mikrotik/sources.json", "docs/mikrotik/coverage.md"}
	before := make(map[string]string)
	for _, path := range paths {
		before[path] = string(read(path))
	}
	writeCache(page, "2026-01-02T00:00:00Z")
	generate()
	for _, path := range paths {
		if string(read(path)) != before[path] {
			t.Errorf("unchanged research changed %s and would open a timestamp-only PR", path)
		}
	}
	// A changed source must retain the new timestamp and generated schema.
	writeCache(strings.ReplaceAll(page, "Example field", "Updated field"), "2026-01-03T00:00:00Z")
	generate()
	var changed catalog.Catalog
	if err := json.Unmarshal(read(paths[0]), &changed); err != nil {
		t.Fatal(err)
	}
	updatedField := false
	for _, property := range changed.Operations[0].Properties {
		if property.Name == "name" && property.Description == "Updated field" {
			updatedField = true
		}
	}
	if changed.Sources[0].RetrievedAt != "2026-01-03T00:00:00Z" || !updatedField {
		t.Fatal("changed source content was suppressed")
	}
}
