package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValueGrammar(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"quoted", `a "b" \ c`, `"a \"b\" \\ c"`},
		{"empty list", []any{}, "[  ]"},
		{"nested", []any{map[string]any{"application": "dhcprelay4", "values": []any{map[string]any{"variable": "SERVER", "value": []any{"192.0.2.1"}}}}}, `[ { application "dhcprelay4" values [ { value [ "192.0.2.1" ] variable "SERVER" } ] } ]`},
		{"number", json.Number("42"), "42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Value(tt.value)
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	for _, input := range []any{"ok\nrule delete id 1", "\x1b[31m", map[string]any{"bad key": "v"}, nil} {
		if _, err := Value(input); err == nil {
			t.Fatalf("accepted unsafe value %#v", input)
		}
	}
}

func TestQuoteTransport(t *testing.T) {
	input := `name "$(touch /tmp/never);'quoted'"`
	words, err := Words(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 2 || words[1] != `$(touch /tmp/never);'quoted'` {
		t.Fatalf("words %#v", words)
	}
	if got := ShellQuote(words[1]); !strings.Contains(got, `'"'"'`) {
		t.Fatalf("single quote was not escaped: %s", got)
	}
}

func TestOutputRedactsBeforePagination(t *testing.T) {
	raw := "-----BEGIN PRIVATE KEY-----\nVERY_SECRET_MATERIAL\n-----END PRIVATE KEY-----\nnormal"
	out := Parse(raw, 1, 1)
	if strings.Contains(out.Text, "SECRET") {
		t.Fatalf("private key body leaked: %#v", out)
	}
	table := "application|variable|value\n-----------+--------+-----\nproxy|LOGIN_PASSWORD|hunter2\nproxy|PORT|8080"
	out = Parse(table, 0, 100)
	if out.Format != "table" || len(out.Rows) != 2 || out.Rows[0]["value"] != "[REDACTED]" || out.Rows[1]["value"] != "8080" {
		t.Fatalf("output %#v", out)
	}
	if !IsError("ERROR: bad value") || IsError("name|value\n----+-----\nerror_count|0") {
		t.Fatal("CLI error detection mismatch")
	}
}

func TestStructuredEnvelopeAndNestedSecrets(t *testing.T) {
	raw := `{"result":{"code":200,"status":"OK","content":[{"name":"alice","password":"NEVER"},{"variable":"REMOTE_SECRET","value":["NEVER"]},{"options":{"token":"NEVER"}}]},"version":"11.6"}`
	if !SuccessEnvelope(raw) || IsError(raw) {
		t.Fatal("successful envelope rejected")
	}
	out := Parse(raw, 1, 2)
	b, _ := json.Marshal(out)
	if out.Format != "json" || out.Total != 3 || strings.Contains(string(b), "NEVER") {
		t.Fatalf("structured redaction: %s", b)
	}
	if !IsError(`{"result":{"code":400,"status":"ERROR","content":"bad value"}}`) {
		t.Fatal("failed envelope accepted")
	}
	if SuccessEnvelope(raw[:len(raw)-2]) {
		t.Fatal("truncated envelope accepted")
	}
}
