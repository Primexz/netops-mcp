package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Output struct {
	Format  string              `json:"format"`
	Columns []string            `json:"columns,omitempty"`
	Rows    []map[string]string `json:"rows,omitempty"`
	Text    string              `json:"text,omitempty"`
	Total   int                 `json:"total"`
	Offset  int                 `json:"offset"`
	More    bool                `json:"more"`
	Data    any                 `json:"data,omitempty"`
}

type envelope struct {
	Result *struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Content any    `json:"content"`
	} `json:"result"`
}

func Envelope(raw string) (any, int, bool) {
	var e envelope
	if json.Unmarshal([]byte(raw), &e) != nil || e.Result == nil {
		return nil, 0, false
	}
	return e.Result.Content, e.Result.Code, true
}

func SuccessEnvelope(raw string) bool {
	_, code, ok := Envelope(raw)
	return ok && code >= 200 && code < 300
}

var ansi = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var divider = regexp.MustCompile(`^[\s\-+|=]+$`)
var pem = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)`)
var assignment = regexp.MustCompile(`(?im)([a-zA-Z0-9_\-]*(?:password|passwd|passphrase|secret|token|api_?key|private_?key|psk)[a-zA-Z0-9_\-]*\s*(?:[=:]|\|)\s*)([^\r\n]*)`)
var cliError = regexp.MustCompile(`(?im)^\s*(?:error(?:\s|:|$)|failed(?:\s|:|$)|failure(?:\s|:|$)|invalid command\b|unknown (?:command|parameter)\b|syntax error\b|command not found\b|permission denied\b|access denied\b)`)

func IsError(s string) bool {
	if _, code, ok := Envelope(s); ok {
		return code < 200 || code >= 300
	}
	return cliError.MatchString(ansi.ReplaceAllString(s, "")) || strings.HasPrefix(strings.TrimSpace(s), "-- failed")
}

func SecretName(s string) bool {
	s = strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	for _, part := range []string{"password", "passwd", "passphrase", "secret", "token", "apikey", "privatekey", "privkey", "sharedkey", "authkey", "signingkey", "community", "psk", "credential", "dlkey"} {
		if strings.Contains(s, part) {
			return true
		}
	}
	return strings.HasSuffix(s, "pass") || s == "pin" || s == "newpin" || s == "puk" || s == "key"
}

func RedactText(s string) string {
	s = ansi.ReplaceAllString(s, "")
	s = pem.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	return assignment.ReplaceAllString(s, "${1}[REDACTED]")
}

func Parse(raw string, offset, limit int) Output {
	if content, _, ok := Envelope(raw); ok {
		out := Output{Format: "json", Offset: offset}
		data := redactJSON(content)
		if list, ok := data.([]any); ok {
			out.Total = len(list)
			start := min(offset, len(list))
			end := min(start+limit, len(list))
			out.Data = list[start:end]
			out.More = end < len(list)
		} else {
			out.Total = 1
			out.Data = data
		}
		return out
	}
	raw = strings.TrimSpace(ansi.ReplaceAllString(raw, ""))
	lines := strings.Split(raw, "\n")
	out := Output{Format: "text", Total: len(lines), Offset: offset}
	// Securepoint emits pipe-delimited tables with a separator after the header.
	for i := 0; i+1 < len(lines); i++ {
		if !strings.Contains(lines[i], "|") || !divider.MatchString(strings.TrimSpace(lines[i+1])) {
			continue
		}
		out.Format = "table"
		for col := range strings.SplitSeq(lines[i], "|") {
			out.Columns = append(out.Columns, strings.TrimSpace(col))
		}
		var rows []map[string]string
		lastIdentity := ""
		for _, line := range lines[i+2:] {
			if strings.TrimSpace(line) == "" || divider.MatchString(strings.TrimSpace(line)) {
				continue
			}
			parts := strings.SplitN(line, "|", len(out.Columns))
			if len(parts) != len(out.Columns) { // Preserve unexpected output instead of silently dropping it.
				out.Text += RedactText(line) + "\n"
				continue
			}
			row := make(map[string]string, len(parts))
			for j, col := range out.Columns {
				row[col] = strings.TrimSpace(parts[j])
			}
			// Continuation rows of EXTC values can have an empty variable cell.
			for key, v := range row {
				if strings.EqualFold(key, "variable") || strings.EqualFold(key, "attribute") {
					if v != "" {
						lastIdentity = v
					}
					if v == "" && SecretName(lastIdentity) {
						for col := range row {
							if strings.EqualFold(col, "value") || strings.EqualFold(col, "values") {
								row[col] = "[REDACTED]"
							}
						}
					}
				}
			}
			redactRow(row)
			rows = append(rows, row)
		}
		out.Total = len(rows)
		start := min(offset, len(rows))
		end := min(start+limit, len(rows))
		out.Rows = rows[start:end]
		out.More = end < len(rows)
		return out
	}
	start := min(offset, len(lines))
	end := min(start+limit, len(lines))
	// Redact the whole document before pagination so PEM delimiters cannot be
	// split across pages and expose the body on a later page.
	redacted := strings.Split(RedactText(raw), "\n")
	start = min(start, len(redacted))
	end = min(end, len(redacted))
	out.Text = strings.Join(redacted[start:end], "\n")
	out.More = end < len(redacted)
	return out
}

func redactJSON(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := map[string]any{}
		sensitive := false
		for k, v := range value {
			if strings.EqualFold(k, "variable") || strings.EqualFold(k, "attribute") || strings.EqualFold(k, "name") {
				if s, ok := v.(string); ok && SecretName(s) {
					sensitive = true
				}
			}
		}
		for k, v := range value {
			if SecretName(k) || sensitive && (strings.EqualFold(k, "value") || strings.EqualFold(k, "values")) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = redactJSON(v)
			}
		}
		return out
	case []any:
		list := make([]any, len(value))
		for i, v := range value {
			list[i] = redactJSON(v)
		}
		return list
	case string:
		return RedactText(value)
	default:
		return value
	}
}

// Records supplies simple fields for reference validation without flattening
// the structured data returned to MCP clients.
func (o Output) Records() []map[string]string {
	if o.Format == "table" {
		return o.Rows
	}
	var rows []map[string]string
	if list, ok := o.Data.([]any); ok {
		for _, v := range list {
			if m, ok := v.(map[string]any); ok {
				row := map[string]string{}
				for k, v := range m {
					row[k] = fmt.Sprint(v)
				}
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func redactRow(row map[string]string) {
	sensitiveValue := false
	for k, v := range row {
		lower := strings.ToLower(k)
		if (lower == "variable" || lower == "attribute" || lower == "name" || lower == "key") && SecretName(v) {
			sensitiveValue = true
		}
	}
	for k, v := range row {
		if SecretName(k) || (sensitiveValue && (strings.EqualFold(k, "value") || strings.EqualFold(k, "values"))) {
			row[k] = "[REDACTED]"
		} else {
			row[k] = RedactText(v)
		}
	}
}
