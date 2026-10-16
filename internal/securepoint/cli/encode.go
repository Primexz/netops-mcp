// Package cli handles the Securepoint CLI grammar, never a general-purpose shell.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

var Identifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)

// Value encodes one CLI value. Control characters are rejected: newlines and
// terminal escape characters cannot be used to inject additional commands.
func Value(v any) (string, error) {
	return value(v, 0)
}

func value(v any, depth int) (string, error) {
	if depth > 12 {
		return "", errors.New("CLI value nesting exceeds 12 levels")
	}
	switch v := v.(type) {
	case string:
		if len(v) > 1<<20 {
			return "", errors.New("CLI string exceeds 1 MiB")
		}
		if strings.ContainsFunc(v, unicode.IsControl) {
			return "", errors.New("control characters are not allowed in CLI values; use a multiline input artifact where supported")
		}
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`, nil
	case json.Number:
		if _, err := v.Float64(); err != nil {
			return "", errors.New("invalid number")
		}
		return string(v), nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "", errors.New("non-finite number")
		}
		return fmt.Sprint(v), nil
	case int:
		return fmt.Sprint(v), nil
	case bool:
		if v {
			return "1", nil
		}
		return "0", nil
	case []string:
		items := make([]any, len(v))
		for i, s := range v {
			items[i] = s
		}
		return value(items, depth+1)
	case []any:
		parts := make([]string, 0, len(v))
		for _, x := range v {
			s, err := value(x, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[ " + strings.Join(parts, " ") + " ]", nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(v))
		for _, k := range keys {
			if !Identifier.MatchString(k) {
				return "", fmt.Errorf("invalid CLI object key %q", k)
			}
			s, err := value(v[k], depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, k+" "+s)
		}
		return "{ " + strings.Join(parts, " ") + " }", nil
	default:
		return "", fmt.Errorf("unsupported CLI value type %T", v)
	}
}

// ShellQuote is used only to transport already-encoded CLI words through a root
// login shell, or to construct an explicitly cataloged diagnostic invocation.
func ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func Words(s string) ([]string, error) {
	var result []string
	var current strings.Builder
	quoted, escaped, active := false, false, false
	for _, r := range s {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && quoted {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			active = true
			continue
		}
		if !quoted && unicode.IsSpace(r) {
			if active {
				result = append(result, current.String())
				current.Reset()
				active = false
			}
			continue
		}
		current.WriteRune(r)
		active = true
	}
	if quoted || escaped {
		return nil, errors.New("unbalanced CLI quotes")
	}
	if active {
		result = append(result, current.String())
	}
	return result, nil
}
