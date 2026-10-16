// Package routeros implements bounded, authenticated HTTPS REST requests.
package routeros

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
)

type Client struct {
	profile config.Profile
	http    *http.Client
}

// Error deliberately excludes raw router response bodies and echoed parameters.
type Error struct {
	Kind    string `json:"kind"`
	Status  int    `json:"http_status,omitzero"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

func New(p config.Profile) (*Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if p.CAFile != "" {
		b, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, errors.New("could not read profile CA certificate")
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("profile ca_file contains no PEM certificates")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	// A router profile identifies the actual endpoint; do not send router
	// credentials to an ambient HTTP(S)_PROXY supplied to the MCP process.
	transport.Proxy = nil
	return &Client{profile: p, http: &http.Client{Transport: transport, Timeout: p.Timeout(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

var recordID = regexp.MustCompile(`^\*[0-9A-Fa-f]{1,62}$`)
var menuPath = regexp.MustCompile(`^[a-z0-9-]+(/[a-z0-9-]+)*$`)

func (c *Client) Request(ctx context.Context, method, path, id string, query url.Values, parameters map[string]any) (any, error) {
	if !menuPath.MatchString(path) {
		return nil, errors.New("invalid catalog menu path")
	}
	if id != "" && !recordID.MatchString(id) {
		return nil, errors.New("invalid RouterOS .id")
	}
	password, ok := os.LookupEnv(c.profile.PasswordEnv)
	if !ok || password == "" {
		return nil, &Error{Kind: "credentials", Message: "profile password environment variable is missing or empty"}
	}
	u := url.URL{Scheme: "https", Host: c.profile.Address(), Path: "/rest/" + path, RawQuery: query.Encode()}
	if id != "" {
		u.Path += "/" + id
	} // RouterOS requires the literal '*' in IDs.
	u.RawPath = strings.ReplaceAll(u.EscapedPath(), "%2A", "*")
	var body io.Reader
	if parameters != nil {
		encoded := make(map[string]string, len(parameters))
		for k, v := range parameters {
			switch v := v.(type) {
			case string:
				encoded[k] = v
			case bool:
				if v {
					encoded[k] = "true"
				} else {
					encoded[k] = "false"
				}
			case float64:
				if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v || math.Abs(v) > 9007199254740991 {
					return nil, errors.New("numeric values must be safe JSON integers; use a string for larger numbers")
				}
				encoded[k] = fmt.Sprintf("%.0f", v)
			case int:
				encoded[k] = fmt.Sprint(v)
			default:
				return nil, errors.New("configuration values must be scalar strings, booleans, or integers")
			}
		}
		b, err := json.Marshal(encoded)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errors.New("could not construct RouterOS request")
	}
	req.SetBasicAuth(c.profile.Username, password)
	req.Header.Set("Accept", "application/json")
	if parameters != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &Error{Kind: "cancelled", Message: "RouterOS request cancelled; check router state before repeating a mutation"}
		}
		if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
			return nil, &Error{Kind: "tls", Message: "RouterOS TLS verification failed; check ca_file and the certificate hostname"}
		}
		if e, ok := errors.AsType[*url.Error](err); ok && e.Timeout() {
			return nil, &Error{Kind: "timeout", Message: "RouterOS request timed out; mutation outcome may be unknown"}
		}
		return nil, &Error{Kind: "connection", Message: "RouterOS HTTPS connection failed; mutation outcome may be unknown"}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, statusError(resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.profile.MaxOutputBytes)+1))
	if err != nil {
		return nil, &Error{Kind: "response", Message: "could not read RouterOS response; mutation outcome may be unknown"}
	}
	if len(b) > c.profile.MaxOutputBytes {
		return nil, &Error{Kind: "response_limit", Message: "RouterOS response exceeds max_output_bytes; narrow filters/properties or raise the profile limit. A sent mutation may already have applied"}
	}
	if len(bytes.TrimSpace(b)) == 0 {
		if method == http.MethodGet {
			return nil, &Error{Kind: "response", Message: "RouterOS returned an empty read response"}
		}
		return map[string]any{}, nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, &Error{Kind: "response", Message: "RouterOS returned invalid JSON; a sent mutation may already have applied"}
	}
	switch out.(type) {
	case []any, map[string]any:
	default:
		return nil, &Error{Kind: "response", Message: "unexpected RouterOS JSON shape"}
	}
	return Redact(out, password), nil
}

func statusError(status int) *Error {
	e := &Error{Status: status, Kind: "routeros", Message: "RouterOS rejected the operation; inspect its parameters and firmware documentation"}
	switch {
	case status >= 300 && status < 400:
		e.Kind = "redirect"
		e.Message = "RouterOS redirect refused; configure the router HTTPS host and port directly"
	case status == 401:
		e.Kind = "authentication"
		e.Message = "RouterOS authentication failed; check profile credentials and the user's allowed addresses"
	case status == 403:
		e.Kind = "permission"
		e.Message = "RouterOS permission denied; check read/write, api and rest-api policies and web service access"
	case status == 404:
		e.Kind = "not_found"
		e.Message = "RouterOS menu or record not found; it may be unavailable on this firmware/package set or the .id may be stale"
	case status == 405 || status == 406 || status == 501:
		e.Kind = "unsupported"
		e.Message = "RouterOS does not support this operation for the menu or firmware"
	case status == 400 || status == 422:
		e.Kind = "invalid_parameters"
		e.Message = "RouterOS rejected the parameters; inspect the operation schema and current router references"
	case status == 429:
		e.Kind = "busy"
		e.Message = "RouterOS request limit reached; operation was not automatically retried"
	case status >= 500:
		e.Kind = "router_error"
		e.Message = "RouterOS server error; check router state before repeating a mutation"
	}
	return e
}

var secretAssignment = regexp.MustCompile(`(?i)(password|passwd|passphrase|private[-_]?key|preshared[-_]?key|secret|token|authorization)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)`)
var userInfo = regexp.MustCompile(`(https?://)[^\s/@]+:[^\s/@]+@`)

// Redact is recursive and also covers common key=value secrets in log messages.
// Free-form text can still contain secrets without recognizable labels.
func Redact(v any, secrets ...string) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, value := range v {
			n := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(k))
			if strings.Contains(n, "password") || strings.Contains(n, "passwd") || strings.Contains(n, "passphrase") || strings.Contains(n, "secret") || strings.Contains(n, "privatekey") || strings.Contains(n, "presharedkey") || strings.Contains(n, "token") || n == "authorization" || n == "reconfigurekey" {
				out[k] = "[REDACTED]"
			} else {
				out[k] = Redact(value, secrets...)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = Redact(item, secrets...)
		}
		return out
	case string:
		for _, secret := range secrets {
			if secret != "" {
				v = strings.ReplaceAll(v, secret, "[REDACTED]")
			}
		}
		v = secretAssignment.ReplaceAllString(v, "${1}${2}[REDACTED]")
		return userInfo.ReplaceAllString(v, "${1}[REDACTED]@")
	default:
		return v
	}
}
