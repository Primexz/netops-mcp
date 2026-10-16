package mcphttp

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

func testHandler(t *testing.T, settings serverconfig.HTTP) http.Handler {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	handler, err := NewHandler(server, settings, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestHTTPRejectsAmbiguousHeadersAndAuthorities(t *testing.T) {
	h := testHandler(t, httpSettings(t))
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+httpTestToken) }, 401},
		{"comma authorization", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+httpTestToken+", Bearer "+httpTestToken)
		}, 401},
		{"extra auth whitespace", func(r *http.Request) { r.Header.Set("Authorization", "Bearer  "+httpTestToken) }, 401},
		{"duplicate origin", func(r *http.Request) {
			r.Header["Origin"] = []string{"https://client.example", "https://attacker.example"}
		}, 403},
		{"empty origin", func(r *http.Request) { r.Header["Origin"] = []string{""} }, 403},
		{"origin list", func(r *http.Request) { r.Header.Set("Origin", "https://client.example https://attacker.example") }, 403},
		{"origin path", func(r *http.Request) { r.Header.Set("Origin", "https://client.example/") }, 403},
		{"origin credentials", func(r *http.Request) { r.Header.Set("Origin", "https://user@client.example") }, 403},
		{"host credentials", func(r *http.Request) { r.Host = "user@localhost" }, 403},
		{"host path", func(r *http.Request) { r.Host = "localhost/mcp" }, 403},
		{"host empty query", func(r *http.Request) { r.Host = "localhost?" }, 403},
		{"host empty fragment", func(r *http.Request) { r.Host = "localhost#" }, 403},
		{"host empty port", func(r *http.Request) { r.Host = "localhost:" }, 403},
		{"host invalid port", func(r *http.Request) { r.Host = "localhost:65536" }, 403},
		{"forwarded host ignored", func(r *http.Request) { r.Host = "attacker.example"; r.Header.Set("X-Forwarded-Host", "localhost") }, 403},
		{"forwarded origin ignored", func(r *http.Request) {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("Origin", "https://localhost")
		}, 403},
		{"case insensitive bearer", func(r *http.Request) { r.Header.Set("Authorization", "bEaReR "+httpTestToken) }, 200},
		{"IPv6 loopback", func(r *http.Request) { r.Host = "[::1]:8080" }, 200},
		{"TLS same origin", func(r *http.Request) { r.TLS = new(tls.ConnectionState); r.Header.Set("Origin", "https://localhost") }, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
			r.Header.Set("Authorization", "Bearer "+httpTestToken)
			tc.edit(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("security headers missing")
			}
		})
	}
}

func TestHTTPCORSPreflightHeaders(t *testing.T) {
	h := testHandler(t, httpSettings(t))
	for _, tc := range []struct {
		name    string
		methods []string
		headers []string
		want    int
	}{
		{"allowed", []string{"POST"}, []string{"Authorization, Content-Type", "Accept, MCP-Protocol-Version, MCP-Session-Id, MCP-Method, MCP-Name, Last-Event-ID"}, 204},
		{"missing method", nil, nil, 405},
		{"get method", []string{"GET"}, nil, 405},
		{"duplicate method", []string{"POST", "GET"}, nil, 405},
		{"unknown header", []string{"POST"}, []string{"Authorization, X-Admin"}, 403},
		{"unknown second header", []string{"POST"}, []string{"Authorization", "X-Admin"}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, "http://localhost/mcp", nil)
			r.Header.Set("Origin", "https://client.example")
			r.Header["Access-Control-Request-Method"] = tc.methods
			r.Header["Access-Control-Request-Headers"] = tc.headers
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == 204 && (w.Header().Get("Access-Control-Allow-Methods") != "POST" || !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization")) {
				t.Fatal("missing CORS permissions")
			}
		})
	}
}

func TestHTTPTokenBoundariesAndInvalidEnvironment(t *testing.T) {
	for _, size := range []int{32, 4096} {
		testHandler(t, serverconfig.HTTP{Token: strings.Repeat("x", size)})
	}
	for _, token := range []string{"", strings.Repeat("x", 31), strings.Repeat("x", 4097), httpTestToken + "\t", httpTestToken + "é", httpTestToken + ","} {
		settings := httpSettings(t)
		t.Setenv(settings.TokenEnv, token)
		server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
		_, err := NewHandler(server, settings, nil)
		if err == nil || !strings.Contains(err.Error(), settings.TokenEnv) || token != "" && strings.Contains(err.Error(), token) {
			t.Fatalf("invalid token validation must name its source without exposing its value: %v", err)
		}
	}
}

func TestHTTPRemoteListenerPolicy(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	for _, listen := range []string{"0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "public.example:8080", ":8080"} {
		_, err := NewHandler(server, serverconfig.HTTP{Token: httpTestToken, Listen: listen, AllowedHosts: []string{"mcp.example"}}, nil)
		if err == nil || !strings.Contains(err.Error(), "tls") {
			t.Fatalf("remote listener %q accepted without TLS: %v", listen, err)
		}
	}
	settings := serverconfig.HTTP{Token: httpTestToken, Listen: "0.0.0.0:8080", TLSCertFile: "/offline/cert.pem", TLSKeyFile: "/offline/key.pem"}
	if _, err := NewHandler(server, settings, nil); err == nil {
		t.Fatal("wildcard listener accepted without an explicit host allowlist")
	}
	settings.AllowedHosts = []string{"mcp.example"}
	h := testHandler(t, settings)
	for host, want := range map[string]int{"mcp.example:443": 200, "localhost": 403} {
		r := httptest.NewRequest(http.MethodGet, "https://mcp.example/healthz", nil)
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+httpTestToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("remote host %q: status %d, want %d", host, w.Code, want)
		}
	}
}

func TestHTTPJSONResponseAndChunkedLimit(t *testing.T) {
	settings := httpSettings(t)
	settings.MaxRequestBytes = 1024
	h := testHandler(t, settings)
	for _, chunked := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(strings.Repeat(" ", 2048)))
		if chunked {
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
		}
		r.Header.Set("Authorization", "Bearer "+httpTestToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v: status %d: %s", chunked, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`))
	r.Header.Set("Authorization", "Bearer "+httpTestToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || !json.Valid(w.Body.Bytes()) || w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("stateless JSON response: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
}

func TestResponseLimitNeverSendsPartialSuccess(t *testing.T) {
	for _, size := range []int{15, 16, 17} {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Protocol-Version", "2025-11-25")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(strings.Repeat("x", 8)))
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("SDK flush compatibility: %v", err)
			}
			_, _ = w.Write([]byte(strings.Repeat("x", size-8)))
		})
		w := httptest.NewRecorder()
		limitResponse(next, 16).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://localhost/mcp", nil))
		if size <= 16 {
			if w.Code != 201 || w.Body.Len() != size || w.Header().Get("Mcp-Protocol-Version") != "2025-11-25" {
				t.Fatal("bounded response changed", w.Code, w.Body.String())
			}
		} else if w.Code != 500 || strings.Contains(w.Body.String(), "xxxxxxxx") || !strings.Contains(w.Body.String(), "may already have applied") {
			t.Fatal("overflow sent partial success or lost change warning", w.Code, w.Body.String())
		}
	}
}
