package mcphttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const httpTestToken = "test-token-0123456789abcdefghijklmnopqrstuvwxyz"

func httpSettings(t *testing.T) serverconfig.HTTP {
	t.Helper()
	t.Setenv("MCP_HTTP_TEST_TOKEN", httpTestToken)
	return serverconfig.HTTP{TokenEnv: "MCP_HTTP_TEST_TOKEN", AllowedOrigins: []string{"https://client.example"}}
}

func TestHTTPAuthenticationHostOriginAndPreflight(t *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	h, err := NewHandler(s, httpSettings(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, token, host, origin, method string
		want                              int
	}{
		{"missing token", "", "localhost:8080", "", "POST", 401},
		{"wrong token", "wrong", "localhost:8080", "", "POST", 401},
		{"query token", "", "localhost:8080", "", "GET", 401},
		{"host attack", httpTestToken, "attacker.example", "", "POST", 403},
		{"origin attack", httpTestToken, "localhost:8080", "https://attacker.example", "POST", 403},
		{"null origin", httpTestToken, "localhost:8080", "null", "POST", 403},
		{"allowed origin", httpTestToken, "localhost:8080", "https://client.example", "POST", 200},
		{"same origin", httpTestToken, "localhost:8080", "http://localhost:8080", "POST", 200},
		{"preflight", "", "localhost:8080", "https://client.example", "OPTIONS", 204},
		{"rejected preflight", "", "localhost:8080", "https://attacker.example", "OPTIONS", 403},
		{"no standalone SSE", httpTestToken, "localhost:8080", "", "GET", 405},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, "http://localhost:8080/mcp?access_token="+httpTestToken, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
			request.Host = tt.host
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			if tt.token != "" {
				request.Header.Set("Authorization", "Bearer "+tt.token)
			}
			if tt.origin != "" {
				request.Header.Set("Origin", tt.origin)
			}
			if tt.method == "OPTIONS" {
				request.Header.Set("Access-Control-Request-Method", "POST")
				request.Header.Set("Access-Control-Request-Headers", "Authorization, MCP-Protocol-Version, Content-Type")
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != tt.want {
				t.Fatalf("status %d, want %d; %s", response.Code, tt.want, response.Body.String())
			}
			if strings.Contains(response.Body.String(), httpTestToken) {
				t.Fatal("token leaked in response")
			}
			if tt.want == 401 && response.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing authentication challenge")
			}
			if tt.want == 204 && response.Header().Get("Access-Control-Allow-Origin") != "https://client.example" {
				t.Fatal("missing CORS grant")
			}
		})
	}
}

func TestHTTPTokenSources(t *testing.T) {
	const otherToken = "other-token-0123456789abcdefghijklmnopqrstuvwxyz"
	for _, tt := range []struct {
		name, configured, environment, accepted, rejected string
	}{
		{"config without environment", httpTestToken, "", httpTestToken, otherToken},
		{"config overrides environment", httpTestToken, otherToken, httpTestToken, otherToken},
		{"environment fallback", "", otherToken, otherToken, httpTestToken},
	} {
		t.Run(tt.name, func(t *testing.T) {
			settings := httpSettings(t)
			settings.Token = tt.configured
			t.Setenv(settings.TokenEnv, tt.environment)
			s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			h, err := NewHandler(s, settings, nil)
			if err != nil {
				t.Fatal(err)
			}
			for token, want := range map[string]int{tt.accepted: http.StatusOK, tt.rejected: http.StatusUnauthorized} {
				request := httptest.NewRequest("GET", "http://localhost/healthz", nil)
				request.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				h.ServeHTTP(response, request)
				if response.Code != want {
					t.Fatalf("authentication status %d, want %d", response.Code, want)
				}
			}
		})
	}
}

func TestHTTPRejectsInvalidConfiguredToken(t *testing.T) {
	for _, token := range []string{"short", strings.Repeat("x", 4097), httpTestToken + " unsafe", httpTestToken + "\n"} {
		settings := httpSettings(t)
		settings.Token = token
		s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
		_, err := NewHandler(s, settings, nil)
		if err == nil {
			t.Fatal("invalid configured token accepted despite a valid environment token")
		}
		if !strings.Contains(err.Error(), "http.token") || strings.Contains(err.Error(), token) {
			t.Fatal("token validation must name its setting without exposing the token")
		}
	}
}

func TestHTTPRejectsMissingTokenAndOversizedBody(t *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	settings := httpSettings(t)
	t.Setenv(settings.TokenEnv, "")
	if _, err := NewHandler(s, settings, nil); err == nil {
		t.Fatal("missing token accepted")
	}
	t.Setenv(settings.TokenEnv, "short")
	if _, err := NewHandler(s, settings, nil); err == nil {
		t.Fatal("weak token accepted")
	}
	t.Setenv(settings.TokenEnv, httpTestToken)
	settings.MaxRequestBytes = 1024
	h, err := NewHandler(s, settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader(strings.Repeat(" ", 2048)))
	request.Header.Set("Authorization", "Bearer "+httpTestToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status %d: %s", w.Code, w.Body.String())
	}
}

func TestHTTPShutdown(t *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	settings := httpSettings(t)
	settings.Listen = "127.0.0.1:0"
	// Cancellation may race listener setup; either a canceled listen or a clean
	// shutdown is acceptable, but a running server must not outlive its context.
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, s, settings, nil) }()
	cancel()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "canceled") {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not shut down")
	}
}

func TestHTTPHealthAndDuplicateAuthHeaders(t *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	h, err := NewHandler(s, httpSettings(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(h)
	defer host.Close()
	req, err := http.NewRequestWithContext(t.Context(), "GET", host.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+httpTestToken)
	response, err := host.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || string(b) != `{"status":"ok"}` {
		t.Fatalf("health %d %s", response.StatusCode, b)
	}
	req.Header.Add("Authorization", "Bearer "+httpTestToken)
	response, err = host.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("duplicate authorization accepted: %d", response.StatusCode)
	}
}

func TestGracefulHTTPShutdownCancelsRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	cancelled := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(cancelled) })
	done := make(chan error, 1)
	go func() { done <- serve(ctx, listener, h, serverconfig.HTTP{}, nil) }()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		resp, err := http.Get("http://" + listener.Addr().String() + "/mcp")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("request context not cancelled")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP server did not stop")
	}
	<-requestDone
}
