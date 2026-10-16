// Package mcphttp serves authenticated, stateless MCP over HTTP for both servers.
package mcphttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

// NewHandler serves the same catalog and engine as stdio. One bearer token
// represents one administration principal, including its profiles and plans.
// Construct it before serving requests: it installs MCP cancellation middleware.
func NewHandler(server *mcp.Server, settings serverconfig.HTTP, logger *slog.Logger) (http.Handler, error) {
	if server == nil {
		return nil, errors.New("MCP server is required")
	}
	settings.AllowedHosts = slices.Clone(settings.AllowedHosts)
	settings.AllowedOrigins = slices.Clone(settings.AllowedOrigins)
	if err := settings.Normalize(""); err != nil {
		return nil, err
	}
	logger = stderrLogger(logger)
	token, tokenSource := settings.Token, "http.token"
	if token == "" {
		token, tokenSource = os.Getenv(settings.TokenEnv), settings.TokenEnv
	}
	if len(token) < 32 || len(token) > 4096 || strings.ContainsFunc(token, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-._~+/=", r)
	}) {
		return nil, fmt.Errorf("%s must contain a bearer token of 32..4096 ASCII token characters", tokenSource)
	}
	expected := sha256.Sum256([]byte(token))
	server.AddReceivingMiddleware(requestCancellation)
	stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: settings.MaxRequestBytes,
		PropagateRequestCancellation: true, Logger: logger,
		// Our explicit host allowlist also supports reverse proxies preserving
		// a public Host while connecting to a loopback listener.
		DisableLocalhostProtection: true,
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", limitResponse(stream, maxResponseBytes))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !allowedHost(r.Host, settings.AllowedHosts) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		origin := r.Header.Get("Origin")
		if len(r.Header.Values("Origin")) > 1 || len(r.Header.Values("Origin")) == 1 && origin == "" {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if origin != "" {
			if !allowedOrigin(r, origin, settings.AllowedOrigins) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Expose-Headers", "MCP-Protocol-Version, MCP-Session-Id")
			if r.Method == http.MethodOptions && r.URL.Path == "/mcp" {
				if len(r.Header.Values("Access-Control-Request-Method")) != 1 || r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
					w.Header().Set("Allow", "POST")
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				for _, fields := range r.Header.Values("Access-Control-Request-Headers") {
					for field := range strings.SplitSeq(fields, ",") {
						if field = strings.ToLower(strings.TrimSpace(field)); field != "" && !slices.Contains([]string{"authorization", "content-type", "accept", "mcp-protocol-version", "mcp-session-id", "mcp-method", "mcp-name", "last-event-id"}, field) {
							http.Error(w, "header not allowed", http.StatusForbidden)
							return
						}
					}
				}
				w.Header().Set("Access-Control-Allow-Methods", "POST")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, MCP-Method, MCP-Name, Last-Event-ID")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		scheme, supplied, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		digest := sha256.Sum256([]byte(supplied))
		if !ok || !strings.EqualFold(scheme, "Bearer") || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(digest[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netops-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		requestContext := context.WithValue(r.Context(), requestContextKey{}, r.Context())
		mux.ServeHTTP(w, r.WithContext(requestContext))
	}), nil
}

type requestContextKey struct{}

// The SDK retains context values but detaches cancellation for legacy protocol
// sessions. Our sessions serve one HTTP request each, so their tool handlers
// must stop when that request ends, including on process shutdown.
func requestCancellation(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
		parent, ok := ctx.Value(requestContextKey{}).(context.Context)
		if !ok {
			return next(ctx, method, request)
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(parent, cancel)
		defer stop()
		if parent.Err() != nil {
			cancel()
		}
		return next(ctx, method, request)
	}
}

func allowedHost(authority string, hosts []string) bool {
	u, err := url.Parse("http://" + authority)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(authority, "?#") {
		return false
	}
	if _, err := serverconfig.Origin("http://" + authority); err != nil {
		return false
	}
	host, err := serverconfig.HostName(u.Hostname())
	return err == nil && slices.Contains(hosts, host)
}

func allowedOrigin(r *http.Request, origin string, allowed []string) bool {
	normalized, err := serverconfig.Origin(origin)
	if err != nil {
		return false
	}
	if slices.Contains(allowed, normalized) {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	same, err := serverconfig.Origin(scheme + "://" + r.Host)
	return err == nil && normalized == same
}

// Serve runs until the process context is canceled, then stops accepting
// requests and waits for HTTP connections to close. Active requests inherit the
// process context so appliance operations are canceled before the grace period expires.
func Serve(ctx context.Context, server *mcp.Server, settings serverconfig.HTTP, logger *slog.Logger) error {
	settings.AllowedHosts = slices.Clone(settings.AllowedHosts)
	settings.AllowedOrigins = slices.Clone(settings.AllowedOrigins)
	if err := settings.Normalize(""); err != nil {
		return err
	}
	handler, err := NewHandler(server, settings, logger)
	if err != nil {
		return err
	}
	logger = stderrLogger(logger)
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", settings.Listen)
	if err != nil {
		return fmt.Errorf("MCP HTTP listener: %w", err)
	}
	defer func() { _ = listener.Close() }()
	return serve(ctx, listener, handler, settings, logger)
}

// serve owns the server lifecycle; keeping the listener separate permits offline
// loopback fixtures to observe cancellation of in-flight requests.
func serve(ctx context.Context, listener net.Listener, handler http.Handler, settings serverconfig.HTTP, logger *slog.Logger) error {
	logger = stderrLogger(logger)
	httpServer := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
		TLSConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:    slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	done := make(chan struct{})
	shutdown := make(chan error, 1)
	go func() {
		select {
		case <-done:
			shutdown <- nil
			return
		case <-ctx.Done():
		}
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := httpServer.Shutdown(stop)
		if err != nil {
			_ = httpServer.Close()
		}
		shutdown <- err
	}()
	secure := settings.TLSCertFile != ""
	scheme := "http"
	if secure {
		scheme = "https"
	}
	logger.Info("MCP HTTP listening", "endpoint", scheme+"://"+listener.Addr().String()+"/mcp")
	var err error
	if secure {
		err = httpServer.ServeTLS(listener, settings.TLSCertFile, settings.TLSKeyFile)
	} else {
		err = httpServer.Serve(listener)
	}
	close(done)
	shutdownErr := <-shutdown
	if errors.Is(err, http.ErrServerClosed) {
		return shutdownErr
	}
	return errors.Join(err, shutdownErr)
}

func stderrLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return logger
}
