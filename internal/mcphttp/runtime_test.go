package mcphttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

func testCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("cannot trust test certificate")
	}
	return certFile, keyFile, roots
}

func TestTLSRuntimeAndSafeLogs(t *testing.T) {
	certFile, keyFile, roots := testCertificate(t)
	settings := serverconfig.HTTP{Token: httpTestToken, Listen: "127.0.0.1:0", TLSCertFile: certFile, TLSKeyFile: keyFile}
	handler := testHandler(t, settings)
	listener, err := net.Listen("tcp", settings.Listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	done := make(chan error, 1)
	go func() { done <- serve(ctx, listener, handler, settings, logger) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("TLS listener did not shut down")
			return
		}
		if strings.Contains(logs.String(), httpTestToken) || !strings.Contains(logs.String(), "https://") {
			t.Errorf("unsafe or missing TLS endpoint log: %s", logs.String())
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+listener.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+httpTestToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("TLS health response: status=%d TLS=%v", response.StatusCode, response.TLS)
	}
	oldTLS := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}}
	connection, err := oldTLS.DialContext(t.Context(), "tcp", listener.Addr().String())
	if err == nil {
		_ = connection.Close()
		t.Fatal("obsolete TLS accepted")
	}
}

func TestServeReturnsTLSSetupFailure(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	dir := t.TempDir()
	settings := serverconfig.HTTP{Token: httpTestToken, Listen: "127.0.0.1:0", TLSCertFile: filepath.Join(dir, "missing-cert.pem"), TLSKeyFile: filepath.Join(dir, "missing-key.pem")}
	if err := Serve(t.Context(), server, settings, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("missing TLS files accepted")
	}
}

func TestHTTPToolCancellationForBothProtocolGenerations(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
			started, canceled := make(chan struct{}), make(chan struct{})
			mcp.AddTool(server, &mcp.Tool{Name: "wait", Description: "Wait for cancellation"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
				close(started)
				select {
				case <-ctx.Done():
					close(canceled)
					return nil, nil, ctx.Err()
				case <-time.After(3 * time.Second):
					return nil, nil, context.DeadlineExceeded
				}
			})
			handler, err := NewHandler(server, serverconfig.HTTP{Token: httpTestToken}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"` + version + `","io.modelcontextprotocol/clientCapabilities":{}}}}`
			request := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(body)).WithContext(ctx)
			request.Header.Set("Authorization", "Bearer "+httpTestToken)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("Mcp-Protocol-Version", version)
			request.Header.Set("Mcp-Method", "tools/call")
			request.Header.Set("Mcp-Name", "wait")
			finished := make(chan struct{})
			response := httptest.NewRecorder()
			go func() { handler.ServeHTTP(response, request); close(finished) }()
			select {
			case <-started:
			case <-finished:
				t.Fatalf("tool did not start: %d %s", response.Code, response.Body.String())
			case <-time.After(2 * time.Second):
				t.Fatal("tool did not start")
			}
			cancel()
			select {
			case <-canceled:
			case <-time.After(2 * time.Second):
				t.Fatal("HTTP cancellation did not reach the tool")
			}
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("canceled HTTP request did not complete")
			}
		})
	}
}
