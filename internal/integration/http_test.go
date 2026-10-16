package integration_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Primexz/netops-mcp/internal/mcphttp"
	mtcatalog "github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	mtconfig "github.com/Primexz/netops-mcp/internal/mikrotik/config"
	mtengine "github.com/Primexz/netops-mcp/internal/mikrotik/engine"
	mtserver "github.com/Primexz/netops-mcp/internal/mikrotik/mcpserver"
	spcatalog "github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	spconfig "github.com/Primexz/netops-mcp/internal/securepoint/config"
	spengine "github.com/Primexz/netops-mcp/internal/securepoint/engine"
	spserver "github.com/Primexz/netops-mcp/internal/securepoint/mcpserver"
	sptransport "github.com/Primexz/netops-mcp/internal/securepoint/transport"
	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

type noApplianceRunner struct{ t *testing.T }

func (r noApplianceRunner) Run(context.Context, spconfig.Profile, sptransport.Request) (sptransport.Result, error) {
	r.t.Error("HTTP discovery must not execute an appliance request")
	return sptransport.Result{}, errors.New("appliance access is disabled in this fixture")
}

type notificationHTTPTransport struct {
	base          http.RoundTripper
	token         string
	subscriptions atomic.Int32
}

func (transport *notificationHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+transport.token)
	if request.Header.Get("Mcp-Method") == "subscriptions/listen" {
		transport.subscriptions.Add(1)
	}
	return transport.base.RoundTrip(request)
}

// Notification handlers make the SDK open subscriptions/listen when listChanged
// is advertised. Static catalogs must allow discovery over buffered JSON HTTP
// without opening that long-lived stream.
func TestStaticVendorCatalogsWithHTTPNotificationHandlers(t *testing.T) {
	for _, fixture := range []struct {
		name          string
		profileTool   string
		wantResources bool
		newServer     func(*testing.T, *slog.Logger) (*mcp.Server, error)
	}{
		{
			name: "sp-utm-mcp", profileTool: "utm_profiles_list", wantResources: true,
			newServer: func(t *testing.T, logger *slog.Logger) (*mcp.Server, error) {
				configuration := &spconfig.Config{
					ArtifactDir: t.TempDir(),
					Profiles:    map[string]spconfig.Profile{"main": {Host: "192.0.2.1", Username: "mcp", PasswordEnv: "NETOPS_HTTP_REGRESSION_PASSWORD"}},
				}
				if err := configuration.Normalize(t.TempDir()); err != nil {
					return nil, err
				}
				catalog, err := spcatalog.Load()
				if err != nil {
					return nil, err
				}
				return spserver.New(spengine.New(configuration, catalog, noApplianceRunner{t: t}, logger))
			},
		},
		{
			name: "mikrotik-mcp", profileTool: "mikrotik_profiles_list",
			newServer: func(t *testing.T, logger *slog.Logger) (*mcp.Server, error) {
				configuration := &mtconfig.Config{
					Profiles: map[string]mtconfig.Profile{"main": {Host: "192.0.2.1", Username: "mcp", PasswordEnv: "NETOPS_HTTP_REGRESSION_PASSWORD"}},
				}
				if err := configuration.Normalize(t.TempDir()); err != nil {
					return nil, err
				}
				catalog, err := mtcatalog.Load()
				if err != nil {
					return nil, err
				}
				engine := mtengine.New(configuration, catalog, logger)
				t.Cleanup(engine.Close)
				return mtserver.New(engine)
			},
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			t.Setenv("NETOPS_HTTP_REGRESSION_PASSWORD", "")
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, err := fixture.newServer(t, logger)
			if err != nil {
				t.Fatal(err)
			}
			const token = "offline-http-regression-0123456789abcdefghijklmnopqrstuvwxyz"
			handler, err := mcphttp.NewHandler(server, serverconfig.HTTP{Token: token}, logger)
			if err != nil {
				t.Fatal(err)
			}
			host := httptest.NewServer(handler)
			defer host.Close()
			transport := &notificationHTTPTransport{base: host.Client().Transport, token: token}
			// The SDK opens notification streams with its own background context.
			// Bound HTTP requests as well as Connect so a regression fails promptly.
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			client := mcp.NewClient(&mcp.Implementation{Name: "notification-regression", Version: "1"}, &mcp.ClientOptions{
				Logger:                     logger,
				ToolListChangedHandler:     func(context.Context, *mcp.ToolListChangedRequest) {},
				ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) {},
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint: host.URL + "/mcp", HTTPClient: httpClient,
				MaxRetries: -1, DisableStandaloneSSE: true,
			}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
			if err != nil {
				t.Fatalf("notification-enabled discovery failed: %v", err)
			}
			defer func() {
				if err := session.Close(); err != nil {
					t.Error(err)
				}
			}()
			initialization := session.InitializeResult()
			if initialization.ProtocolVersion != "2026-07-28" || initialization.ServerInfo == nil || initialization.ServerInfo.Name != fixture.name {
				t.Fatalf("unexpected discovery result: %+v", initialization)
			}
			capabilities := initialization.Capabilities
			if capabilities == nil || capabilities.Tools == nil || capabilities.Tools.ListChanged {
				t.Fatalf("static tools must advertise support without listChanged: %+v", capabilities)
			}
			if fixture.wantResources && capabilities.Resources == nil {
				t.Fatal("Securepoint resource capability disappeared")
			}
			if capabilities.Resources != nil && capabilities.Resources.ListChanged {
				t.Fatal("static resources advertise listChanged")
			}
			var names []string
			for tool, err := range session.Tools(ctx, nil) {
				if err != nil {
					t.Fatalf("tools listing failed: %v", err)
				}
				names = append(names, tool.Name)
			}
			if !slices.Contains(names, fixture.profileTool) {
				t.Fatalf("tools listing lost %q (%d tools returned)", fixture.profileTool, len(names))
			}
			if fixture.wantResources {
				resources, err := session.ListResources(ctx, nil)
				if err != nil || len(resources.Resources) == 0 {
					t.Fatalf("resources listing failed: result=%v error=%v", resources, err)
				}
			}
			if attempts := transport.subscriptions.Load(); attempts != 0 {
				t.Fatalf("static discovery attempted %d notification subscriptions", attempts)
			}
		})
	}
}
