package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
	"github.com/Primexz/netops-mcp/internal/securepoint/transport"
)

type fakeRunner struct {
	mu           sync.Mutex
	outputs      map[string]string
	calls        []string
	failCommand  string
	started      bool
	blockCommand string
	entered      chan struct{}
	release      chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, p config.Profile, r transport.Request) (transport.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Command)
	out := f.outputs[r.Command]
	fail := f.failCommand == r.Command
	block := f.blockCommand == r.Command
	f.mu.Unlock()
	if block {
		select {
		case f.entered <- struct{}{}:
		default:
		}
		select {
		case <-f.release:
		case <-ctx.Done():
			return transport.Result{Started: true}, ctx.Err()
		}
	}
	if fail {
		return transport.Result{Output: out, Started: f.started}, errors.New("simulated connection loss")
	}
	return transport.Result{Output: out, Started: true}, nil
}

func testEngine(t *testing.T) (*Engine, *fakeRunner, *bytes.Buffer) {
	t.Helper()
	c := &config.Config{ArtifactDir: t.TempDir(), Profiles: map[string]config.Profile{
		"first":  {Host: "192.0.2.1", Username: "admin", PasswordEnv: "PASS", ReadOnly: new(false), AllowUnverified: true},
		"second": {Host: "192.0.2.2", Username: "admin", PasswordEnv: "PASS", ReadOnly: new(false), AllowUnverified: true},
	}}
	if err := c.Normalize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{outputs: map[string]string{
		"system info":        "attribute|value\n---------+-----\nversion|14.1.3\nserial|TEST",
		"help":               "node get\nnode new\nnode set\nrule get\nrule new\nservice get\nuser get\ninterface get\nroute get\ncert get\nsystem info\nsystem config get",
		"node get":           "id|name|address|zone\n--+----+-------+----\n1|existing|192.0.2.1|internal",
		"interface zone get": "id|name\n--+----\n1|internal",
		"system config get":  "name|active\n----+------\nmain|1",
	}}
	logs := &bytes.Buffer{}
	return New(c, cat, f, slog.New(slog.NewJSONHandler(logs, nil))), f, logs
}

func prepareNode(t *testing.T, e *Engine) Plan {
	t.Helper()
	r, err := e.Call(t.Context(), "first", "utm_node_new", map[string]any{"name": "newhost", "address": "192.0.2.8", "zone": "internal"}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan == nil {
		t.Fatal("no plan")
	}
	return *r.Plan
}

func TestPreviewExecuteActivationSaveAndReplay(t *testing.T) {
	e, f, _ := testEngine(t)
	p := prepareNode(t, e)
	for _, call := range f.calls {
		if strings.HasPrefix(call, "node new") {
			t.Fatal("preview mutated appliance")
		}
	}
	r, err := e.Execute(t.Context(), "first", p.ID, true, true)
	if err != nil || r.Status != "completed" || !r.Saved || len(r.Steps) != 3 {
		t.Fatalf("%#v %v", r, err)
	}
	want := []string{`node new name "newhost" address "192.0.2.8" zone "internal"`, "system update rule", "system config save"}
	if got := strings.Join(f.calls[len(f.calls)-3:], "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("wrong execution sequence: %s", got)
	}
	if _, err := e.Execute(t.Context(), "first", p.ID, true, true); err == nil {
		t.Fatal("plan replay accepted")
	}
}

func TestStaleExpiredAndWrongProfilePlans(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		e, f, _ := testEngine(t)
		p := prepareNode(t, e)
		f.outputs["node get"] += "\n2|other|192.0.2.9|internal"
		if _, err := e.Execute(t.Context(), "first", p.ID, true, false); err == nil || !strings.Contains(err.Error(), "state changed") {
			t.Fatal(err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e, _, _ := testEngine(t)
		p := prepareNode(t, e)
		e.now = func() time.Time { return p.ExpiresAt }
		if _, err := e.Execute(t.Context(), "first", p.ID, false, false); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatal(err)
		}
	})
	t.Run("profile", func(t *testing.T) {
		e, _, _ := testEngine(t)
		p := prepareNode(t, e)
		if _, err := e.Execute(t.Context(), "second", p.ID, true, false); err == nil {
			t.Fatal("cross-profile execute succeeded")
		}
		if len(e.Plans("first")) != 1 {
			t.Fatal("other profile consumed plan")
		}
	})
}

func TestDefaultReadOnlyAndPermissions(t *testing.T) {
	e, f, _ := testEngine(t)
	p := e.Config.Profiles["first"]
	p.ReadOnly = nil
	e.Config.Profiles["first"] = p
	_, err := e.Call(t.Context(), "first", "utm_node_delete", map[string]any{"id": "1"}, 0, 100)
	if err == nil || !strings.Contains(err.Error(), "read-only") || len(f.calls) != 0 {
		t.Fatalf("%v, calls %v", err, f.calls)
	}
	p.ReadOnly = new(false)
	p.AllowUnverified = false
	e.Config.Profiles["first"] = p
	if _, err := e.Call(t.Context(), "first", "utm_node_delete", map[string]any{"id": "1"}, 0, 100); err == nil {
		t.Fatal("unverified mutation allowed without permission")
	}
	if _, err := e.Call(t.Context(), "first", "utm_system_reboot", nil, 0, 100); err == nil {
		t.Fatal("lifecycle permission bypassed")
	}
	if _, err := e.Call(t.Context(), "first", "utm_cert_export_privatekey", map[string]any{"id": "1"}, 0, 100); err == nil {
		t.Fatal("sensitive export permission bypassed")
	}
}

func TestPartialAndUncertainAreNotReplayed(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		e, f, _ := testEngine(t)
		p := prepareNode(t, e)
		f.failCommand = "system update rule"
		f.started = true
		r, err := e.Execute(t.Context(), "first", p.ID, true, true)
		if err != nil || r.Status != "partial" || r.Saved || len(r.Steps) != 2 || r.Steps[1].Status != "uncertain" {
			t.Fatalf("%#v %v", r, err)
		}
		for _, cmd := range f.calls {
			if cmd == "system config save" {
				t.Fatal("saved after activation failure")
			}
		}
	})
	t.Run("uncertain", func(t *testing.T) {
		e, f, _ := testEngine(t)
		p := prepareNode(t, e)
		f.failCommand = `node new name "newhost" address "192.0.2.8" zone "internal"`
		f.started = true
		r, err := e.Execute(t.Context(), "first", p.ID, false, false)
		if err != nil || r.Status != "uncertain" {
			t.Fatalf("%#v %v", r, err)
		}
		if _, err := e.Execute(t.Context(), "first", p.ID, false, false); err == nil {
			t.Fatal("uncertain mutation replayed")
		}
	})
}

func TestSaveRequiresActivation(t *testing.T) {
	e, _, _ := testEngine(t)
	p := prepareNode(t, e)
	if _, err := e.Execute(t.Context(), "first", p.ID, false, true); err == nil {
		t.Fatal("save without activation accepted")
	}
	if len(e.Plans("first")) != 1 {
		t.Fatal("invalid choices consumed plan")
	}
}

func TestSecretsNeverAppearInPreviewOrAudit(t *testing.T) {
	e, _, logs := testEngine(t)
	for _, tt := range []struct {
		id   string
		args map[string]any
	}{
		{"utm_user_new", map[string]any{"name": "bob", "password": "VERY_SECRET", "groups": []any{"users"}}},
		{"utm_extc_value_set", map[string]any{"application": "proxy", "variable": "LOGIN_PASSWORD", "value": []any{"VERY_SECRET"}}},
		{"utm_rsa_import", map[string]any{"name": "key", "format": "HEX", "value": "VERY_SECRET"}},
	} {
		r, err := e.Call(t.Context(), "first", tt.id, tt.args, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "VERY_SECRET") || strings.Contains(logs.String(), "VERY_SECRET") {
			t.Fatalf("%s leaked: %s", tt.id, b)
		}
	}
}

func TestExportStoredOutsideToolOutput(t *testing.T) {
	e, f, _ := testEngine(t)
	p := e.Config.Profiles["first"]
	p.AllowSensitiveExports = true
	e.Config.Profiles["first"] = p
	key := "-----BEGIN PRIVATE KEY-----\nVERY_SECRET\n-----END PRIVATE KEY-----"
	f.outputs[`cert export privatekey id "1"`] = key
	r, err := e.Call(t.Context(), "first", "utm_cert_export_privatekey", map[string]any{"id": "1"}, 0, 100)
	if err != nil || r.Artifact == nil || r.Output != nil {
		t.Fatalf("%#v %v", r, err)
	}
	b, _, err := e.ReadArtifact("first", r.Artifact.ID)
	if err != nil || string(b) != key {
		t.Fatalf("%s %v", b, err)
	}
}

func TestCanceledLockWaitAndConcurrentProfiles(t *testing.T) {
	e, f, _ := testEngine(t)
	f.blockCommand = "node get"
	f.entered = make(chan struct{}, 1)
	f.release = make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = e.Call(t.Context(), "first", "utm_node_get", nil, 0, 100) })
	<-f.entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.Call(ctx, "first", "utm_node_get", nil, 0, 100); err == nil {
		t.Fatal("canceled wait continued")
	}
	if _, err := e.Call(t.Context(), "second", "utm_system_info", nil, 0, 100); err != nil {
		t.Fatal("independent profile blocked", err)
	}
	close(f.release)
	wg.Wait()
}

func TestFirmwareParsingAndVersionGate(t *testing.T) {
	if Firmware(`{"result":{"code":200,"content":[{"attribute":"version","value":"14.1.5"}]},"version":"11.6"}`) != "14.1.5" {
		t.Fatal("wire format version mistaken for firmware")
	}
	if Firmware("kernel_version|6.1.2\nfirmware_version|14.2.0\n") != "14.2.0" {
		t.Fatal("kernel version mistaken for firmware")
	}
	e, f, _ := testEngine(t)
	f.outputs["system info"] = "version|12.7.4"
	if _, err := e.Call(t.Context(), "first", "utm_node_get", nil, 0, 100); err == nil {
		t.Fatal("12.x accepted")
	}
}
