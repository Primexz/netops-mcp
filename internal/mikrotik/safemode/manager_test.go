package safemode

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/routeros"
	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

type fakeGuard struct {
	mu                 sync.Mutex
	obs                observation
	broken             bool
	commitErr          error
	onRollback         func()
	onCommit           func(context.Context) error
	commits, rollbacks atomic.Int32
	closed             atomic.Bool
}

func (g *fakeGuard) check(context.Context) (observation, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.broken || g.closed.Load() {
		return observation{}, errors.New("lost guard")
	}
	return g.obs, nil
}
func (g *fakeGuard) commit(ctx context.Context) error {
	g.commits.Add(1)
	if g.onCommit != nil {
		return g.onCommit(ctx)
	}
	return g.commitErr
}
func (g *fakeGuard) rollback(context.Context) error {
	g.rollbacks.Add(1)
	obs, err := g.check(context.Background())
	if err != nil || !obs.enabled || !obs.current {
		return errors.New("ownership lost")
	}
	if g.onRollback != nil {
		g.onRollback()
	}
	return nil
}
func (g *fakeGuard) close() { g.closed.Store(true) }

func managerFixture(t *testing.T) (*Manager, *fakeGuard) {
	t.Helper()
	g := &fakeGuard{obs: observation{enabled: true, current: true}}
	p := config.Profile{ReadOnly: new(false), SafeMode: config.SafeMode{Required: true, TimeoutSeconds: 300}}
	m := newManager(map[string]config.Profile{"main": p, "second": p}, nil, func(context.Context, config.Profile) (guard, error) { return g, nil }, time.Millisecond, 40*time.Millisecond)
	t.Cleanup(m.Close)
	return m, g
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatal("condition did not become true")
		case <-ticker.C:
		}
	}
}

func begin(t *testing.T, m *Manager) View {
	t.Helper()
	v, err := m.Begin(t.Context(), "main")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestWindowRequiresMatchingIDAndExplicitConfirmation(t *testing.T) {
	m, g := managerFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	v, err := m.Begin(ctx, "main")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Begin(t.Context(), "main"); err == nil {
		t.Fatal("duplicate begin accepted")
	}
	for _, tc := range []struct{ profile, id string }{{"main", ""}, {"main", "wrong"}, {"second", v.ID}} {
		_, _, err := m.Do(t.Context(), tc.profile, tc.id, func(context.Context, func() error) (any, error) { t.Fatal("invalid ID reached write"); return nil, nil })
		if err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	out, state, err := m.Do(t.Context(), "main", v.ID, func(_ context.Context, dispatch func() error) (any, error) { return "written", dispatch() })
	if err != nil || out != "written" || state.State != "active" || g.commits.Load() != 0 {
		t.Fatal(out, state, err)
	}
	probes := 0
	state, err = m.Confirm(t.Context(), "main", v.ID, func(context.Context) error { probes++; return nil })
	if err != nil || state.State != "committed" || probes != 1 || g.commits.Load() != 1 || g.rollbacks.Load() != 0 {
		t.Fatal(state, err)
	}
	if _, err := m.Confirm(t.Context(), "main", v.ID, func(context.Context) error { t.Fatal("replayed confirmation"); return nil }); err == nil {
		t.Fatal("stale ID accepted")
	}
	m.Close()
	if g.rollbacks.Load() != 0 {
		t.Fatal("shutdown rolled back committed changes")
	}
}

func TestPreconditionFailurePreservesWindowAndExpiryPreventsDispatch(t *testing.T) {
	m, g := managerFixture(t)
	v := begin(t, m)
	_, state, err := m.Do(t.Context(), "main", v.ID, func(context.Context, func() error) (any, error) { return nil, errors.New("dynamic record") })
	if err == nil || state.State != "active" {
		t.Fatal(state, err)
	}
	_, state, err = m.Do(t.Context(), "main", v.ID, func(_ context.Context, dispatch func() error) (any, error) {
		m.windows["main"].view.ExpiresAt = time.Now().Add(-time.Second)
		return nil, dispatch()
	})
	if err == nil || state.State != "rollback_requested" || g.rollbacks.Load() != 1 {
		t.Fatal(state, err)
	}
}

func TestFailedWriteDrainsBeforeRollbackAndCannotConfirm(t *testing.T) {
	m, g := managerFixture(t)
	v := begin(t, m)
	_, state, err := m.Do(t.Context(), "main", v.ID, func(_ context.Context, dispatch func() error) (any, error) {
		if err := dispatch(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	})
	if err == nil || state.State != "rollback_requested" || state.ReleaseAfter.IsZero() || g.rollbacks.Load() != 0 {
		t.Fatal(state, err)
	}
	if _, err := m.Confirm(t.Context(), "main", v.ID, func(context.Context) error { t.Fatal("failed window reached confirm probe"); return nil }); err == nil {
		t.Fatal("failed window confirmed")
	}
	if _, err := m.Rollback(t.Context(), "main", v.ID); err != nil {
		t.Fatal(err)
	}
	if g.rollbacks.Load() != 0 {
		t.Fatal("explicit rollback skipped REST drain")
	}
	eventually(t, func() bool { return g.closed.Load() })
	if g.rollbacks.Load() != 1 {
		t.Fatal("missing rollback after drain")
	}
}

func TestMonitoringExpiryHistoryAndOwnerLoss(t *testing.T) {
	for _, mode := range []string{"expiry", "history", "owner"} {
		t.Run(mode, func(t *testing.T) {
			m, g := managerFixture(t)
			v := begin(t, m)
			switch mode {
			case "expiry":
				w := m.windows["main"]
				_ = w.lock(t.Context())
				w.view.ExpiresAt = time.Now().Add(-time.Second)
				w.unlock()
			case "history":
				g.mu.Lock()
				g.obs.history = 80
				g.mu.Unlock()
			case "owner":
				g.mu.Lock()
				g.obs.current = false
				g.mu.Unlock()
			}
			eventually(t, func() bool { return g.closed.Load() })
			state, err := m.Status(t.Context(), "main")
			if err != nil || state.State == "active" || g.commits.Load() != 0 {
				t.Fatal(state, err)
			}
			if mode == "owner" && state.State != "uncertain" {
				t.Fatal(state)
			}
			if _, err := m.Confirm(t.Context(), "main", v.ID, func(context.Context) error { return nil }); err == nil {
				t.Fatal("terminal window confirmed")
			}
		})
	}
}

func TestConfirmationRequiresFreshRESTAndAcknowledgement(t *testing.T) {
	for _, mode := range []string{"probe", "ack"} {
		t.Run(mode, func(t *testing.T) {
			m, g := managerFixture(t)
			v := begin(t, m)
			if mode == "ack" {
				g.commitErr = errors.New("lost acknowledgement")
			}
			state, err := m.Confirm(t.Context(), "main", v.ID, func(context.Context) error {
				if mode == "probe" {
					return errors.New("disconnected")
				}
				return nil
			})
			if err == nil || state.State == "committed" {
				t.Fatal(state, err)
			}
			if mode == "probe" && g.commits.Load() != 0 {
				t.Fatal("committed without REST connectivity")
			}
			if mode == "ack" && state.State != "uncertain" {
				t.Fatal(state)
			}
		})
	}
}

func TestRollbackAndConfirmationSerializeWithWrite(t *testing.T) {
	m, g := managerFixture(t)
	v := begin(t, m)
	entered, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _, err := m.Do(t.Context(), "main", v.ID, func(_ context.Context, dispatch func() error) (any, error) {
			if err := dispatch(); err != nil {
				return nil, err
			}
			close(entered)
			<-release
			return "done", nil
		})
		if err != nil {
			t.Error(err)
		}
	})
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.Confirm(ctx, "main", v.ID, func(context.Context) error { t.Error("cancelled confirmation reached probe"); return nil }); err == nil {
		t.Fatal("cancelled wait accepted")
	}
	rollbackDone := make(chan struct{})
	wg.Go(func() {
		defer close(rollbackDone)
		_, err := m.Rollback(t.Context(), "main", v.ID)
		if err != nil {
			t.Error(err)
		}
	})
	if g.closed.Load() {
		t.Fatal("guard released with write in flight")
	}
	close(release)
	<-rollbackDone
	wg.Wait()
	if g.rollbacks.Load() != 1 || g.commits.Load() != 0 {
		t.Fatal("incorrect serialized outcome")
	}
}

func TestShutdownRetainsGuardForUncertainWrite(t *testing.T) {
	m, g := managerFixture(t)
	v := begin(t, m)
	_, state, _ := m.Do(t.Context(), "main", v.ID, func(_ context.Context, dispatch func() error) (any, error) {
		if err := dispatch(); err != nil {
			return nil, err
		}
		return nil, errors.New("lost response")
	})
	m.Close()
	if time.Now().Before(state.ReleaseAfter) || g.rollbacks.Load() != 1 {
		t.Fatal("shutdown released before possible late REST completion")
	}
	if _, err := m.Begin(t.Context(), "main"); err == nil {
		t.Fatal("closed manager accepted begin")
	}
}

func TestLateRESTCompletionRemainsInsideRollbackWindow(t *testing.T) {
	entered, finishLate, lateDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var changed atomic.Bool
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(finishLate) }) })
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-finishLate // Model RouterOS continuing work after client cancellation.
		changed.Store(true)
		close(lateDone)
		_, _ = io.WriteString(w, `{".id":"*A"}`)
	})
	c, err := routeros.New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, g := managerFixture(t)
	m.drain = 200 * time.Millisecond
	g.onRollback = func() { changed.Store(false) }
	v := begin(t, m)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := m.Do(ctx, "main", v.ID, func(ctx context.Context, dispatch func() error) (any, error) {
			if err := dispatch(); err != nil {
				return nil, err
			}
			return c.Request(ctx, "PATCH", "ip/address", "*A", nil, map[string]any{"comment": "late"})
		})
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled write succeeded")
	}
	if g.closed.Load() {
		t.Fatal("guard released before remote write completed")
	}
	release.Do(func() { close(finishLate) })
	<-lateDone
	eventually(t, func() bool { return g.closed.Load() })
	if changed.Load() {
		t.Fatal("late mutation escaped rollback")
	}
}

func TestConfirmationControlCannotOutliveDeadline(t *testing.T) {
	m, g := managerFixture(t)
	g.onCommit = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	v := begin(t, m)
	w := m.windows["main"]
	_ = w.lock(t.Context())
	w.view.ExpiresAt = time.Now().Add(20 * time.Millisecond)
	w.unlock()
	state, err := m.Confirm(t.Context(), "main", v.ID, func(context.Context) error { return nil })
	if err == nil || state.State != "uncertain" || !g.closed.Load() {
		t.Fatal(state, err)
	}
}

func TestConfirmationProbeCannotHoldExpiredWindow(t *testing.T) {
	m, g := managerFixture(t)
	v := begin(t, m)
	w := m.windows["main"]
	_ = w.lock(t.Context())
	w.view.ExpiresAt = time.Now().Add(20 * time.Millisecond)
	w.unlock()
	state, err := m.Confirm(t.Context(), "main", v.ID, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if err == nil || state.State != "rollback_requested" || g.commits.Load() != 0 || !g.closed.Load() {
		t.Fatal(state, err)
	}
}

func TestHistoryLimitAroundMutation(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			m, g := managerFixture(t)
			v := begin(t, m)
			if phase == "before" {
				g.mu.Lock()
				g.obs.history = 80
				g.mu.Unlock()
			}
			sent := false
			_, state, err := m.Do(t.Context(), "main", v.ID, func(_ context.Context, dispatch func() error) (any, error) {
				if err := dispatch(); err != nil {
					return nil, err
				}
				sent = true
				g.mu.Lock()
				g.obs.history = 80
				g.mu.Unlock()
				return "written", nil
			})
			if err == nil || state.State != "rollback_requested" || sent != (phase == "after") || g.rollbacks.Load() != 1 || g.commits.Load() != 0 {
				t.Fatal(state, err)
			}
		})
	}
}

func TestReadOnlyAndUnconfiguredBeginStayOffline(t *testing.T) {
	p := config.Profile{ReadOnly: new(true), SafeMode: config.SafeMode{Required: true, TimeoutSeconds: 300}}
	m := newManager(map[string]config.Profile{"main": p}, nil, func(context.Context, config.Profile) (guard, error) {
		t.Error("denied begin contacted SSH")
		return nil, errors.New("unexpected dial")
	}, time.Hour, time.Millisecond)
	defer m.Close()
	for _, profile := range []string{"main", "unknown"} {
		if _, err := m.Begin(t.Context(), profile); err == nil {
			t.Fatal("denied profile acquired safe mode")
		}
	}
}
