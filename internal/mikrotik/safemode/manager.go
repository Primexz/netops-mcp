package safemode

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
)

const (
	historyLimit = 80
	// RouterOS continues a REST command after its HTTP client gives up, for up
	// to 60 seconds. Keep the owner alive for that bound plus a small margin.
	requestDrain = 65 * time.Second
)

// View describes local knowledge, not a claim that RouterOS has undone changes.
type View struct {
	Profile        string    `json:"profile"`
	ID             string    `json:"safe_mode_id,omitempty"`
	State          string    `json:"state"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	ReleaseAfter   time.Time `json:"release_after,omitzero"`
	HistoryActions int       `json:"history_actions"`
	Reason         string    `json:"reason,omitempty"`
}

// Error preserves the state alongside a sanitized failure, including when a
// write may already have applied and a rollback is waiting for it to finish.
type Error struct {
	Message string
	View    View
}

func (e *Error) Error() string { return e.Message }

type window struct {
	gate    chan struct{}
	profile config.Profile
	view    View
	guard   guard
}

func (w *window) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case w.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *window) unlock() { <-w.gate }

// Manager serializes protected writes and control calls per profile. Its worker
// lifetime is owned by Close, independently of individual MCP requests.
type Manager struct {
	windows  map[string]*window
	logger   *slog.Logger
	dial     func(context.Context, config.Profile) (guard, error)
	now      func() time.Time
	interval time.Duration
	drain    time.Duration
	closed   atomic.Bool
	stop     chan struct{}
	wg       sync.WaitGroup
}

func New(profiles map[string]config.Profile, logger *slog.Logger) *Manager {
	return newManager(profiles, logger, connect, 5*time.Second, requestDrain)
}

func newManager(profiles map[string]config.Profile, logger *slog.Logger, dial func(context.Context, config.Profile) (guard, error), interval, drain time.Duration) *Manager {
	m := &Manager{windows: map[string]*window{}, logger: logger, dial: dial, now: time.Now, interval: interval, drain: drain, stop: make(chan struct{})}
	for name, p := range profiles {
		if !p.SafeMode.Required {
			continue
		}
		w := &window{gate: make(chan struct{}, 1), profile: p, view: View{Profile: name, State: "inactive"}}
		m.windows[name] = w
		m.wg.Go(func() { m.watch(w) })
	}
	return m
}

func (m *Manager) window(profile string) (*window, error) {
	if m.closed.Load() {
		return nil, errors.New("safe-mode manager is shutting down")
	}
	w, ok := m.windows[profile]
	if !ok {
		return nil, errors.New("safe mode is not configured as required for this profile")
	}
	return w, nil
}

func (m *Manager) Begin(ctx context.Context, profile string) (View, error) {
	w, err := m.window(profile)
	if err != nil {
		return View{}, err
	}
	if w.profile.IsReadOnly() {
		return View{}, errors.New("profile is read-only; safe-mode changes require read_only=false")
	}
	if err := w.lock(ctx); err != nil {
		return View{}, err
	}
	defer w.unlock()
	if m.closed.Load() {
		return w.view, errors.New("safe-mode manager is shutting down")
	}
	if w.guard != nil {
		return w.view, m.failure(w, "a safe-mode window already exists; inspect its status")
	}
	g, err := m.dial(ctx, w.profile)
	if err != nil {
		return w.view, err
	}
	w.guard = g
	w.view = View{Profile: profile, ID: rand.Text(), State: "active", ExpiresAt: m.now().Add(time.Duration(w.profile.SafeMode.TimeoutSeconds) * time.Second).UTC()}
	if m.closed.Load() || ctx.Err() != nil {
		m.requestRollback(w, "begin was cancelled", time.Time{})
		return w.view, m.failure(w, "safe-mode begin cancelled; rollback requested")
	}
	m.audit(w)
	return w.view, nil
}

func (m *Manager) Status(ctx context.Context, profile string) (View, error) {
	w, err := m.window(profile)
	if err != nil {
		return View{}, err
	}
	if err := w.lock(ctx); err != nil {
		return View{}, err
	}
	defer w.unlock()
	m.maintain(w)
	return w.view, nil
}

// Do holds the window through preconditions, the REST write, and the post-check.
// The callback marks dispatch immediately before the actual mutation request;
// failed local validation/precondition reads do not consume a healthy window.
func (m *Manager) Do(ctx context.Context, profile, id string, call func(context.Context, func() error) (any, error)) (any, View, error) {
	w, err := m.window(profile)
	if err != nil {
		return nil, View{}, err
	}
	if err := w.lock(ctx); err != nil {
		return nil, View{}, err
	}
	defer w.unlock()
	if err := m.active(w, id); err != nil {
		return nil, w.view, err
	}
	if err := m.check(w); err != nil {
		m.requestRollback(w, "safe-mode ownership or history capacity lost", time.Time{})
		return nil, w.view, m.failure(w, "safe-mode protection unavailable; mutation refused")
	}
	var sent time.Time
	callCtx, cancel := context.WithDeadline(ctx, minTime(w.view.ExpiresAt, m.now().Add(60*time.Second)))
	defer cancel()
	out, err := call(callCtx, func() error {
		if err := callCtx.Err(); err != nil {
			return err
		}
		if err := m.active(w, id); err != nil {
			return err
		}
		if err := m.check(w); err != nil {
			m.requestRollback(w, "dispatch protection check failed", time.Time{})
			return m.failure(w, "safe-mode protection unavailable; mutation refused")
		}
		if err := m.active(w, id); err != nil {
			return err
		}
		sent = m.now()
		return nil
	})
	if sent.IsZero() {
		if !m.now().Before(w.view.ExpiresAt) {
			m.requestRollback(w, "confirmation deadline expired during preconditions", time.Time{})
		}
		return out, w.view, err
	}
	if err != nil {
		// Count the drain from the failure observation, conservatively covering
		// time a request might have spent queued on RouterOS before executing.
		m.requestRollback(w, "a REST write failed; check router state before any retry", m.now().Add(m.drain))
		return nil, w.view, m.failure(w, "REST write failed; safe-mode rollback requested, mutation outcome may be unknown")
	}
	if m.closed.Load() || ctx.Err() != nil || !m.now().Before(w.view.ExpiresAt) {
		m.requestRollback(w, "window expired or request/server stopped after a write", time.Time{})
		return nil, w.view, m.failure(w, "safe-mode rollback requested after write; inspect status")
	}
	if err := m.check(w); err != nil {
		m.requestRollback(w, "safe-mode post-write protection check failed", time.Time{})
		return nil, w.view, m.failure(w, "write may have applied; safe-mode protection could not be verified")
	}
	return out, w.view, nil
}

func (m *Manager) Confirm(ctx context.Context, profile, id string, probe func(context.Context) error) (View, error) {
	w, err := m.window(profile)
	if err != nil {
		return View{}, err
	}
	if err := w.lock(ctx); err != nil {
		return View{}, err
	}
	defer w.unlock()
	if err := m.active(w, id); err != nil {
		return w.view, err
	}
	if err := m.check(w); err != nil {
		m.requestRollback(w, "confirmation protection check failed", time.Time{})
		return w.view, m.failure(w, "safe-mode confirmation refused; protection unavailable")
	}
	probeCtx, cancelProbe := context.WithDeadline(ctx, minTime(w.view.ExpiresAt, m.now().Add(controlTimeout)))
	defer cancelProbe()
	if err := probe(probeCtx); err != nil {
		m.requestRollback(w, "confirmation REST connectivity check failed", time.Time{})
		return w.view, m.failure(w, "fresh REST connectivity check failed; rollback requested")
	}
	if err := ctx.Err(); err != nil {
		return w.view, err
	}
	if err := m.active(w, id); err != nil {
		return w.view, err
	}
	control, cancel := context.WithDeadline(ctx, minTime(w.view.ExpiresAt, m.now().Add(controlTimeout)))
	defer cancel()
	err = w.guard.commit(control)
	w.guard.close()
	w.guard = nil
	if err != nil {
		w.view.State, w.view.Reason = "uncertain", "confirmation was not acknowledged; check router state"
		m.audit(w)
		return w.view, m.failure(w, w.view.Reason)
	}
	w.view.State, w.view.Reason = "committed", "changes explicitly confirmed"
	m.audit(w)
	return w.view, nil
}

func (m *Manager) Rollback(ctx context.Context, profile, id string) (View, error) {
	w, err := m.window(profile)
	if err != nil {
		return View{}, err
	}
	if err := w.lock(ctx); err != nil {
		return View{}, err
	}
	defer w.unlock()
	if id == "" || id != w.view.ID {
		return w.view, m.failure(w, "unknown safe-mode session ID for this profile")
	}
	if w.view.State == "rollback_requested" {
		m.maintain(w)
		return w.view, nil
	}
	if err := m.active(w, id); err != nil {
		return w.view, err
	}
	m.requestRollback(w, "rollback explicitly requested", time.Time{})
	return w.view, nil
}

func (m *Manager) active(w *window, id string) error {
	if m.closed.Load() || id == "" || id != w.view.ID || w.guard == nil || w.view.State != "active" {
		return m.failure(w, "an active matching safe_mode_id is required before writing or confirming")
	}
	if !m.now().Before(w.view.ExpiresAt) {
		m.requestRollback(w, "confirmation deadline expired", time.Time{})
		return m.failure(w, "safe-mode window expired; rollback requested")
	}
	return nil
}

func (m *Manager) check(w *window) error {
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	obs, err := w.guard.check(ctx)
	if err != nil {
		return err
	}
	w.view.HistoryActions = obs.history
	if !obs.enabled || !obs.current || obs.history >= historyLimit {
		return errors.New("safe-mode ownership or history capacity unavailable")
	}
	return nil
}

func (m *Manager) requestRollback(w *window, reason string, releaseAfter time.Time) {
	w.view.State, w.view.Reason = "rollback_requested", reason
	w.view.ReleaseAfter = releaseAfter.UTC()
	m.audit(w)
	if !m.now().Before(releaseAfter) {
		m.release(w)
	}
}

func (m *Manager) release(w *window) {
	if w.guard == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	err := w.guard.rollback(ctx)
	w.guard.close()
	w.guard = nil
	if err != nil {
		w.view.State, w.view.Reason = "uncertain", "owner session lost or rollback unacknowledged; recovery may be delayed; inspect router state"
	}
	m.audit(w)
}

func (m *Manager) maintain(w *window) {
	if w.guard == nil {
		return
	}
	if w.view.State == "active" && !m.now().Before(w.view.ExpiresAt) {
		m.requestRollback(w, "confirmation deadline expired", time.Time{})
		return
	}
	if (w.view.State == "rollback_requested" || w.view.State == "uncertain") && !m.now().Before(w.view.ReleaseAfter) {
		m.release(w)
		return
	}
	if err := m.check(w); err != nil {
		if (w.view.State == "rollback_requested" || w.view.State == "uncertain") && m.now().Before(w.view.ReleaseAfter) {
			// Do not intentionally release a guard early while a REST request
			// may still execute. A lost owner nevertheless makes recovery uncertain.
			w.view.State, w.view.Reason = "uncertain", "guard monitoring failed while a REST write may still be running"
			m.audit(w)
			return
		}
		m.requestRollback(w, "safe-mode monitoring failed", time.Time{})
	}
}

func (m *Manager) watch(w *window) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			_ = w.lock(context.Background())
			if w.guard != nil {
				if delay := time.Until(w.view.ReleaseAfter); delay > 0 {
					// Only shutdown waits here. Normal calls return the pending
					// state while the worker retains the guard for late writes.
					timer := time.NewTimer(delay)
					<-timer.C
				}
				m.requestRollback(w, "server shutting down", time.Time{})
			}
			w.unlock()
			return
		case <-ticker.C:
			select {
			case w.gate <- struct{}{}:
				m.maintain(w)
				w.unlock()
			default: // An in-flight call owns monitoring until its post-check.
			}
		}
	}
}

func (m *Manager) Close() {
	if m.closed.CompareAndSwap(false, true) {
		close(m.stop)
	}
	m.wg.Wait()
}

func (m *Manager) failure(w *window, message string) error {
	return &Error{Message: message, View: w.view}
}

func (m *Manager) audit(w *window) {
	if m.logger != nil {
		m.logger.Info("safe mode", "profile", w.view.Profile, "state", w.view.State, "reason", w.view.Reason)
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
