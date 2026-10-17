package safemode

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/Primexz/netops-mcp/internal/mikrotik/routeros"
	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

func TestConsoleGuardsRESTChanges(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(strconv.FormatBool(commit), func(t *testing.T) {
			f := testutil.NewSafeRouter(t)
			ctx, cancel := context.WithCancel(t.Context())
			g, err := connect(ctx, f.Profile)
			if err != nil {
				t.Fatal(err)
			}
			defer g.close()
			cancel() // The guard must survive completion of the begin request.
			c, err := routeros.New(f.Profile)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Request(t.Context(), "PATCH", "ip/address", "*A", nil, map[string]any{"comment": "changed"}); err != nil {
				t.Fatal(err)
			}
			obs, err := g.check(t.Context())
			if err != nil || !obs.current || !obs.enabled || obs.history != 1 || f.Value() != "changed" {
				t.Fatal(obs, err)
			}
			if commit {
				if err := g.commit(t.Context()); err != nil {
					t.Fatal(err)
				}
				g.close()
				if f.Value() != "changed" || f.Commits.Load() != 1 || f.Rollbacks.Load() != 0 {
					t.Fatal("commit did not retain REST change")
				}
			} else {
				if err := g.rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
				g.close()
				eventually(t, func() bool { return f.Value() == "original" })
				if f.Commits.Load() != 0 {
					t.Fatal("rollback committed changes")
				}
			}
		})
	}
}

func TestConsoleDisablesTerminalDetection(t *testing.T) {
	f := testutil.NewSafeRouter(t)
	f.RequireTerminalOptions.Store(true)
	g, err := connect(t.Context(), f.Profile)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	if err := g.rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.Commits.Load() != 0 {
		t.Fatal("terminal negotiation committed changes")
	}
}

func TestConsoleRequiresInteractiveTerminal(t *testing.T) {
	f := testutil.NewSafeRouter(t)
	f.RequireInteractive.Store(true)
	g, err := connect(t.Context(), f.Profile)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	if err := g.rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleAcceptsModernAcknowledgements(t *testing.T) {
	f := testutil.NewSafeRouter(t)
	f.ModernAcknowledgements.Store(true)
	g, err := connect(t.Context(), f.Profile)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	obs, err := g.check(t.Context())
	if err != nil || !obs.current || !obs.enabled {
		t.Fatal("safe-mode ownership not confirmed", obs, err)
	}
	if err := g.commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.Commits.Load() != 1 {
		t.Fatal("safe mode was not explicitly committed")
	}
}

func TestConsoleRefusesUnavailableTerminal(t *testing.T) {
	for _, mode := range []string{"PTY request refused", "console prompt not received"} {
		t.Run(mode, func(t *testing.T) {
			f := testutil.NewSafeRouter(t)
			f.RejectPTY.Store(mode == "PTY request refused")
			f.NoPrompt.Store(mode == "console prompt not received")
			g, err := connect(t.Context(), f.Profile)
			if g != nil {
				g.close()
			}
			if err == nil || !strings.Contains(err.Error(), mode) {
				t.Fatalf("error = %v, want %q", err, mode)
			}
			if f.Writes.Load() != 0 || f.Commits.Load() != 0 || f.Rollbacks.Load() != 0 {
				t.Fatal("failed terminal setup changed router state")
			}
		})
	}
}

func TestConsoleRefusesOccupiedUnsupportedAndUntrustedRouter(t *testing.T) {
	for _, mode := range []string{"occupied", "takeover race", "unsupported", "unknown key", "changed key", "missing password"} {
		t.Run(mode, func(t *testing.T) {
			f := testutil.NewSafeRouter(t)
			switch mode {
			case "occupied":
				f.Occupied.Store(true)
			case "takeover race":
				f.HijackOnTake.Store(true)
			case "unsupported":
				f.Unsupported.Store(true)
			case "unknown key":
				if err := os.WriteFile(f.Profile.SafeMode.KnownHosts, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "changed key":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := ssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				address := net.JoinHostPort(f.Profile.Host, strconv.Itoa(f.Profile.SafeMode.SSHPort))
				if err := os.WriteFile(f.Profile.SafeMode.KnownHosts, []byte(knownhosts.Line([]string{address}, signer.PublicKey())+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing password":
				t.Setenv(f.Profile.PasswordEnv, "")
			}
			g, err := connect(t.Context(), f.Profile)
			if g != nil {
				g.close()
			}
			if err == nil || strings.Contains(err.Error(), "fixture-password") {
				t.Fatal("unsafe connection accepted", err)
			}
			if f.Commits.Load() != 0 || f.Rollbacks.Load() != 0 {
				t.Fatal("touched another session")
			}
		})
	}
}

func TestConsoleLostOwnerAndLostCommitAcknowledgement(t *testing.T) {
	for _, mode := range []string{"disconnect", "commit ack"} {
		t.Run(mode, func(t *testing.T) {
			f := testutil.NewSafeRouter(t)
			g, err := connect(t.Context(), f.Profile)
			if err != nil {
				t.Fatal(err)
			}
			defer g.close()
			if mode == "disconnect" {
				f.DropSSH()
				if _, err := g.check(t.Context()); err == nil {
					t.Fatal("disconnected owner considered healthy")
				}
			} else {
				f.DropOnCommit.Store(true)
				if err := g.commit(t.Context()); err == nil {
					t.Fatal("missing commit acknowledgement accepted")
				}
				if f.Commits.Load() != 1 {
					t.Fatal("fixture did not simulate uncertain applied commit")
				}
			}
		})
	}
}
