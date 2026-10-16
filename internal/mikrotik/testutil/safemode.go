package testutil

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
)

// SafeRouter is a synthetic appliance sharing configuration between local SSH
// and HTTPS servers. It tests framing/lifetimes, not real firmware compatibility.
type SafeRouter struct {
	Profile       config.Profile
	History       atomic.Int32
	Occupied      atomic.Bool
	HijackOnTake  atomic.Bool
	Unsupported   atomic.Bool
	DropOnCommit  atomic.Bool
	FailProbe     atomic.Bool
	Writes        atomic.Int32
	Commits       atomic.Int32
	Rollbacks     atomic.Int32
	mu            sync.Mutex
	value, backup string
	owner         int64
	connections   map[*ssh.ServerConn]bool
}

func NewSafeRouter(t testing.TB) *SafeRouter {
	t.Helper()
	f := &SafeRouter{value: "original", connections: map[*ssh.ServerConn]bool{}}
	_, f.Profile = Router(t, f.serveHTTP)
	f.Profile.SafeMode = config.SafeMode{Required: true, TimeoutSeconds: 300}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if meta.User() != f.Profile.Username || string(pass) != "fixture-password" {
			return nil, fmt.Errorf("bad credentials")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.Profile.SafeMode.SSHPort = l.Addr().(*net.TCPAddr).Port
	f.Profile.SafeMode.KnownHosts = filepath.Join(t.TempDir(), "known_hosts")
	address := net.JoinHostPort(f.Profile.Host, strconv.Itoa(f.Profile.SafeMode.SSHPort))
	if err := os.WriteFile(f.Profile.SafeMode.KnownHosts, []byte(knownhosts.Line([]string{address}, signer.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var next atomic.Int64
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer func() { _ = sc.Close() }()
				f.mu.Lock()
				f.connections[sc] = true
				f.mu.Unlock()
				defer func() { f.mu.Lock(); delete(f.connections, sc); f.mu.Unlock() }()
				go ssh.DiscardRequests(reqs)
				id := next.Add(1)
				defer f.undo(id)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						_ = ch.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					stream, requests, err := ch.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range requests {
							_ = req.Reply(req.Type == "shell", nil)
						}
					}()
					f.shell(stream, id)
					_ = stream.Close()
				}
			})
		}
	})
	t.Cleanup(func() { _ = l.Close(); f.DropSSH(); wg.Wait() })
	return f
}

func (f *SafeRouter) DropSSH() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for conn := range f.connections {
		_ = conn.Close()
	}
}

func (f *SafeRouter) Value() string { f.mu.Lock(); defer f.mu.Unlock(); return f.value }

func (f *SafeRouter) undo(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.owner == id {
		f.value = f.backup
		f.owner = 0
		f.History.Store(0)
		f.Rollbacks.Add(1)
	}
}

var modeNonce = regexp.MustCompile(`:put \("([A-Za-z0-9]+):"`)

func (f *SafeRouter) shell(stream ssh.Channel, id int64) {
	r := bufio.NewReader(stream)
	var command strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		switch b {
		case 0x18:
			f.mu.Lock()
			if f.owner == id {
				f.owner = 0
				f.Commits.Add(1)
				f.mu.Unlock()
				if f.DropOnCommit.Load() {
					return
				}
				_, _ = io.WriteString(stream, "\r\n[Safe Mode released]\r\n")
			} else if f.owner != 0 || f.Occupied.Load() || f.HijackOnTake.Load() {
				f.mu.Unlock()
				_, _ = io.WriteString(stream, "\r\nHijacking Safe Mode from someone - unroll/release/don't take it [u/r/d]: ")
			} else {
				f.owner = id
				f.backup = f.value
				f.History.Store(0)
				f.mu.Unlock()
				_, _ = io.WriteString(stream, "\r\n[Safe Mode taken]\r\n")
			}
		case 0x04:
			f.undo(id)
			return
		case '\r', '\n':
			text := command.String()
			command.Reset()
			if f.Unsupported.Load() {
				_ = stream.Close()
				return
			}
			match := modeNonce.FindStringSubmatch(text)
			if match == nil {
				_ = stream.Close()
				return
			}
			f.mu.Lock()
			enabled := f.owner != 0 || f.Occupied.Load()
			current := f.owner == id
			f.mu.Unlock()
			// Split and color the response to exercise incremental console parsing.
			_, _ = io.WriteString(stream, "\r\n\x1b[32m"+match[1]+":")
			_, _ = fmt.Fprintf(stream, "%t:%t:%d\x1b[0m\r\n", enabled, current, f.History.Load())
		default:
			command.WriteByte(b)
			if command.Len() > 4096 {
				return
			}
		}
	}
}

func (f *SafeRouter) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if f.FailProbe.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{".id":"*A","dynamic":"false","version":"7.26","name":"fixture"}`)
		return
	}
	f.Writes.Add(1)
	f.mu.Lock()
	f.value = "changed"
	f.mu.Unlock()
	f.History.Add(1)
	_, _ = io.WriteString(w, `{".id":"*A"}`)
}
