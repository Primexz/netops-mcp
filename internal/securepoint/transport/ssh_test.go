package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/Primexz/netops-mcp/internal/securepoint/config"
)

// This verifies real SSH framing/authentication/host-key checks against a local
// protocol fixture. It deliberately makes no claim about Securepoint firmware.
func sshFixture(t *testing.T) (config.Profile, <-chan string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) != "testpass" {
			return nil, fmt.Errorf("bad credentials")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	commands := make(chan string, 20)
	var wg sync.WaitGroup
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
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						_ = ch.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							_ = request.Reply(false, nil)
							continue
						}
						var payload struct{ Command string }
						if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
							return
						}
						commands <- payload.Command
						_ = request.Reply(true, nil)
						switch payload.Command {
						case "spcli":
							input, _ := io.ReadAll(channel)
							if !strings.HasPrefix(string(input), "cli json\n") {
								t.Error("JSON mode did not configure a local CLI session")
							}
							_, _ = io.WriteString(channel, `{"result":{"code":200,"status":"OK","content":[{"application":"sshd"}]}}`)
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{255}))
							_ = channel.Close()
							continue
						case "slow":
							time.Sleep(100 * time.Millisecond)
						case "large":
							_, _ = io.WriteString(channel, strings.Repeat("x", 8192))
						case "bad":
							_, _ = io.WriteString(channel, "ERROR: invalid argument\n")
						default:
							_, _ = io.WriteString(channel, "id|name\n--+----\n1|fixture\n")
						}
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = channel.Close()
					}
				}
			})
		}
	})
	port := l.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", fmt.Sprint(port))}, signer.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECUREPOINT_TEST_PASSWORD", "testpass")
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	return config.Profile{Host: "127.0.0.1", Port: port, Username: "admin", PasswordEnv: "SECUREPOINT_TEST_PASSWORD", KnownHosts: kh, TimeoutSeconds: 2, MaxOutputBytes: 4096}, commands
}

func TestSSHExecAndHostIdentity(t *testing.T) {
	p, commands := sshFixture(t)
	r, err := (SSH{}).Run(t.Context(), p, Request{Command: "node get"})
	if err != nil || !strings.Contains(r.Output, "fixture") || <-commands != "node get" {
		t.Fatalf("%#v %v", r, err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(other)
	if err := os.WriteFile(p.KnownHosts, []byte(knownhosts.Line([]string{p.Address()}, signer.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (SSH{}).Run(t.Context(), p, Request{Command: "node get"}); err == nil {
		t.Fatal("mismatched host key was accepted")
	}
}

func TestSSHOutputLimitCancellationAndCLIErrors(t *testing.T) {
	p, _ := sshFixture(t)
	r, err := (SSH{}).Run(t.Context(), p, Request{Command: "large"})
	if err == nil || !r.Started || len(r.Output) > p.MaxOutputBytes {
		t.Fatalf("limit %#v %v", r, err)
	}
	if _, err := (SSH{}).Run(t.Context(), p, Request{Command: "bad"}); err == nil {
		t.Fatal("exit-zero CLI error was accepted")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if _, err := (SSH{}).Run(ctx, p, Request{Command: "slow"}); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestRootCLIRequotesShellMetacharacters(t *testing.T) {
	p, commands := sshFixture(t)
	p.RootCLI = true
	_, err := (SSH{}).Run(t.Context(), p, Request{Command: `node new name "$(touch /tmp/never)" address "192.0.2.1" zone "internal"`})
	if err != nil {
		t.Fatal(err)
	}
	command := <-commands
	if !strings.HasPrefix(command, "spcli ") || !strings.Contains(command, `'$(touch /tmp/never)'`) {
		t.Fatalf("unquoted root command %s", command)
	}
}

func TestJSONSessionUsesProtocolStatus(t *testing.T) {
	p, commands := sshFixture(t)
	p.RootCLI = true
	p.JSONOutput = true
	r, err := (SSH{}).Run(t.Context(), p, Request{Command: "extc application get"})
	if err != nil || !strings.Contains(r.Output, `"code":200`) || <-commands != "spcli" {
		t.Fatalf("%#v %v", r, err)
	}
}
