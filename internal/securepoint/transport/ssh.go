// Package transport executes bounded, non-interactive SSH requests. Each request
// owns a fresh connection; an uncertain mutation is never transparently replayed.
package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/Primexz/netops-mcp/internal/securepoint/cli"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
)

type Request struct {
	Command string
	Input   []byte
	Shell   bool
}

type Result struct {
	Output string
	// Started is true once SSH may have accepted an execution request. An error
	// from that point onward can leave an operation's outcome uncertain.
	Started bool
}

type Runner interface {
	Run(context.Context, config.Profile, Request) (Result, error)
}

type SSH struct{}

func (SSH) Run(ctx context.Context, p config.Profile, req Request) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout())
	defer cancel()
	client, cleanup, err := Connect(ctx, p)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	session, err := client.NewSession()
	if err != nil {
		return Result{}, errors.New("could not create SSH session")
	}
	defer func() { _ = session.Close() }()
	command := req.Command
	input := req.Input
	if req.Shell {
		if !p.RootCLI {
			return Result{}, errors.New("diagnostic requires a root_cli profile")
		}
	} else if p.RootCLI && p.JSONOutput {
		// Output mode belongs to this short-lived CLI session. No appliance
		// configuration is changed. Sending a single encoded command on stdin
		// also preserves the CLI's own quoting for nested values and spaces.
		command = "spcli"
		input = append([]byte("cli json\n"+req.Command+"\n"), req.Input...)
	} else if p.RootCLI {
		// spcli accepts the command as arguments, as documented for SSH/root.
		// Quote every word again for the login shell; CLI escaping alone is not
		// shell escaping and must never be used as such.
		words, err := cli.Words(command)
		if err != nil {
			return Result{}, err
		}
		quoted := make([]string, 0, len(words))
		for _, w := range words {
			quoted = append(quoted, cli.ShellQuote(w))
		}
		command = "spcli " + strings.Join(quoted, " ")
	}
	out := &limitedBuffer{limit: p.MaxOutputBytes}
	session.Stdout, session.Stderr = out, out
	if len(input) > 0 {
		session.Stdin = bytes.NewReader(input)
	}
	result := Result{Started: true}
	err = session.Run(command)
	result.Output = out.String()
	if out.Exceeded() {
		return result, errors.New("remote output exceeded max_output_bytes; outcome may be uncertain")
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("SSH request interrupted: %w", ctx.Err())
	}
	if err != nil {
		if exit, ok := errors.AsType[*ssh.ExitError](err); ok && exit.ExitStatus() == 255 && cli.SuccessEnvelope(result.Output) {
			return result, nil
		}
		return result, errors.New("SSH command failed; inspect the sanitized step output")
	}
	if cli.IsError(result.Output) {
		return result, errors.New("appliance rejected the CLI command")
	}
	return result, nil
}

// Connect verifies the appliance identity and closes both SSH and agent sockets
// on cancellation, including during the handshake and authentication exchange.
func Connect(ctx context.Context, p config.Profile) (*ssh.Client, func(), error) {
	verify, err := knownhosts.New(p.KnownHosts)
	if err != nil {
		return nil, nil, errors.New("cannot read configured known_hosts file")
	}
	var methods []ssh.AuthMethod
	var agentConn net.Conn
	if p.PasswordEnv != "" {
		password, ok := os.LookupEnv(p.PasswordEnv)
		if !ok || password == "" {
			return nil, nil, fmt.Errorf("password environment variable %s is not set", p.PasswordEnv)
		}
		methods = append(methods, ssh.Password(password))
	}
	if p.KeyFile != "" {
		key, err := os.ReadFile(p.KeyFile)
		if err != nil {
			return nil, nil, errors.New("cannot read SSH private key")
		}
		var signer ssh.Signer
		if p.KeyPassphraseEnv != "" {
			pass, ok := os.LookupEnv(p.KeyPassphraseEnv)
			if !ok {
				return nil, nil, errors.New("SSH key passphrase environment variable is not set")
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(pass))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return nil, nil, errors.New("cannot parse SSH private key")
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if p.SSHAgent {
		var d net.Dialer
		agentConn, err = d.DialContext(ctx, "unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, nil, errors.New("cannot connect to SSH agent")
		}
		methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
	}
	closeAgent := func() {
		if agentConn != nil {
			_ = agentConn.Close()
		}
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", p.Address())
	if err != nil {
		closeAgent()
		return nil, nil, fmt.Errorf("cannot connect to appliance: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); closeAgent() })
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	cc, channels, requests, err := ssh.NewClientConn(conn, p.Address(), &ssh.ClientConfig{User: p.Username, Auth: methods, HostKeyCallback: verify, Timeout: p.Timeout()})
	if err != nil {
		stop()
		_ = conn.Close()
		closeAgent()
		return nil, nil, errors.New("SSH handshake/authentication failed (check credentials, host key and appliance access policy)")
	}
	client := ssh.NewClient(cc, channels, requests)
	return client, func() { stop(); _ = client.Close(); closeAgent() }, nil
}

type limitedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if n > b.limit-b.buffer.Len() {
		_, _ = b.buffer.Write(p[:max(0, b.limit-b.buffer.Len())])
		b.exceeded = true
		return n, nil // Keep draining SSH so a verbose process cannot deadlock.
	}
	_, err := b.buffer.Write(p)
	return n, err
}
func (b *limitedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }
func (b *limitedBuffer) Exceeded() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.exceeded }

var _ io.Writer = (*limitedBuffer)(nil)
