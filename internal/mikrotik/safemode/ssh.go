// Package safemode owns persistent RouterOS console sessions that guard REST writes.
package safemode

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
)

const controlTimeout = 5 * time.Second

type observation struct {
	enabled, current bool
	history          int
}

// A guard never accepts user commands or configuration parameters.
type guard interface {
	check(context.Context) (observation, error)
	commit(context.Context) error
	rollback(context.Context) error
	close()
}

type console struct {
	client *ssh.Client
	input  io.WriteCloser
	chunks chan []byte
	done   chan struct{}
	once   sync.Once
}

// connect uses a bounded establishment context only. An acquired guard lives
// beyond the MCP request, until explicit confirmation, rollback, or shutdown.
func connect(ctx context.Context, p config.Profile) (guard, error) {
	verify, err := knownhosts.New(p.SafeMode.KnownHosts)
	if err != nil {
		return nil, errors.New("cannot read safe-mode known_hosts file")
	}
	password := os.Getenv(p.PasswordEnv)
	if password == "" {
		return nil, errors.New("profile password environment variable is missing or empty")
	}
	address := net.JoinHostPort(p.Host, strconv.Itoa(p.SafeMode.SSHPort))
	ctx, cancel := context.WithTimeout(ctx, p.Timeout())
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("safe-mode SSH connection failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	cc, channels, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		// RouterOS login options disable colors and terminal detection for this
		// automated console. The account and REST username remain unchanged.
		User: p.Username + "+ct", Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: verify,
	})
	if err != nil {
		_ = conn.Close()
		return nil, errors.New("safe-mode SSH authentication or host-key verification failed")
	}
	c := &console{client: ssh.NewClient(cc, channels, requests), chunks: make(chan []byte, 8), done: make(chan struct{})}
	session, err := c.client.NewSession()
	if err != nil {
		c.close()
		return nil, errors.New("cannot open safe-mode SSH session")
	}
	// Ctrl+X and Ctrl+D must reach the interactive console. A shell without a
	// PTY is a line-oriented command stream on RouterOS, not a safe-mode terminal.
	if err := session.RequestPty("vt100", 24, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		c.close()
		return nil, errors.New("safe mode requires an interactive SSH terminal; PTY request refused")
	}
	c.input, err = session.StdinPipe()
	if err != nil {
		c.close()
		return nil, errors.New("cannot open safe-mode console input")
	}
	output, err := session.StdoutPipe()
	if err != nil {
		c.close()
		return nil, errors.New("cannot open safe-mode console output")
	}
	session.Stderr = io.Discard
	if err := session.Shell(); err != nil {
		c.close()
		return nil, errors.New("RouterOS interactive SSH shell unavailable")
	}
	go c.read(output)
	// Do not send commands while the router is still displaying its login
	// banner or preparing the terminal; early input can be lost at startup.
	if _, err := c.exchange(ctx, "", consolePrompt); err != nil {
		c.close()
		return nil, fmt.Errorf("safe-mode console prompt not received: %w", err)
	}
	obs, err := c.check(ctx)
	if err != nil {
		err = fmt.Errorf("safe-mode initial state probe failed: %w", err)
	}
	if err == nil && obs.enabled {
		err = errors.New("RouterOS safe mode is already owned; takeover is refused")
	}
	if err == nil {
		_, err = c.exchange(ctx, "\x18", regexp.MustCompile(`(?i)(?:\[safe mode taken\]|taking safe mode session\.\.\.\s*success!)`))
		if err != nil {
			err = fmt.Errorf("safe-mode take acknowledgement failed: %w", err)
		}
	}
	if err == nil {
		obs, err = c.check(ctx)
		if err != nil {
			err = fmt.Errorf("safe-mode ownership probe failed: %w", err)
		} else if !obs.enabled || !obs.current || obs.history >= historyLimit {
			err = errors.New("could not verify safe-mode ownership and history capacity")
		}
	}
	if err != nil || ctx.Err() != nil {
		c.close() // Never /quit: loss of an acquired session must request rollback.
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	// Stop the establishment cancellation hook before its context is canceled.
	// If cancellation already won, the ownership check above cannot confer a lease.
	if !stop() {
		c.close()
		return nil, errors.New("safe-mode SSH establishment cancelled")
	}
	return c, nil
}

func (c *console) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.client.Close()
	})
}

func (c *console) read(r io.Reader) {
	defer close(c.chunks)
	for {
		b := make([]byte, 4096)
		n, err := r.Read(b)
		if n > 0 {
			select {
			case c.chunks <- b[:n]:
			case <-c.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

var consoleANSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var consolePrompt = regexp.MustCompile(`(?:^|[\r\n])\[[^\r\n\]]+\][^\r\n]*>[ \t]*$`)

func (c *console) exchange(ctx context.Context, input string, pattern *regexp.Regexp) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	// Closing the connection interrupts a blocked SSH write as well as a read.
	stop := context.AfterFunc(ctx, c.close)
	defer stop()
	if _, err := io.WriteString(c.input, input); err != nil {
		return nil, errors.New("safe-mode console write failed; outcome may be uncertain")
	}
	var output strings.Builder
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("safe-mode console did not acknowledge control; outcome may be uncertain")
		case b, ok := <-c.chunks:
			if !ok {
				return nil, errors.New("safe-mode SSH session lost; rollback may be delayed")
			}
			_, _ = output.Write(b)
			if output.Len() > 64<<10 {
				return nil, errors.New("safe-mode console output exceeded limit")
			}
			plain := consoleANSI.ReplaceAllString(output.String(), "")
			if strings.Contains(strings.ToLower(plain), "hijacking safe mode") {
				return nil, errors.New("safe-mode takeover refused")
			}
			if match := pattern.FindStringSubmatch(plain); match != nil {
				return match, nil
			}
		}
	}
}

func (c *console) check(ctx context.Context) (observation, error) {
	nonce := rand.Text()
	// Only booleans and a count leave the console. History undo/redo text can
	// contain credentials and must never enter results or operational logs.
	command := fmt.Sprintf(":put (\"%s:\" . [/safe-mode get enabled] . \":\" . [/safe-mode get current] . \":\" . [/system/history print count-only where floating-undo=yes])\r", nonce)
	pattern := regexp.MustCompile(`(?:^|[\r\n])` + nonce + `:(true|false|yes|no):(true|false|yes|no):([0-9]+)[\r\n]`)
	match, err := c.exchange(ctx, command, pattern)
	if err != nil {
		return observation{}, err
	}
	count, err := strconv.Atoi(match[3])
	if err != nil {
		return observation{}, errors.New("invalid safe-mode history count")
	}
	return observation{enabled: match[1] == "true" || match[1] == "yes", current: match[2] == "true" || match[2] == "yes", history: count}, nil
}

func (c *console) commit(ctx context.Context) error {
	obs, err := c.check(ctx)
	if err != nil {
		return err
	}
	if !obs.enabled || !obs.current || obs.history >= historyLimit {
		return errors.New("safe-mode ownership or history capacity lost; confirmation refused")
	}
	if _, err := c.exchange(ctx, "\x18", regexp.MustCompile(`(?i)(?:\[safe mode released\]|releasing safe mode\.\.\.\s*success!)`)); err != nil {
		return err
	}
	obs, err = c.check(ctx)
	if err == nil && obs.current {
		err = errors.New("safe-mode release was not verified")
	}
	return err
}

func (c *console) rollback(ctx context.Context) error {
	obs, err := c.check(ctx)
	if err != nil {
		return err
	}
	if !obs.enabled || !obs.current {
		return errors.New("safe-mode ownership lost; rollback cannot be verified")
	}
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, c.close)
	defer stop()
	_, err = io.WriteString(c.input, "\x04")
	if err != nil {
		return errors.New("safe-mode rollback control failed; outcome uncertain")
	}
	return nil // This acknowledges only the request, never a verified rollback.
}
