// Package config loads appliance profiles without embedding credentials in tool arguments.
package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

type Config struct {
	Server      serverconfig.Server `toml:"server"`
	ArtifactDir string              `toml:"artifact_dir"`
	Groups      []string            `toml:"groups"`
	Profiles    map[string]Profile  `toml:"profiles"`
}

type Profile struct {
	Host                  string   `toml:"host"`
	Port                  int      `toml:"port"`
	Username              string   `toml:"username"`
	PasswordEnv           string   `toml:"password_env"`
	KeyFile               string   `toml:"key_file"`
	KeyPassphraseEnv      string   `toml:"key_passphrase_env"`
	SSHAgent              bool     `toml:"ssh_agent"`
	KnownHosts            string   `toml:"known_hosts"`
	RootCLI               bool     `toml:"root_cli"`
	JSONOutput            bool     `toml:"json_output"`
	ReadOnly              *bool    `toml:"read_only"`
	AllowDiagnostics      bool     `toml:"allow_diagnostics"`
	AllowSensitiveExports bool     `toml:"allow_sensitive_exports"`
	AllowFileTransfer     bool     `toml:"allow_file_transfer"`
	AllowLifecycle        bool     `toml:"allow_lifecycle"`
	TimeoutSeconds        int      `toml:"timeout_seconds"`
	MaxOutputBytes        int      `toml:"max_output_bytes"`
	Groups                []string `toml:"groups"`
}

func (p Profile) IsReadOnly() bool       { return p.ReadOnly == nil || *p.ReadOnly }
func (p Profile) Address() string        { return net.JoinHostPort(p.Host, fmt.Sprint(p.Port)) }
func (p Profile) Timeout() time.Duration { return time.Duration(p.TimeoutSeconds) * time.Second }

func Load(path string) (*Config, error) {
	var c Config
	base, err := serverconfig.Load(path, &c)
	if err != nil {
		return nil, err
	}
	if err := c.Normalize(base); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Normalize(base string) error {
	if c.Server.HTTP.Listen == "" {
		c.Server.HTTP.Listen = "127.0.0.1:8080"
	}
	if c.Server.HTTP.TokenEnv == "" {
		c.Server.HTTP.TokenEnv = "SP_UTM_MCP_HTTP_TOKEN"
	}
	if err := c.Server.Normalize(base); err != nil {
		return err
	}
	if len(c.Profiles) == 0 {
		return errors.New("at least one appliance profile is required")
	}
	if c.ArtifactDir == "" {
		c.ArtifactDir = "artifacts"
	}
	var err error
	c.ArtifactDir, err = serverconfig.ResolvePath(base, c.ArtifactDir)
	if err != nil {
		return err
	}
	for name, p := range c.Profiles {
		if !serverconfig.ValidProfileName(name) || p.Host == "" || p.Username == "" {
			return fmt.Errorf("profile %q: valid name, host and username are required", name)
		}
		if _, err := serverconfig.HostName(p.Host); err != nil {
			return fmt.Errorf("profile %q: invalid host", name)
		}
		if strings.ContainsAny(p.Username, "\r\n\x00") {
			return fmt.Errorf("profile %q: invalid username", name)
		}
		for field, ref := range map[string]string{"password_env": p.PasswordEnv, "key_passphrase_env": p.KeyPassphraseEnv} {
			if ref != "" && !serverconfig.ValidEnvName(ref) {
				return fmt.Errorf("profile %q: %s must name an environment variable", name, field)
			}
		}
		if p.Port == 0 {
			p.Port = 22
		}
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("profile %q: port out of range", name)
		}
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 30
		}
		if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 3600 {
			return fmt.Errorf("profile %q: timeout must be 1..3600 seconds", name)
		}
		if p.MaxOutputBytes == 0 {
			p.MaxOutputBytes = 4 << 20
		}
		if p.MaxOutputBytes < 1024 || p.MaxOutputBytes > 64<<20 {
			return fmt.Errorf("profile %q: max_output_bytes must be 1024..67108864", name)
		}
		if p.KnownHosts == "" {
			p.KnownHosts = "~/.ssh/known_hosts"
		}
		p.KnownHosts, err = serverconfig.ResolvePath(base, p.KnownHosts)
		if err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		if p.KeyFile != "" {
			p.KeyFile, err = serverconfig.ResolvePath(base, p.KeyFile)
			if err != nil {
				return fmt.Errorf("profile %q: %w", name, err)
			}
		}
		if p.PasswordEnv == "" && p.KeyFile == "" && !p.SSHAgent {
			return fmt.Errorf("profile %q: configure password_env, key_file or ssh_agent", name)
		}
		if p.Username == "root" && !p.RootCLI {
			return fmt.Errorf("profile %q: root requires root_cli = true", name)
		}
		if p.JSONOutput && !p.RootCLI {
			return fmt.Errorf("profile %q: json_output currently requires root_cli", name)
		}
		c.Profiles[name] = p
	}
	return nil
}
