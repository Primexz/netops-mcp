// Package config loads named RouterOS profiles without reading secrets offline.
package config

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/Primexz/netops-mcp/internal/serverconfig"
)

var Groups = []string{"system", "interface", "bridge", "vlan", "address", "route", "firewall", "dhcp", "dns", "log"}

type Config struct {
	Groups   []string            `toml:"groups"`
	Server   serverconfig.Server `toml:"server"`
	Profiles map[string]Profile  `toml:"profiles"`
}

// Server and HTTP use the common MCP listener configuration.
type Server = serverconfig.Server
type HTTP = serverconfig.HTTP

type Profile struct {
	Host           string   `toml:"host"`
	Port           int      `toml:"port"`
	Username       string   `toml:"username"`
	PasswordEnv    string   `toml:"password_env"`
	CAFile         string   `toml:"ca_file"`
	ReadOnly       *bool    `toml:"read_only"`
	TimeoutSeconds int      `toml:"timeout_seconds"`
	MaxOutputBytes int      `toml:"max_output_bytes"`
	Groups         []string `toml:"groups"`
	SafeMode       SafeMode `toml:"safe_mode"`
}

// SafeMode configures the separate SSH session guarding REST mutations.
type SafeMode struct {
	Required       bool   `toml:"required"`
	SSHPort        int    `toml:"ssh_port"`
	KnownHosts     string `toml:"known_hosts"`
	TimeoutSeconds int    `toml:"timeout_seconds"`
}

func (s *SafeMode) normalize(base string) error {
	if s.SSHPort == 0 {
		s.SSHPort = 22
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = 300
	}
	if s.SSHPort < 1 || s.SSHPort > 65535 {
		return errors.New("safe_mode.ssh_port must be 1..65535")
	}
	if s.TimeoutSeconds < 30 || s.TimeoutSeconds > 600 {
		return errors.New("safe_mode.timeout_seconds must be 30..600")
	}
	if s.Required && s.KnownHosts == "" {
		return errors.New("safe_mode.required needs an explicit safe_mode.known_hosts path")
	}
	var err error
	s.KnownHosts, err = serverconfig.ResolvePath(base, s.KnownHosts)
	return err
}

func (p Profile) IsReadOnly() bool       { return p.ReadOnly == nil || *p.ReadOnly }
func (p Profile) Address() string        { return net.JoinHostPort(p.Host, fmt.Sprint(p.Port)) }
func (p Profile) Timeout() time.Duration { return time.Duration(p.TimeoutSeconds) * time.Second }
func Enabled(group string, groups []string) bool {
	return len(groups) == 0 || slices.Contains(groups, group)
}

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
	if len(c.Profiles) == 0 {
		return errors.New("at least one router profile is required")
	}
	if c.Server.HTTP.Listen == "" {
		c.Server.HTTP.Listen = "127.0.0.1:8081"
	}
	if c.Server.HTTP.TokenEnv == "" {
		c.Server.HTTP.TokenEnv = "MIKROTIK_MCP_HTTP_TOKEN"
	}
	if err := c.Server.Normalize(base); err != nil {
		return err
	}
	if err := validateGroups(c.Groups); err != nil {
		return err
	}
	for name, p := range c.Profiles {
		if !serverconfig.ValidProfileName(name) || p.Host == "" || p.Username == "" {
			return fmt.Errorf("profile %q: valid name, host and username are required", name)
		}
		if _, err := serverconfig.HostName(p.Host); err != nil {
			return fmt.Errorf("profile %q: host must be a bare IP address or DNS name", name)
		}
		if strings.ContainsAny(p.Username, ":\r\n\x00") {
			return fmt.Errorf("profile %q: invalid username", name)
		}
		if !serverconfig.ValidEnvName(p.PasswordEnv) {
			return fmt.Errorf("profile %q: password_env must name an environment variable", name)
		}
		if p.Port == 0 {
			p.Port = 443
		}
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("profile %q: port must be 1..65535", name)
		}
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 30
		}
		if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 3600 {
			return fmt.Errorf("profile %q: timeout_seconds must be 1..3600", name)
		}
		if p.MaxOutputBytes == 0 {
			p.MaxOutputBytes = 4 << 20
		}
		if p.MaxOutputBytes < 1024 || p.MaxOutputBytes > 64<<20 {
			return fmt.Errorf("profile %q: max_output_bytes must be 1024..67108864", name)
		}
		if err := validateGroups(p.Groups); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		if err := p.SafeMode.normalize(base); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		if p.CAFile != "" {
			var err error
			p.CAFile, err = serverconfig.ResolvePath(base, p.CAFile)
			if err != nil {
				return fmt.Errorf("profile %q: %w", name, err)
			}
		}
		c.Profiles[name] = p
	}
	return nil
}

func validateGroups(groups []string) error {
	for _, g := range groups {
		if !slices.Contains(Groups, g) {
			return fmt.Errorf("unknown feature group %q", g)
		}
	}
	return nil
}
