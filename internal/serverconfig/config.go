// Package serverconfig provides common, offline configuration loading and MCP listener settings.
package serverconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Server configures an independent MCP server's transport.
type Server struct {
	Transport string `toml:"transport"`
	HTTP      HTTP   `toml:"http"`
}

// Normalize validates the transport and listener without reading credentials or TLS files.
// Vendors must assign their listener and token environment defaults before calling it.
func (s *Server) Normalize(base string) error {
	if s.Transport == "" {
		s.Transport = "stdio"
	}
	if s.Transport != "stdio" && s.Transport != "http" {
		return errors.New("server.transport must be stdio or http")
	}
	if err := s.HTTP.Normalize(base); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// Load decodes strict TOML into target and returns the absolute configuration directory.
// It does not normalize vendor settings or look up secret environment values.
func Load(path string, target any) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := toml.NewDecoder(bytes.NewReader(b)).DisallowUnknownFields().Decode(target); err != nil {
		return "", fmt.Errorf("configuration: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Dir(abs), nil
}

// ResolvePath expands ~/ and resolves relative paths beside the configuration file.
// It does not read or require the referenced file to exist.
func ResolvePath(base, path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(homeDir, rest)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return filepath.Clean(path), nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var profileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidEnvName checks a reference's syntax without reading its value.
func ValidEnvName(name string) bool { return envName.MatchString(name) }

func ValidProfileName(name string) bool { return profileName.MatchString(name) }
