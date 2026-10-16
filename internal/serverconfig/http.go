package serverconfig

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// HTTP describes the inbound MCP listener independently of appliance connections.
type HTTP struct {
	Listen          string   `toml:"listen"`
	Token           string   `toml:"token"`
	TokenEnv        string   `toml:"token_env"`
	AllowedHosts    []string `toml:"allowed_hosts"`
	AllowedOrigins  []string `toml:"allowed_origins"`
	TLSCertFile     string   `toml:"tls_cert_file"`
	TLSKeyFile      string   `toml:"tls_key_file"`
	MaxRequestBytes int64    `toml:"max_request_bytes"`
}

func (h *HTTP) Normalize(base string) error {
	if h.Listen == "" {
		h.Listen = "127.0.0.1:8080"
	}
	host, port, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return errors.New("http.listen must be host:port")
	}
	if host != "" {
		if _, err := HostName(host); err != nil {
			return fmt.Errorf("http.listen: %w", err)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return errors.New("http.listen port must be 0..65535")
	}
	if h.TokenEnv == "" {
		h.TokenEnv = "NETOPS_MCP_HTTP_TOKEN"
	}
	if !ValidEnvName(h.TokenEnv) {
		return errors.New("invalid http.token_env name")
	}
	if (h.TLSCertFile == "") != (h.TLSKeyFile == "") {
		return errors.New("http.tls_cert_file and http.tls_key_file must be configured together")
	}
	loopback := strings.EqualFold(host, "localhost")
	if ip, err := netip.ParseAddr(host); err == nil {
		loopback = ip.IsLoopback()
	}
	if !loopback && h.TLSCertFile == "" {
		return errors.New("HTTP listeners outside loopback require tls_cert_file and tls_key_file; use a loopback listener behind a TLS reverse proxy")
	}
	if h.TLSCertFile != "" {
		h.TLSCertFile, err = ResolvePath(base, h.TLSCertFile)
		if err != nil {
			return err
		}
		h.TLSKeyFile, err = ResolvePath(base, h.TLSKeyFile)
		if err != nil {
			return err
		}
	}
	if len(h.AllowedHosts) == 0 {
		if loopback {
			h.AllowedHosts = []string{"127.0.0.1", "localhost", "::1"}
		} else {
			ip, err := netip.ParseAddr(host)
			if host == "" || err == nil && ip.IsUnspecified() {
				return errors.New("wildcard HTTP listeners require an explicit allowed_hosts list")
			}
			h.AllowedHosts = []string{host}
		}
	}
	for i, name := range h.AllowedHosts {
		normalized, err := HostName(name)
		if err != nil {
			return fmt.Errorf("http.allowed_hosts: %w", err)
		}
		h.AllowedHosts[i] = normalized
	}
	for i, origin := range h.AllowedOrigins {
		normalized, err := Origin(origin)
		if err != nil {
			return fmt.Errorf("http.allowed_origins: %w", err)
		}
		h.AllowedOrigins[i] = normalized
	}
	if h.MaxRequestBytes == 0 {
		h.MaxRequestBytes = 16 << 20
	}
	if h.MaxRequestBytes < 1024 || h.MaxRequestBytes > 64<<20 {
		return errors.New("http.max_request_bytes must be 1024..67108864")
	}
	return nil
}

// HostName validates configured hostnames/IPs, without ports or wildcard syntax.
func HostName(name string) (string, error) {
	if ip, err := netip.ParseAddr(name); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("scoped IP addresses are not supported")
		}
		return ip.String(), nil
	}
	if name == "" || len(name) > 253 {
		return "", errors.New("expected a hostname or IP without a port or wildcard")
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid HTTP hostname")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return "", errors.New("invalid HTTP hostname")
			}
		}
	}
	return strings.ToLower(name), nil
}

// Origin accepts only an HTTP(S) origin, including an optional explicit port.
func Origin(raw string) (string, error) {
	if strings.Contains(raw, "#") {
		return "", errors.New("an origin cannot contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("expected an exact http(s) origin without a path, credentials, query or fragment")
	}
	host, err := HostName(u.Hostname())
	if err != nil {
		return "", err
	}
	// URL parsing permits empty ports and unbracketed IPv6; neither is an exact origin.
	if strings.HasSuffix(u.Host, ":") || strings.Contains(host, ":") != strings.HasPrefix(u.Host, "[") {
		return "", errors.New("invalid origin authority")
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid origin port")
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}
