package serverconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStrictServerSchema(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		valid bool
	}{
		{"server", "[server]\ntransport='http'\n[server.http]\nlisten='127.0.0.1:8123'\ntoken_env='HTTP_SECRET'\n", true},
		{"top level transport", "transport='http'", false},
		{"top level http", "[http]\nlisten='127.0.0.1:8080'", false},
		{"bearer token env", "[server.http]\nbearer_token_env='HTTP_SECRET'", false},
		{"unknown nested key", "[server.http]\nallowed_host=['localhost']", false},
		{"malformed", "[server", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			var c struct {
				Server Server `toml:"server"`
			}
			base, err := Load(path, &c)
			if !tc.valid {
				if err == nil || !strings.Contains(err.Error(), "configuration:") {
					t.Fatalf("expected configuration error, got %v", err)
				}
				return
			}
			if err != nil || base != filepath.Dir(path) || c.Server.HTTP.TokenEnv != "HTTP_SECRET" {
				t.Fatalf("load: base=%q config=%+v error=%v", base, c, err)
			}
		})
	}
}

func TestResolvePathWithoutReadingFiles(t *testing.T) {
	dir := t.TempDir()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]string{
		"":                                 "",
		"certs/../cert.pem":                filepath.Join(dir, "cert.pem"),
		"~/missing/key.pem":                filepath.Join(homeDir, "missing/key.pem"),
		filepath.Join(dir, "absolute.pem"): filepath.Join(dir, "absolute.pem"),
	} {
		got, err := ResolvePath(dir, raw)
		if err != nil || got != want {
			t.Errorf("ResolvePath(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	var target Server
	if _, err := Load(filepath.Join(dir, "missing.toml"), &target); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestServerOfflineNormalization(t *testing.T) {
	s := Server{Transport: "http", HTTP: HTTP{TokenEnv: "NETOPS_TEST_MISSING_TOKEN", Token: "invalid until startup", TLSCertFile: "missing.pem", TLSKeyFile: "missing.key"}}
	t.Setenv(s.HTTP.TokenEnv, "")
	if err := s.Normalize(t.TempDir()); err != nil {
		t.Fatalf("offline normalization required secrets or files: %v", err)
	}
	s.Transport = "sse"
	if err := s.Normalize(t.TempDir()); err == nil {
		t.Fatal("unsupported transport accepted")
	}
}

func TestProfileAndEnvironmentReferences(t *testing.T) {
	for _, name := range []string{"headquarters", "branch-1", "router.site_2"} {
		if !ValidProfileName(name) {
			t.Errorf("valid profile rejected: %q", name)
		}
	}
	for _, name := range []string{"", "../router", "router name", "_router", strings.Repeat("a", 129)} {
		if ValidProfileName(name) {
			t.Errorf("invalid profile accepted: %q", name)
		}
	}
	for _, name := range []string{"SP_UTM_HQ_PASSWORD", "MIKROTIK_HQ_PASSWORD", "_KEY_2"} {
		if !ValidEnvName(name) {
			t.Errorf("valid environment name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "2PASSWORD", "PASS WORD", "PASS=VALUE", "${PASSWORD}", "PASS\n"} {
		if ValidEnvName(name) {
			t.Errorf("invalid environment name accepted: %q", name)
		}
	}
}
