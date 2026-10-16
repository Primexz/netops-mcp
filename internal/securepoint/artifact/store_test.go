package artifact

import (
	"os"
	"testing"
)

func TestIntegrityAndProfileIsolation(t *testing.T) {
	s := New(t.TempDir())
	m, err := s.Save("first", "sensitive_export", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Read("second", m.ID); err == nil {
		t.Fatal("cross-profile read succeeded")
	}
	if _, _, err := s.Read("first", "../../config.toml"); err == nil {
		t.Fatal("path traversal succeeded")
	}
	if err := os.WriteFile(m.Path, []byte("tamper"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Read("first", m.ID); err == nil {
		t.Fatal("checksum change not detected")
	}
}
