// Package artifact keeps potentially sensitive exports out of MCP result text.
package artifact

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type Metadata struct {
	ID      string    `json:"id"`
	Profile string    `json:"profile"`
	Kind    string    `json:"kind"`
	Path    string    `json:"path"`
	Bytes   int       `json:"bytes"`
	SHA256  string    `json:"sha256"`
	Created time.Time `json:"created"`
}

type Store struct {
	dir   string
	mu    sync.Mutex
	files map[string]Metadata
}

func New(dir string) *Store { return &Store{dir: dir, files: map[string]Metadata{}} }

func (s *Store) Save(profile, kind string, data []byte) (Metadata, error) {
	if len(data) > 64<<20 {
		return Metadata{}, errors.New("artifact exceeds 64 MiB")
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return Metadata{}, err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return Metadata{}, err
	}
	defer func() { _ = root.Close() }()
	id := rand.Text() + ".bin"
	f, err := root.OpenFile(id, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Metadata{}, err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = root.Remove(id)
		return Metadata{}, errors.New("could not persist artifact")
	}
	h := sha256.Sum256(data)
	m := Metadata{ID: id, Profile: profile, Kind: kind, Path: filepath.Join(s.dir, id), Bytes: len(data), SHA256: hex.EncodeToString(h[:]), Created: time.Now().UTC()}
	s.mu.Lock()
	s.files[id] = m
	s.mu.Unlock()
	return m, nil
}

func (s *Store) Read(profile, id string) ([]byte, Metadata, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9]+\.bin$`).MatchString(id) {
		return nil, Metadata{}, errors.New("invalid artifact ID")
	}
	s.mu.Lock()
	m, ok := s.files[id]
	s.mu.Unlock()
	if !ok || m.Profile != profile {
		return nil, Metadata{}, errors.New("artifact not found for this profile in this server session")
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, Metadata{}, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(id)
	if err != nil {
		return nil, Metadata{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, Metadata{}, err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(m.Bytes) {
		return nil, Metadata{}, errors.New("artifact changed")
	}
	data := make([]byte, m.Bytes)
	n := 0
	for n < len(data) {
		count, err := f.Read(data[n:])
		n += count
		if err != nil {
			return nil, Metadata{}, err
		}
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != m.SHA256 {
		return nil, Metadata{}, fmt.Errorf("artifact checksum mismatch")
	}
	return data, m, nil
}

func (s *Store) List(profile string) []Metadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []Metadata
	for _, m := range s.files {
		if m.Profile == profile {
			result = append(result, m)
		}
	}
	return result
}
