package transport

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/Primexz/netops-mcp/internal/securepoint/config"
)

const UploadDir = "/tmp/sp-utm-mcp"
const ReportDir = "/var/www/admin/private"

type RemoteFile struct {
	Name     string    `json:"name"`
	Bytes    int64     `json:"bytes"`
	Modified time.Time `json:"modified"`
}

type Files interface {
	ListFiles(context.Context, config.Profile, string) ([]RemoteFile, error)
	Download(context.Context, config.Profile, string) ([]byte, error)
	Upload(context.Context, config.Profile, string, []byte) (string, error)
}

func remotePath(name string) error {
	if !path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("invalid remote path")
	}
	dir := path.Dir(name)
	if dir != UploadDir && dir != ReportDir {
		return errors.New("remote files must be directly inside /tmp/sp-utm-mcp or /var/www/admin/private")
	}
	return nil
}

func filesClient(ctx context.Context, p config.Profile) (*sftp.Client, func(), error) {
	if !p.RootCLI || !p.AllowFileTransfer {
		return nil, nil, errors.New("SFTP requires root_cli and allow_file_transfer")
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout())
	ssh, cleanup, err := Connect(ctx, p)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	client, err := sftp.NewClient(ssh)
	if err != nil {
		cleanup()
		cancel()
		return nil, nil, errors.New("appliance SFTP subsystem unavailable")
	}
	return client, func() { _ = client.Close(); cleanup(); cancel() }, nil
}

func (SSH) ListFiles(ctx context.Context, p config.Profile, dir string) ([]RemoteFile, error) {
	if dir != ReportDir && dir != UploadDir {
		return nil, errors.New("unsupported remote directory")
	}
	c, close, err := filesClient(ctx, p)
	if err != nil {
		return nil, err
	}
	defer close()
	entries, err := c.ReadDir(dir)
	if err != nil {
		return nil, errors.New("cannot list remote artifact directory")
	}
	var files []RemoteFile
	for _, f := range entries {
		if f.Mode().IsRegular() {
			files = append(files, RemoteFile{Name: path.Join(dir, f.Name()), Bytes: f.Size(), Modified: f.ModTime()})
		}
	}
	return files, nil
}

func (SSH) Download(ctx context.Context, p config.Profile, name string) ([]byte, error) {
	if err := remotePath(name); err != nil {
		return nil, err
	}
	c, close, err := filesClient(ctx, p)
	if err != nil {
		return nil, err
	}
	defer close()
	info, err := c.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("remote artifact is not a regular file")
	}
	if info.Size() > int64(p.MaxOutputBytes) {
		return nil, errors.New("remote artifact exceeds max_output_bytes")
	}
	f, err := c.Open(name)
	if err != nil {
		return nil, errors.New("cannot open remote artifact")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, int64(p.MaxOutputBytes)+1))
	if err != nil {
		return nil, errors.New("remote artifact download interrupted")
	}
	if len(b) > p.MaxOutputBytes {
		return nil, errors.New("remote artifact exceeds max_output_bytes")
	}
	return b, nil
}

func (SSH) Upload(ctx context.Context, p config.Profile, name string, data []byte) (string, error) {
	if err := remotePath(name); err != nil {
		return "", err
	}
	if path.Dir(name) != UploadDir {
		return "", errors.New("uploads are restricted to /tmp/sp-utm-mcp")
	}
	c, close, err := filesClient(ctx, p)
	if err != nil {
		return "", err
	}
	defer close()
	if _, err := c.Lstat(UploadDir); err != nil {
		if err := c.Mkdir(UploadDir); err != nil {
			return "", errors.New("cannot create remote staging directory")
		}
	}
	info, err := c.Lstat(UploadDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("remote staging directory must be a real directory")
	}
	if stat, ok := info.Sys().(*sftp.FileStat); !ok || stat.UID != 0 {
		return "", errors.New("remote staging directory must be owned by root")
	}
	if err := c.Chmod(UploadDir, 0700); err != nil {
		return "", errors.New("cannot protect remote staging directory")
	}
	f, err := c.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return "", errors.New("cannot create unique remote staging file")
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = c.Remove(name)
		return "", errors.New("cannot protect remote staging file")
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", errors.New("remote upload interrupted; staging file may be incomplete")
	}
	return name, nil
}
