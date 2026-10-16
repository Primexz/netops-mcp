package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path"

	"github.com/Primexz/netops-mcp/internal/securepoint/artifact"
	"github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
	"github.com/Primexz/netops-mcp/internal/securepoint/transport"
)

type uploadPlan struct{ ArtifactID, RemotePath string }

func filePermissions(p config.Profile, upload bool) error {
	if !p.AllowSensitiveExports {
		return errors.New("allow_sensitive_exports is required for artifact access")
	}
	if !p.RootCLI || !p.AllowFileTransfer {
		return errors.New("remote artifact access requires root_cli and allow_file_transfer")
	}
	if upload && p.IsReadOnly() {
		return errors.New("profile is read-only")
	}
	if upload && !p.AllowUnverified {
		return errors.New("file transfer has not been live-verified; allow_unverified is required")
	}
	return nil
}

func (e *Engine) ReadArtifact(profile, id string) ([]byte, artifact.Metadata, error) {
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return nil, artifact.Metadata{}, errors.New("unknown appliance profile")
	}
	if !p.AllowSensitiveExports {
		return nil, artifact.Metadata{}, errors.New("allow_sensitive_exports is disabled for this profile")
	}
	return e.Artifacts.Read(profile, id)
}

func (e *Engine) StageArtifact(profile string, data []byte) (artifact.Metadata, error) {
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return artifact.Metadata{}, errors.New("unknown appliance profile")
	}
	if !p.AllowSensitiveExports {
		return artifact.Metadata{}, errors.New("allow_sensitive_exports is required for staging sensitive artifacts")
	}
	return e.Artifacts.Save(profile, "staged_import", data)
}

func (e *Engine) RemoteFiles(ctx context.Context, profile, dir string) ([]transport.RemoteFile, error) {
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return nil, errors.New("unknown appliance profile")
	}
	if err := filePermissions(p, false); err != nil {
		return nil, err
	}
	f, ok := e.runner.(transport.Files)
	if !ok {
		return nil, errors.New("runner does not support file transfers")
	}
	release, err := e.acquire(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer release()
	return f.ListFiles(ctx, p, dir)
}

func (e *Engine) Download(ctx context.Context, profile, name string) (artifact.Metadata, error) {
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return artifact.Metadata{}, errors.New("unknown appliance profile")
	}
	if err := filePermissions(p, false); err != nil {
		return artifact.Metadata{}, err
	}
	f, ok := e.runner.(transport.Files)
	if !ok {
		return artifact.Metadata{}, errors.New("runner does not support file transfers")
	}
	release, err := e.acquire(ctx, profile)
	if err != nil {
		return artifact.Metadata{}, err
	}
	defer release()
	b, err := f.Download(ctx, p, name)
	e.audit(profile, "artifact_download", "download", err == nil)
	if err != nil {
		return artifact.Metadata{}, err
	}
	return e.Artifacts.Save(profile, "remote_file", b)
}

func (e *Engine) PrepareUpload(ctx context.Context, profile, id string) (Plan, error) {
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return Plan{}, errors.New("unknown appliance profile")
	}
	if err := filePermissions(p, true); err != nil {
		return Plan{}, err
	}
	if _, ok := e.runner.(transport.Files); !ok {
		return Plan{}, errors.New("runner does not support file transfers")
	}
	_, m, err := e.Artifacts.Read(profile, id)
	if err != nil {
		return Plan{}, err
	}
	release, err := e.acquire(ctx, profile)
	if err != nil {
		return Plan{}, err
	}
	defer release()
	c, err := e.discover(ctx, profile, false)
	if err != nil {
		return Plan{}, err
	}
	if !c.SupportedFamily {
		return Plan{}, errors.New("file transfers require detected firmware 14.x")
	}
	remote := path.Join(transport.UploadDir, rand.Text()+".bin")
	op := catalog.Operation{ID: "utm_artifacts_upload", Command: "SFTP upload", Group: "system", Kind: "change", SensitiveOutput: true, Snapshot: []string{"system config get"}}
	if err := e.Allowed(p, op, true); err != nil {
		return Plan{}, err
	}
	view, err := e.prepare(ctx, profile, op, map[string]any{}, transport.Request{}, c)
	if err != nil {
		return Plan{}, err
	}
	e.mu.Lock()
	s := e.plans[view.ID]
	s.upload = &uploadPlan{ArtifactID: id, RemotePath: remote}
	s.view.Command = fmt.Sprintf("SFTP upload artifact %s (%d bytes; sha256 %s) to %s", id, m.Bytes, m.SHA256, remote)
	s.view.Parameters = map[string]any{"artifact_id": id, "remote_path": remote, "sha256": m.SHA256}
	view = s.view
	e.mu.Unlock()
	return view, nil
}
