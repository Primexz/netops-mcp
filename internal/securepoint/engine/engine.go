// Package engine coordinates appliance capabilities, isolated profiles, and
// one-shot change plans. MCP handlers never bypass this layer.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Primexz/netops-mcp/internal/securepoint/artifact"
	"github.com/Primexz/netops-mcp/internal/securepoint/catalog"
	"github.com/Primexz/netops-mcp/internal/securepoint/cli"
	"github.com/Primexz/netops-mcp/internal/securepoint/config"
	"github.com/Primexz/netops-mcp/internal/securepoint/transport"
)

const PlanTTL = 10 * time.Minute

type Capabilities struct {
	Profile           string    `json:"profile"`
	Firmware          string    `json:"firmware"`
	SupportedFamily   bool      `json:"supported_family"`
	Commands          []string  `json:"commands,omitempty"`
	DiscoveryComplete bool      `json:"discovery_complete"`
	Warnings          []string  `json:"warnings,omitempty"`
	DiscoveredAt      time.Time `json:"discovered_at"`
}

type Plan struct {
	ID                          string         `json:"id"`
	Profile                     string         `json:"profile"`
	Operation                   string         `json:"operation"`
	Parameters                  map[string]any `json:"parameters"`
	Command                     string         `json:"command"`
	Activation                  []string       `json:"activation,omitempty"`
	CanSave                     bool           `json:"can_save"`
	RequiresLifecyclePermission bool           `json:"requires_lifecycle_permission"`
	LiveVerified                bool           `json:"live_verified"`
	Preconditions               []string       `json:"preconditions"`
	ExpiresAt                   time.Time      `json:"expires_at"`
	Notes                       []string       `json:"notes,omitempty"`
	CurrentState                []CurrentState `json:"current_state,omitempty"`
}

type CurrentState struct {
	Command string     `json:"command"`
	Output  cli.Output `json:"output"`
}

type storedPlan struct {
	view        Plan
	operation   catalog.Operation
	args        map[string]any
	request     transport.Request
	fingerprint string
	snapshots   []string
	firmware    string
	upload      *uploadPlan
}

type Step struct {
	Command  string             `json:"command"`
	Status   string             `json:"status"`
	Output   *cli.Output        `json:"output,omitempty"`
	Error    string             `json:"error,omitempty"`
	Artifact *artifact.Metadata `json:"artifact,omitempty"`
}

type Execution struct {
	PlanID            string   `json:"plan_id"`
	Profile           string   `json:"profile"`
	Status            string   `json:"status"`
	Steps             []Step   `json:"steps"`
	PendingActivation []string `json:"pending_activation,omitempty"`
	Saved             bool     `json:"saved"`
	SaveAvailable     bool     `json:"save_available"`
	Notes             []string `json:"notes,omitempty"`
}

type Result struct {
	Profile      string             `json:"profile"`
	Operation    string             `json:"operation"`
	Output       *cli.Output        `json:"output,omitempty"`
	Artifact     *artifact.Metadata `json:"artifact,omitempty"`
	Plan         *Plan              `json:"plan,omitempty"`
	LiveVerified bool               `json:"live_verified"`
}

type Engine struct {
	Config    *config.Config
	Catalog   *catalog.Catalog
	Artifacts *artifact.Store
	runner    transport.Runner
	logger    *slog.Logger
	mu        sync.Mutex
	plans     map[string]*storedPlan
	caps      map[string]Capabilities
	locks     map[string]chan struct{}
	now       func() time.Time
}

func New(c *config.Config, cat *catalog.Catalog, runner transport.Runner, logger *slog.Logger) *Engine {
	e := &Engine{Config: c, Catalog: cat, Artifacts: artifact.New(c.ArtifactDir), runner: runner, logger: logger, plans: map[string]*storedPlan{}, caps: map[string]Capabilities{}, locks: map[string]chan struct{}{}, now: time.Now}
	for name := range c.Profiles {
		e.locks[name] = make(chan struct{}, 1)
	}
	return e
}

func (e *Engine) acquire(ctx context.Context, name string) (func(), error) {
	ch, ok := e.locks[name]
	if !ok {
		return nil, fmt.Errorf("unknown appliance profile %q", name)
	}
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *Engine) Discover(ctx context.Context, name string) (Capabilities, error) {
	release, err := e.acquire(ctx, name)
	if err != nil {
		return Capabilities{}, err
	}
	defer release()
	return e.discover(ctx, name, true)
}

var versionPattern = regexp.MustCompile(`\b(\d{1,2}\.\d+\.\d+(?:\.\d+)?)\b`)

func Firmware(output string) string {
	if content, _, ok := cli.Envelope(output); ok {
		if rows, ok := content.([]any); ok {
			for _, v := range rows {
				if row, ok := v.(map[string]any); ok {
					attribute, _ := row["attribute"].(string)
					value, _ := row["value"].(string)
					if strings.EqualFold(attribute, "version") || strings.EqualFold(attribute, "firmware_version") {
						return value
					}
				}
			}
		}
	}
	for line := range strings.SplitSeq(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "version") || strings.Contains(lower, "firmware") || strings.Contains(lower, "release") {
			if m := versionPattern.FindStringSubmatch(line); len(m) > 1 && (strings.HasPrefix(m[1], "14.") || strings.HasPrefix(m[1], "12.")) {
				return m[1]
			}
		}
	}
	return ""
}

func (e *Engine) discover(ctx context.Context, name string, refresh bool) (Capabilities, error) {
	e.mu.Lock()
	cached, ok := e.caps[name]
	e.mu.Unlock()
	if !refresh && ok && e.now().Sub(cached.DiscoveredAt) < time.Minute {
		return cached, nil
	}
	p := e.Config.Profiles[name]
	r, err := e.runner.Run(ctx, p, transport.Request{Command: "system info"})
	if err != nil {
		return Capabilities{}, fmt.Errorf("read-only firmware discovery failed: %w", err)
	}
	c := Capabilities{Profile: name, Firmware: Firmware(r.Output), DiscoveredAt: e.now().UTC()}
	c.SupportedFamily = strings.HasPrefix(c.Firmware, "14.")
	if c.Firmware == "" {
		c.Warnings = append(c.Warnings, "Could not identify firmware in system info; mutations remain disabled.")
	}
	r, err = e.runner.Run(ctx, p, transport.Request{Command: "help"})
	if err != nil {
		c.Warnings = append(c.Warnings, "Command discovery failed; catalog support remains documentation-derived.")
	} else {
		advertised := regexp.MustCompile(`(?m)^Command:\s*([^\r\n]+)`).FindAllStringSubmatch(r.Output, -1)
		if len(advertised) > 0 {
			for _, match := range advertised {
				c.Commands = append(c.Commands, strings.TrimSpace(match[1]))
			}
			c.DiscoveryComplete = true
		}
		for _, op := range e.Catalog.Operations {
			if len(advertised) > 0 {
				break
			}
			if op.Shell {
				continue
			}
			pattern := `(?m)^\s*(?:[a-zA-Z0-9_.-]+>\s*)?` + regexp.QuoteMeta(op.Command) + `(?:\s|$)`
			if regexp.MustCompile(pattern).MatchString(r.Output) {
				c.Commands = append(c.Commands, op.Command)
			}
		}
		// Only the explicit Command: inventory establishes a complete listing.
		// An abbreviated/plain help view cannot prove that a command is absent.
		if !c.DiscoveryComplete {
			c.Warnings = append(c.Warnings, "Help output did not enumerate command paths; availability will be checked by appliance responses.")
		}
	}
	e.mu.Lock()
	e.caps[name] = c
	e.mu.Unlock()
	return c, nil
}

func enabled(group string, groups []string) bool {
	return len(groups) == 0 || slices.Contains(groups, group)
}

func (e *Engine) Allowed(p config.Profile, o catalog.Operation, write bool) error {
	if !enabled(o.Group, e.Config.Groups) || !enabled(o.Group, p.Groups) {
		return errors.New("operation group is disabled for this profile")
	}
	if o.UnavailableReason != "" {
		return fmt.Errorf("operation unavailable: %s", o.UnavailableReason)
	}
	if o.Diagnostic && !p.AllowDiagnostics {
		return errors.New("allow_diagnostics is disabled for this profile")
	}
	if o.Shell && !p.RootCLI {
		return errors.New("operation requires a root_cli profile")
	}
	if o.SensitiveOutput && !p.AllowSensitiveExports {
		return errors.New("allow_sensitive_exports is disabled for this profile")
	}
	if o.Lifecycle && !p.AllowLifecycle {
		return errors.New("allow_lifecycle is disabled for this profile")
	}
	if write && p.IsReadOnly() {
		return errors.New("profile is read-only; configuration changes are disabled")
	}
	if write && !o.LiveVerified && !p.AllowUnverified {
		return errors.New("operation has not been live-verified; enable allow_unverified explicitly after reviewing the coverage report")
	}
	return nil
}

func (e *Engine) Call(ctx context.Context, name, id string, args map[string]any, offset, limit int) (Result, error) {
	result := Result{Profile: name, Operation: id}
	o, ok := e.Catalog.Get(id)
	if !ok {
		return result, errors.New("unknown catalog operation")
	}
	result.LiveVerified = o.LiveVerified
	p, ok := e.Config.Profiles[name]
	if !ok {
		return result, errors.New("unknown appliance profile")
	}
	if err := e.Allowed(p, o, o.Kind != "read"); err != nil {
		return result, err
	}
	if offset < 0 || limit < 1 || limit > 1000 {
		return result, errors.New("offset must be nonnegative and limit must be 1..1000")
	}
	req, err := o.Build(args)
	if err != nil {
		return result, err
	}
	release, err := e.acquire(ctx, name)
	if err != nil {
		return result, err
	}
	defer release()
	c, err := e.discover(ctx, name, false)
	if err != nil {
		return result, err
	}
	result.LiveVerified = o.LiveVerified && c.Firmware == o.ObservedFirmware
	if !c.SupportedFamily && o.Command != "system info" {
		return result, errors.New("this catalog requires detected firmware 14.x")
	}
	if c.Firmware != "" && !catalog.VersionAtLeast(c.Firmware, o.MinimumFirmware) {
		return result, fmt.Errorf("operation requires firmware %s or later", o.MinimumFirmware)
	}
	if c.DiscoveryComplete && !o.Shell && !slices.Contains(c.Commands, o.Command) {
		return result, fmt.Errorf("command %s is not advertised by this appliance firmware; inspect utm_appliance_discover and the EXTC application interface", o.Command)
	}
	if o.Kind == "read" {
		r, err := e.runner.Run(ctx, p, req)
		e.audit(name, id, "read", err == nil)
		if err != nil {
			return result, err
		}
		if o.SensitiveOutput {
			kind := "sensitive_export"
			if o.Command == "system config export" {
				kind = "configuration_download_key"
			}
			m, err := e.Artifacts.Save(name, kind, []byte(r.Output))
			if err != nil {
				return result, err
			}
			result.Artifact = &m
		} else {
			parsed := cli.Parse(r.Output, offset, limit)
			result.Output = &parsed
		}
		return result, nil
	}
	plan, err := e.prepare(ctx, name, o, args, req, c)
	if err != nil {
		return result, err
	}
	result.Plan = &plan
	e.audit(name, id, "prepared", true)
	return result, nil
}

func (e *Engine) prepare(ctx context.Context, name string, o catalog.Operation, args map[string]any, req transport.Request, c Capabilities) (Plan, error) {
	p := e.Config.Profiles[name]
	snapshots := slices.Clone(o.Snapshot)
	fingerprint, state, err := e.snapshotDetails(ctx, p, snapshots)
	if err != nil {
		return Plan{}, err
	}
	if err := e.checkReferences(ctx, p, o, args); err != nil {
		return Plan{}, err
	}
	view := Plan{ID: rand.Text(), Profile: name, Operation: o.ID, Parameters: redactOperationArgs(o, args), Command: previewCommand(o, args), Activation: slices.Clone(o.Activation), CanSave: o.Persistable, ExpiresAt: e.now().Add(PlanTTL).UTC(), RequiresLifecyclePermission: o.Lifecycle, LiveVerified: o.LiveVerified, Preconditions: snapshots}
	view.CurrentState = state
	if o.Group == "extc" {
		view.Notes = append(view.Notes, "EXTC changes may require appmgmt restart for the affected application; prepare that operation separately.")
	}
	if len(snapshots) == 0 {
		view.Notes = append(view.Notes, "No stable read-back is documented for this operation; external state changes cannot be detected.")
	}
	view.Notes = append(view.Notes, "Execution is not transactional. A lost connection can leave the result uncertain; it will not be retried.")
	// Deep copy parameters before retaining them: callers cannot mutate an
	// already-reviewed plan after preparing it.
	b, _ := json.Marshal(args)
	var copied map[string]any
	_ = json.Unmarshal(b, &copied)
	stored := &storedPlan{view: view, operation: o, args: copied, request: req, fingerprint: fingerprint, snapshots: snapshots, firmware: c.Firmware}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, old := range e.plans {
		if !e.now().Before(old.view.ExpiresAt) {
			delete(e.plans, id)
		}
	}
	if len(e.plans) >= 1000 {
		return Plan{}, errors.New("too many pending plans; discard or execute existing plans")
	}
	e.plans[view.ID] = stored
	return view, nil
}

func (e *Engine) snapshot(ctx context.Context, p config.Profile, commands []string) (string, error) {
	hash, _, err := e.snapshotDetails(ctx, p, commands)
	return hash, err
}

func (e *Engine) snapshotDetails(ctx context.Context, p config.Profile, commands []string) (string, []CurrentState, error) {
	h := sha256.New()
	var state []CurrentState
	for _, cmd := range commands {
		r, err := e.runner.Run(ctx, p, transport.Request{Command: cmd})
		if err != nil {
			return "", nil, fmt.Errorf("precondition read %s failed: %w", cmd, err)
		}
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", cmd, strings.TrimSpace(r.Output))
		state = append(state, CurrentState{Command: cmd, Output: cli.Parse(r.Output, 0, 50)})
	}
	return hex.EncodeToString(h.Sum(nil)), state, nil
}

func (e *Engine) Execute(ctx context.Context, name, id string, activate, save bool) (Execution, error) {
	result := Execution{PlanID: id, Profile: name, Status: "rejected"}
	release, err := e.acquire(ctx, name)
	if err != nil {
		return result, err
	}
	defer release()
	e.mu.Lock()
	stored, ok := e.plans[id]
	e.mu.Unlock()
	if !ok || stored.view.Profile != name {
		return result, errors.New("plan not found for this profile; plans are scoped to the current server session")
	}
	if !e.now().Before(stored.view.ExpiresAt) {
		e.Discard(name, id)
		return result, errors.New("plan expired; prepare a fresh change")
	}
	o := stored.operation
	p := e.Config.Profiles[name]
	if err := e.Allowed(p, o, true); err != nil {
		return result, err
	}
	if save && !o.Persistable {
		return result, errors.New("saving is not applicable to this operation")
	}
	if save && !activate && len(o.Activation) > 0 {
		return result, errors.New("activate must be true before saving a change requiring activation")
	}
	c, err := e.discover(ctx, name, true)
	if err != nil {
		return result, err
	}
	if !c.SupportedFamily || c.Firmware != stored.firmware {
		return result, errors.New("firmware changed since preview; prepare a fresh plan")
	}
	current, err := e.snapshot(ctx, p, stored.snapshots)
	if err != nil {
		return result, err
	}
	if current != stored.fingerprint {
		e.Discard(name, id)
		return result, errors.New("appliance state changed since preview; prepare a fresh plan")
	}
	if err := e.checkReferences(ctx, p, o, stored.args); err != nil {
		return result, err
	}
	// Consume before sending the mutation; failure or cancellation must not make
	// the same plan replayable, even when the remote result is uncertain.
	e.Discard(name, id)
	if stored.upload != nil {
		if err := filePermissions(p, true); err != nil {
			return result, err
		}
		data, _, err := e.Artifacts.Read(name, stored.upload.ArtifactID)
		if err != nil {
			return result, err
		}
		files, ok := e.runner.(transport.Files)
		if !ok {
			return result, errors.New("runner does not support file transfer")
		}
		_, err = files.Upload(ctx, p, stored.upload.RemotePath, data)
		step := Step{Command: stored.view.Command, Status: "completed"}
		result.Status = "completed"
		if err != nil {
			step.Status = "uncertain"
			step.Error = "upload failed; inspect remote staging file before retrying"
			result.Status = "uncertain"
		}
		result.Steps = []Step{step}
		e.audit(name, o.ID, result.Status, err == nil)
		return result, nil
	}
	requests := []transport.Request{stored.request}
	if activate {
		for _, cmd := range o.Activation {
			requests = append(requests, transport.Request{Command: cmd})
		}
	} else {
		result.PendingActivation = slices.Clone(o.Activation)
	}
	if save {
		requests = append(requests, transport.Request{Command: "system config save"})
	}
	result.SaveAvailable = o.Persistable
	for i, req := range requests {
		command := req.Command
		if i == 0 {
			command = stored.view.Command
		}
		step := Step{Command: command, Status: "completed"}
		r, err := e.runner.Run(ctx, p, req)
		if err != nil {
			step.Status = "failed"
			if r.Started {
				step.Status = "uncertain"
			}
			step.Error = cli.RedactText(err.Error())
			result.Steps = append(result.Steps, step)
			result.Status = step.Status
			if i > 0 {
				result.Status = "partial"
			}
			result.Notes = append(result.Notes, "Inspect current appliance state before preparing another change. No rollback or retry was performed.")
			e.audit(name, o.ID, result.Status, false)
			return result, nil
		}
		if o.SensitiveOutput && i == 0 {
			m, artifactErr := e.Artifacts.Save(name, "sensitive_operation_output", []byte(r.Output))
			if artifactErr != nil {
				step.Error = "operation completed, but its sensitive output could not be persisted"
				result.Steps = append(result.Steps, step)
				result.Status = "partial"
				return result, nil
			}
			step.Artifact = &m
		} else {
			parsed := cli.Parse(r.Output, 0, 100)
			step.Output = &parsed
		}
		result.Steps = append(result.Steps, step)
	}
	result.Status = "completed"
	result.Saved = save
	e.audit(name, o.ID, "executed", true)
	return result, nil
}

func (e *Engine) Discard(profile, id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.plans[id]
	if !ok || p.view.Profile != profile {
		return false
	}
	delete(e.plans, id)
	// Clear references to sensitive inputs as soon as a plan is discarded.
	return true
}

func (e *Engine) Plans(profile string) []Plan {
	e.mu.Lock()
	defer e.mu.Unlock()
	var plans []Plan
	for _, p := range e.plans {
		if p.view.Profile == profile && e.now().Before(p.view.ExpiresAt) {
			plans = append(plans, p.view)
		}
	}
	return plans
}

func redactArgs(args map[string]any) map[string]any {
	result := map[string]any{}
	sensitiveValue := false
	for _, k := range []string{"variable", "attribute"} {
		if s, ok := args[k].(string); ok && cli.SecretName(s) {
			sensitiveValue = true
		}
	}
	for k, v := range args {
		if cli.SecretName(k) || k == "input" || (k == "value" && sensitiveValue) || k == "content" {
			result[k] = "[REDACTED]"
			continue
		}
		switch v := v.(type) {
		case map[string]any:
			result[k] = redactArgs(v)
		case []any:
			list := make([]any, 0, len(v))
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					list = append(list, redactArgs(m))
				} else {
					if k == "options" {
						if text, ok := item.(string); ok {
							key, _, _ := strings.Cut(text, "=")
							if cli.SecretName(key) {
								item = key + "=[REDACTED]"
							}
						}
					}
					list = append(list, item)
				}
			}
			result[k] = list
		default:
			result[k] = v
		}
	}
	return result
}

func redactOperationArgs(o catalog.Operation, args map[string]any) map[string]any {
	result := redactArgs(args)
	if o.Command == "rsa import" || o.Command == "pkey import" {
		if _, ok := result["value"]; ok {
			result["value"] = "[REDACTED]"
		}
	}
	return result
}

func previewCommand(o catalog.Operation, args map[string]any) string {
	redacted := redactOperationArgs(o, args)
	// Use the encoder independently of required/type checks: redaction may turn
	// an array into a marker string, which is intentionally not executable.
	var cmd strings.Builder
	cmd.WriteString(o.Command)
	for _, p := range o.Parameters {
		v, ok := redacted[p.Name]
		if !ok {
			continue
		}
		if p.Type == "multiline" {
			cmd.WriteString(" <stdin: REDACTED>")
			continue
		}
		s, err := cli.Value(v)
		if err != nil {
			s = "[REDACTED]"
		}
		if !p.Positional {
			cmd.WriteString(" " + p.Name)
		}
		cmd.WriteString(" " + s)
	}
	return cmd.String()
}

func (e *Engine) audit(profile, operation, event string, success bool) {
	if e.logger != nil {
		e.logger.Info("appliance operation", "profile", profile, "operation", operation, "event", event, "success", success)
	}
}

func (e *Engine) checkReferences(ctx context.Context, p config.Profile, o catalog.Operation, args map[string]any) error {
	// Only documented name references are checked. Appliance-side validators
	// remain authoritative for dependency constraints not exposed by the CLI.
	type lookup struct {
		command, column string
		keys            []string
	}
	var checks []lookup
	if o.Command == "node new" || o.Command == "node set" {
		checks = append(checks, lookup{"interface zone get", "name", []string{"zone"}})
	}
	if o.Command == "rule new" || o.Command == "rule set" {
		checks = append(checks, lookup{"node get", "name", []string{"src", "dst", "nat_node"}}, lookup{"service get", "name", []string{"service", "nat_service"}}, lookup{"rule group get", "name", []string{"group"}})
	}
	for _, check := range checks {
		var values []string
		for _, key := range check.keys {
			if s, ok := args[key].(string); ok && s != "" {
				values = append(values, s)
			}
		}
		if len(values) == 0 {
			continue
		}
		r, err := e.runner.Run(ctx, p, transport.Request{Command: check.command})
		if err != nil {
			return fmt.Errorf("reference lookup %s failed: %w", check.command, err)
		}
		out := cli.Parse(r.Output, 0, 1000)
		if (out.Format != "table" && out.Format != "json") || out.More {
			continue
		} // A partial/unknown format cannot prove absence.
		var names []string
		for _, row := range out.Records() {
			for key, v := range row {
				if strings.EqualFold(key, check.column) {
					names = append(names, v)
				}
			}
		}
		if len(names) == 0 {
			continue
		}
		for _, value := range values {
			if !slices.Contains(names, value) {
				// Rules may reference groups as well as individual objects.
				if check.command == "node get" || check.command == "service get" {
					continue
				}
				return fmt.Errorf("reference %q not found in %s", value, check.command)
			}
		}
	}
	return nil
}
