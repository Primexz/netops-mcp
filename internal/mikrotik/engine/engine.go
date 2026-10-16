// Package engine enforces profile permissions before dispatching catalog operations.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/Primexz/netops-mcp/internal/mikrotik/catalog"
	"github.com/Primexz/netops-mcp/internal/mikrotik/config"
	"github.com/Primexz/netops-mcp/internal/mikrotik/routeros"
	"github.com/Primexz/netops-mcp/internal/mikrotik/safemode"
)

type Engine struct {
	Config   *config.Config
	Catalog  *catalog.Catalog
	logger   *slog.Logger
	mu       sync.Mutex
	clients  map[string]*routeros.Client
	SafeMode *safemode.Manager
}

func New(c *config.Config, cat *catalog.Catalog, logger *slog.Logger) *Engine {
	return &Engine{Config: c, Catalog: cat, logger: logger, clients: map[string]*routeros.Client{}, SafeMode: safemode.New(c.Profiles, logger)}
}
func (e *Engine) Close() {
	e.SafeMode.Close()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.clients {
		c.Close()
	}
}
func (e *Engine) client(profile string) (*routeros.Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.clients[profile]; c != nil {
		return c, nil
	}
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return nil, errors.New("unknown profile")
	}
	c, err := routeros.New(p)
	if err != nil {
		return nil, err
	}
	e.clients[profile] = c
	return c, nil
}

func (e *Engine) Profiles() any {
	profiles := make([]map[string]any, 0, len(e.Config.Profiles))
	for _, name := range slices.Sorted(maps.Keys(e.Config.Profiles)) {
		p := e.Config.Profiles[name]
		groups := []string{}
		for _, g := range config.Groups {
			if config.Enabled(g, e.Config.Groups) && config.Enabled(g, p.Groups) {
				groups = append(groups, g)
			}
		}
		profiles = append(profiles, map[string]any{"name": name, "host": p.Host, "port": p.Port, "read_only": p.IsReadOnly(), "groups": groups, "safe_mode_required": p.SafeMode.Required, "safe_mode_timeout_seconds": p.SafeMode.TimeoutSeconds})
	}
	return map[string]any{"profiles": profiles}
}

// Call receives schema-validated arguments from the MCP adapter.
func (e *Engine) Call(ctx context.Context, o catalog.Operation, args map[string]any) (out any, err error) {
	profile, _ := args["profile"].(string)
	defer func() {
		if e.logger != nil {
			e.logger.Info("operation", "profile", profile, "operation", o.Name, "success", err == nil)
		}
	}()
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return nil, errors.New("unknown profile")
	}
	if !config.Enabled(o.Group, e.Config.Groups) || !config.Enabled(o.Group, p.Groups) {
		return nil, errors.New("operation group is disabled for this profile")
	}
	if !o.ReadOnly() && p.IsReadOnly() {
		return nil, errors.New("profile is read-only; configuration changes require read_only=false")
	}
	c, err := e.client(profile)
	if err != nil {
		return nil, err
	}
	modeID, _ := args["safe_mode_id"].(string)
	if !o.ReadOnly() && p.SafeMode.Required {
		out, view, err := e.SafeMode.Do(ctx, profile, modeID, func(ctx context.Context, dispatch func() error) (any, error) {
			return e.call(ctx, c, profile, o, args, dispatch)
		})
		if err == nil {
			out.(map[string]any)["safe_mode"] = view
		}
		return out, err
	}
	if modeID != "" {
		return nil, errors.New("safe_mode_id is only accepted for writes on profiles requiring safe mode")
	}
	return e.call(ctx, c, profile, o, args, func() error { return nil })
}

// ConfirmSafeMode checks REST reachability inside the same window lock used by
// mutations. This internal safety probe does not expose disabled system tools.
func (e *Engine) ConfirmSafeMode(ctx context.Context, profile, id string) (safemode.View, error) {
	return e.SafeMode.Confirm(ctx, profile, id, func(ctx context.Context) error {
		c, err := e.client(profile)
		if err != nil {
			return err
		}
		_, err = c.Request(ctx, "GET", "system/resource", "", nil, nil)
		return err
	})
}

func (e *Engine) call(ctx context.Context, c *routeros.Client, profile string, o catalog.Operation, args map[string]any, dispatch func() error) (any, error) {
	id, _ := args["id"].(string)
	params, _ := args["parameters"].(map[string]any)
	if o.StaticOnly && (o.Action == "update" || o.Action == "delete") {
		current, err := c.Request(ctx, "GET", o.Path, id, nil, nil)
		if err != nil {
			return nil, err
		}
		record, ok := current.(map[string]any)
		if list, isList := current.([]any); isList && len(list) == 1 {
			record, ok = list[0].(map[string]any)
		}
		if !ok {
			return nil, errors.New("could not verify static record before mutation")
		}
		dynamic, present := record["dynamic"]
		if !present || (dynamic != "false" && dynamic != "no" && dynamic != false) {
			return nil, errors.New("static-only operation refused: record is dynamic or its status is unavailable")
		}
	}
	if o.Action == "move" {
		params = map[string]any{".id": id, "destination": args["destination"]}
		if err := dispatch(); err != nil {
			return nil, err
		}
		value, err := c.Request(ctx, o.Method, o.Path+"/move", "", nil, params)
		if err != nil {
			return nil, err
		}
		return map[string]any{"profile": profile, "operation": o.Name, "data": value}, nil
	}
	query := url.Values{}
	if filters, ok := args["filters"].(map[string]any); ok {
		for k, v := range filters {
			query.Set(k, v.(string))
		}
	}
	if properties, ok := args["properties"].([]any); ok {
		// RouterOS expects one comma-separated .proplist value.
		if len(properties) > 0 {
			values := make([]string, len(properties))
			for i, v := range properties {
				values[i] = v.(string)
			}
			query.Set(".proplist", strings.Join(values, ","))
		}
	}
	path := o.Path
	if o.Singleton && o.Action == "update" {
		path += "/set"
	}
	if !o.ReadOnly() {
		if err := dispatch(); err != nil {
			return nil, err
		}
	}
	value, err := c.Request(ctx, o.Method, path, id, query, params)
	if err != nil {
		return nil, err
	}
	if o.Action == "list" {
		records, ok := value.([]any)
		if !ok {
			return nil, errors.New("expected a RouterOS record list")
		}
		start := min(integer(args, "offset", 0), len(records))
		end := min(start+integer(args, "limit", 100), len(records))
		return map[string]any{"profile": profile, "operation": o.Name, "records": records[start:end], "offset": start, "total": len(records), "more": end < len(records), "truncated": end < len(records)}, nil
	}
	return map[string]any{"profile": profile, "operation": o.Name, "data": value}, nil
}

func integer(args map[string]any, name string, fallback int) int {
	if n, ok := args[name].(float64); ok {
		return int(n)
	}
	return fallback
}

// Discover reports actual read observations, never guesses complete command support.
// It uses the same group permissions as the corresponding operation tools.
func (e *Engine) Discover(ctx context.Context, profile string) (any, error) {
	p, ok := e.Config.Profiles[profile]
	if !ok {
		return nil, errors.New("unknown profile")
	}
	if !config.Enabled("system", e.Config.Groups) || !config.Enabled("system", p.Groups) {
		return nil, errors.New("system group is disabled for this profile")
	}
	c, err := e.client(profile)
	if err != nil {
		return nil, err
	}
	resource, err := c.Request(ctx, "GET", "system/resource", "", nil, nil)
	if err != nil {
		return nil, err
	}
	packages, packageErr := c.Request(ctx, "GET", "system/package", "", nil, nil)
	out := map[string]any{"profile": profile, "resource": resource, "packages": packages, "complete_capability_probe": false}
	if packageErr != nil {
		if re, ok := errors.AsType[*routeros.Error](packageErr); ok {
			out["packages_error"] = re
		} else {
			out["packages_error"] = fmt.Sprint(packageErr)
		}
	}
	return out, nil
}
