package config

import "github.com/Primexz/netops-mcp/internal/serverconfig"

// HTTP describes the shared inbound MCP listener settings.
type HTTP = serverconfig.HTTP

type Server = serverconfig.Server

func HostName(name string) (string, error) { return serverconfig.HostName(name) }
func Origin(raw string) (string, error)    { return serverconfig.Origin(raw) }
