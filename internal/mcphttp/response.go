package mcphttp

import (
	"bytes"
	"errors"
	"maps"
	"net/http"
)

// JSON responses may contain several copies of an appliance result. Bound the
// complete response independently of the inbound request and profile limits.
const maxResponseBytes = 64 << 20

var errResponseLimit = errors.New("MCP HTTP response exceeds byte limit")

// limitResponse buffers the JSON response so exceeding the limit never sends a
// truncated success response. A tool may already have applied a change; callers
// must not retry mutations merely because delivery of their result failed.
func limitResponse(next http.Handler, limit int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := &responseBuffer{header: make(http.Header), limit: limit}
		next.ServeHTTP(buffer, r)
		if buffer.exceeded {
			http.Error(w, "MCP response exceeds byte limit; a requested change may already have applied", http.StatusInternalServerError)
			return
		}
		maps.Copy(w.Header(), buffer.header)
		// The MCP SDK may select its own cache policy. The shared listener always
		// serves administrative results with no-store.
		w.Header().Set("Cache-Control", "no-store")
		status := buffer.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}

type responseBuffer struct {
	header   http.Header
	body     bytes.Buffer
	limit    int
	status   int
	exceeded bool
}

func (w *responseBuffer) Header() http.Header { return w.header }

func (w *responseBuffer) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

// Flush acknowledges the SDK's flush requests without publishing buffered bytes.
// The shared transport uses finite JSON responses; standalone SSE is disabled.
func (w *responseBuffer) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
}

func (w *responseBuffer) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.exceeded || len(p) > w.limit-w.body.Len() {
		w.exceeded = true
		w.body.Reset()
		return 0, errResponseLimit
	}
	return w.body.Write(p)
}
