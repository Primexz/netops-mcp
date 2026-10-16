package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Primexz/netops-mcp/internal/mikrotik/testutil"
)

func TestRESTMethodsEncodingAndAuthentication(t *testing.T) {
	var calls atomic.Int32
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fixture-user" || pass != "fixture-password" {
			t.Error("wrong basic auth")
		}
		if r.URL.Path != "/rest/ip/address/*A" || strings.Contains(r.RequestURI, "%2A") {
			t.Errorf("ID not literal: %s", r.RequestURI)
		}
		if r.Method == "GET" {
			if r.URL.Query().Get("comment") != "WAN & guests? / =" {
				t.Error("query not encoded")
			}
			_, _ = fmt.Fprint(w, `{".id":"*A","disabled":"false","mtu":"1500"}`)
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing content type")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["comment"] != "quote \" newline\n $() ; /" || body["disabled"] != "true" || body["mtu"] != "1500" {
			t.Errorf("wrong body: %v", body)
		}
		_, _ = fmt.Fprint(w, `{".id":"*A"}`)
	})
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	query := url.Values{"comment": []string{"WAN & guests? / ="}}
	out, err := c.Request(t.Context(), "GET", "ip/address", "*A", query, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["disabled"] != "false" {
		t.Fatal("RouterOS string coerced")
	}
	for _, method := range []string{"PUT", "PATCH", "POST"} {
		if _, err := c.Request(t.Context(), method, "ip/address", "*A", nil, map[string]any{"comment": "quote \" newline\n $() ; /", "disabled": true, "mtu": float64(1500)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Request(t.Context(), "DELETE", "ip/address", "*A", nil, nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 5 {
		t.Fatal(calls.Load())
	}
}

func TestErrorsAreClassifiedAndDoNotEchoBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   string
	}{{400, "invalid_parameters"}, {401, "authentication"}, {403, "permission"}, {404, "not_found"}, {405, "unsupported"}, {406, "unsupported"}, {429, "busy"}, {500, "router_error"}} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			var calls atomic.Int32
			_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, `{"detail":"password=fixture-password secret=do-not-echo"}`)
			})
			c, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.Request(t.Context(), "PATCH", "ip/address", "*1", nil, map[string]any{"comment": "x"})
			re, ok := errors.AsType[*Error](err)
			if !ok || re.Kind != tc.kind || re.Status != tc.status {
				t.Fatalf("wrong error: %v", err)
			}
			if strings.Contains(err.Error(), "do-not-echo") || strings.Contains(err.Error(), "fixture-password") {
				t.Fatal("secret echoed")
			}
			if calls.Load() != 1 {
				t.Fatal("mutation retried")
			}
		})
	}
}

func TestTLSRedirectAndMissingCredentials(t *testing.T) {
	var redirected atomic.Int32
	other, _ := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); t.Error("redirect followed") })
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+"/rest/ip/address")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Request(t.Context(), "GET", "ip/address", "", nil, nil)
	if re, ok := errors.AsType[*Error](err); !ok || re.Kind != "redirect" {
		t.Fatal(err)
	}
	if redirected.Load() != 0 {
		t.Fatal("credentials forwarded")
	}
	p.CAFile = ""
	untrusted, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	_, err = untrusted.Request(t.Context(), "GET", "ip/address", "", nil, nil)
	if re, ok := errors.AsType[*Error](err); !ok || re.Kind != "tls" {
		t.Fatalf("untrusted router accepted: %v", err)
	}
	t.Setenv(p.PasswordEnv, "")
	_, err = c.Request(t.Context(), "GET", "ip/address", "", nil, nil)
	if re, ok := errors.AsType[*Error](err); !ok || re.Kind != "credentials" {
		t.Fatal(err)
	}
}

func TestResponseBoundsAndCancellation(t *testing.T) {
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wait") == "true" {
			<-r.Context().Done()
			return
		}
		_, _ = fmt.Fprintf(w, `{"message":%q}`, strings.Repeat("x", 2048))
	})
	p.MaxOutputBytes = 1024
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Request(t.Context(), "GET", "log", "", nil, nil)
	if re, ok := errors.AsType[*Error](err); !ok || re.Kind != "response_limit" {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = c.Request(ctx, "GET", "log", "", url.Values{"wait": []string{"true"}}, nil)
	if re, ok := errors.AsType[*Error](err); !ok || re.Kind != "cancelled" {
		t.Fatal(err)
	}
}

func TestUnexpectedResponseShapesAndUnsafeInputs(t *testing.T) {
	var response string
	var calls atomic.Int32
	_, p := testutil.Router(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = fmt.Fprint(w, response) })
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, body := range []string{"", "not JSON", "null", "true", "123"} {
		response = body
		if _, err := c.Request(t.Context(), "GET", "ip/address", "", nil, nil); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	n := calls.Load()
	for _, path := range []string{"../execute", "ip/address?x=1", "/ip/address"} {
		if _, err := c.Request(t.Context(), "GET", path, "", nil, nil); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	if _, err := c.Request(t.Context(), "PATCH", "ip/address", "*1/../../execute", nil, nil); err == nil {
		t.Fatal("unsafe id accepted")
	}
	if _, err := c.Request(t.Context(), "PATCH", "ip/address", "*1", nil, map[string]any{"mtu": float64(1.25)}); err == nil {
		t.Fatal("fractional integer rounded")
	}
	if calls.Load() != n {
		t.Fatal("unsafe request reached router")
	}
}

func TestRedaction(t *testing.T) {
	out := Redact(map[string]any{"password": "a", "private-key": "b", "reconfigure-key": "c", "nested": []any{map[string]any{"api_token": "d", "message": "password=hello token='secret value' https://user:pass@router/ fixture-password"}}, "disabled": "false"}, "fixture-password")
	b, _ := json.Marshal(out)
	for _, secret := range []string{`"a"`, `"b"`, `"c"`, `"d"`, "hello", "secret value", "user:pass", "fixture-password"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("redaction leaked %q: %s", secret, b)
		}
	}
	if !strings.Contains(string(b), `"disabled":"false"`) {
		t.Fatal("ordinary value altered")
	}
}
