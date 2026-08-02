// The `nofossh` build tag compiles this file instead of fossh.go: same
// public API, zero cgo, zero dependency on libfossh being present at
// build or link time. Downstream projects drop telemetry entirely with
// `go build -tags nofossh`, no call-site changes required (§12).
//
//go:build nofossh

package fossh

import (
	"net/http"
	"time"
)

// Config configures a Client. Ignored in the nofossh build — see fossh.go.
type Config struct {
	Path string
	Key  string
}

// Client is a no-op stand-in in the nofossh build — see fossh.go.
type Client struct{}

// Error mirrors the real binding's error type so type assertions against
// *fossh.Error keep compiling either way; it's just never constructed here.
type Error struct {
	Code int32
	Name string
}

func (e *Error) Error() string { return "fossh: " + e.Name }

// New always succeeds and returns a Client whose methods are all no-ops.
func New(Config) (*Client, error) { return &Client{}, nil }

func (c *Client) Close() {}

func (c *Client) Pageview(*http.Request) error { return nil }

func (c *Client) Event(string, int64, map[string]string) error { return nil }

func (c *Client) Timing(string, time.Duration) error { return nil }

func (c *Client) Flush() error { return nil }

// Middleware returns next unchanged — no recording happens in the
// nofossh build.
func Middleware(*Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}
