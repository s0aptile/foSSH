// Package fossh is a thin, idiomatic Go wrapper around foSSH's C ABI
// (libfossh, §11 of the implementation spec). Build with `-tags nofossh`
// to compile every exported call to a no-op, with zero cgo dependency,
// without touching call sites — see fossh_noop.go.
//
//go:build !nofossh

package fossh

/*
#cgo LDFLAGS: -lfossh
#include <stdlib.h>
#include "fossh.h"
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
	"unsafe"
)

// Config configures a Client.
type Config struct {
	// Path to a fossh.toml. Empty searches $FOSSH_CONFIG, ./fossh.toml,
	// then /etc/fossh/fossh.toml — the same order fossh-cli uses (§10).
	Path string
	// Key is the write key `fossh site create` printed once
	// (fossh_<slug>_<base32>). Read it from an environment variable or a
	// secret store — never hardcode it.
	Key string
}

// Client wraps one fossh_ctx. The zero value is not usable; construct
// with New. Safe for concurrent use from multiple goroutines: fossh_ctx
// itself is Send + Sync on the Rust side (§11), and Client additionally
// guards Close against a concurrent call using an already-freed pointer.
type Client struct {
	mu  sync.Mutex
	ctx *C.fossh_ctx
}

// Error is returned by every Client method on a non-zero fossh return
// code. Name is one of a fixed, small set of strings (§11's
// fossh_last_error) — never anything derived from caller-supplied data,
// so it's always safe to log.
type Error struct {
	Code int32
	Name string
}

func (e *Error) Error() string {
	return fmt.Sprintf("fossh: %s (%d)", e.Name, e.Code)
}

var errClosed = errors.New("fossh: client is closed")

func lastError(ctx *C.fossh_ctx, code int32) error {
	if code == 0 {
		return nil
	}
	buf := make([]byte, 64)
	C.fossh_last_error(ctx, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	n := bytes.IndexByte(buf, 0)
	if n < 0 {
		n = len(buf)
	}
	return &Error{Code: code, Name: string(buf[:n])}
}

func cStringOrNil(s string) (*C.char, func()) {
	if s == "" {
		return nil, func() {}
	}
	cs := C.CString(s)
	return cs, func() { C.free(unsafe.Pointer(cs)) }
}

// New initializes a Client from cfg. The returned Client must be closed
// (typically via defer c.Close()) to release the underlying fossh_ctx.
func New(cfg Config) (*Client, error) {
	cPath, freePath := cStringOrNil(cfg.Path)
	defer freePath()

	ctx := C.fossh_init(cPath)
	if ctx == nil {
		return nil, errors.New("fossh: fossh_init failed (bad config path, or the data directory/database could not be opened)")
	}

	if cfg.Key != "" {
		cKey := C.CString(cfg.Key)
		defer C.free(unsafe.Pointer(cKey))
		if rc := C.fossh_set_key(ctx, cKey); rc != 0 {
			err := lastError(ctx, int32(rc))
			C.fossh_free(ctx)
			return nil, err
		}
	}

	return &Client{ctx: ctx}, nil
}

// Close releases the underlying fossh_ctx. Safe to call more than once,
// and safe to call on a nil *Client.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx != nil {
		C.fossh_free(c.ctx)
		c.ctx = nil
	}
}

// Pageview records a page view for r: path, referrer, remote IP, and
// user agent. If you're behind a reverse proxy, resolve the real client
// IP from X-Forwarded-For (or similar) upstream of this call and set
// r.RemoteAddr accordingly — foSSH hashes and discards whatever IP it's
// given within this one call either way (P2, §11), so there's no
// after-the-fact way to correct it once the call returns.
func (c *Client) Pageview(r *http.Request) error {
	path, freePath := cStringOrNil(r.URL.Path)
	defer freePath()
	referrer, freeReferrer := cStringOrNil(r.Referer())
	defer freeReferrer()

	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	ip, freeIP := cStringOrNil(host)
	defer freeIP()
	ua, freeUA := cStringOrNil(r.UserAgent())
	defer freeUA()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return errClosed
	}
	rc := C.fossh_pageview(c.ctx, path, referrer, ip, ua)
	return lastError(c.ctx, int32(rc))
}

// Event records a named action event. props may be nil; every key and
// value must be a plain string — that's the whole wire shape §8/P8
// allows, so anything else would just be rejected server-side anyway.
func (c *Client) Event(name string, value int64, props map[string]string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var cProps *C.char
	if len(props) > 0 {
		b, err := json.Marshal(props)
		if err != nil {
			return fmt.Errorf("fossh: marshaling props: %w", err)
		}
		cProps = C.CString(string(b))
		defer C.free(unsafe.Pointer(cProps))
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return errClosed
	}
	rc := C.fossh_event(c.ctx, cName, C.int64_t(value), cProps)
	return lastError(c.ctx, int32(rc))
}

// Timing records a named timing event, in milliseconds.
func (c *Client) Timing(name string, d time.Duration) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return errClosed
	}
	rc := C.fossh_timing(c.ctx, cName, C.int64_t(d.Milliseconds()))
	return lastError(c.ctx, int32(rc))
}

// Flush drains any spooled events for this process into the database
// immediately, rather than waiting for the next fossh-maintain/compactor
// cycle. Safe to call at shutdown so nothing gets stranded.
func (c *Client) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return errClosed
	}
	rc := C.fossh_flush(c.ctx)
	return lastError(c.ctx, int32(rc))
}

// Middleware returns net/http middleware that records a Pageview for
// every request before calling next. A recording failure is never
// surfaced as an HTTP error — telemetry must not be able to break the
// request it's observing — so check c.Pageview yourself if you need to
// react to it (e.g. from your own logging middleware).
func Middleware(c *Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = c.Pageview(r)
			next.ServeHTTP(w, r)
		})
	}
}
