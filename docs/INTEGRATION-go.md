# Go integration

`bindings/go` (`github.com/s0aptile/fossh-go`) is a thin cgo wrapper around foSSH's C ABI (`libfossh`, §11).

## Install

Not published yet (Open Alpha) — a `replace` directive pointing at this repository, or vendoring, until it's tagged:

```
go mod edit -replace github.com/s0aptile/fossh-go=../path/to/fossh/bindings/go
```

## Build requirements

cgo needs to find `fossh.h` and link against `libfossh`:

```
export CGO_CFLAGS="-I/path/to/fossh/include"
export CGO_LDFLAGS="-L/path/to/fossh/lib -lfossh"
export LD_LIBRARY_PATH="/path/to/fossh/lib:$LD_LIBRARY_PATH"   # or install libfossh.so to a standard loader path
```

For a fully static Go binary, link `libfossh.a` instead and skip `LD_LIBRARY_PATH` entirely — see `scripts/build-release.sh` for how this project builds both.

## Basic usage

```go
package main

import (
	"log"
	"net/http"
	"os"

	fossh "github.com/s0aptile/fossh-go"
)

func main() {
	client, err := fossh.New(fossh.Config{
		Path: os.Getenv("FOSSH_CONFIG"),
		Key:  os.Getenv("FOSSH_KEY"),
	})
	if err != nil {
		log.Fatalf("fossh.New: %v", err)
	}
	defer client.Close()
	defer client.Flush()

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		if err := client.Event("signup", 1, nil); err != nil {
			log.Printf("fossh.Event: %v", err)
		}
	})

	// One line to adopt: every request through mux gets a Pageview.
	handler := fossh.Middleware(client)(mux)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

Runnable version: `examples/go/main.go`.

## Dropping telemetry entirely: `-tags nofossh`

```
go build -tags nofossh ./...
```

Compiles every exported call in this package to a no-op with **zero cgo dependency** — no `libfossh` needed at build or link time at all. Every call site keeps working unchanged; `fossh.New` always succeeds and returns a client whose methods do nothing. Useful for a build that must not depend on cgo (cross-compilation without a C toolchain for the target, `CGO_ENABLED=0` environments, etc.) without touching application code.

## Errors

Every method returns `*fossh.Error` on a non-zero `fossh_*` result, with a fixed `.Name` string (`"REJECTED"`, `"RATE_LIMITED"`, `"UNAUTHORIZED"`, ...) — never anything derived from caller-supplied data, so it's always safe to log directly:

```go
if err := client.Event("checkout", 1, nil); err != nil {
	var fe *fossh.Error
	if errors.As(err, &fe) && fe.Name == "RATE_LIMITED" {
		// back off, don't retry immediately
	}
}
```

## Concurrency

`*fossh.Client` is safe for concurrent use from multiple goroutines — `fossh_ctx` is `Send + Sync` on the Rust side (§11), and `Client.Close` additionally guards against a concurrent call racing an already-freed pointer.

## Testing without a real Go toolchain

This binding was written and reviewed without a Go toolchain available in the authoring environment — see `DECISIONS.md` for that limitation. `bindings/go/fossh_test.go` shells out to the `fossh` CLI to set up a throwaway site per test and skips gracefully if it isn't on `$PATH`/`$FOSSH_CLI_BIN`.
