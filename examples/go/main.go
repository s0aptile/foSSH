// Runnable example for the Go binding (bindings/go). Build and run per
// docs/INTEGRATION-go.md — needs CGO_CFLAGS/CGO_LDFLAGS pointed at a
// built libfossh, and a site already created with `fossh site create`.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	fossh "github.com/s0aptile/fossh-go"
)

func main() {
	client, err := fossh.New(fossh.Config{
		Path: os.Getenv("FOSSH_CONFIG"), // empty is fine too — same search order as the CLI
		Key:  os.Getenv("FOSSH_KEY"),
	})
	if err != nil {
		log.Fatalf("fossh.New: %v", err)
	}
	defer client.Close()
	defer func() {
		if err := client.Flush(); err != nil {
			log.Printf("fossh.Flush at shutdown: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello from an app with foSSH wired in")
	})
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		if err := client.Event("signup.completed", 1, map[string]string{"plan": "pro"}); err != nil {
			log.Printf("fossh.Event(signup.completed): %v", err)
		}
		fmt.Fprintln(w, "signed up")
	})

	// One line to adopt: every request through mux gets a Pageview.
	handler := fossh.Middleware(client)(mux)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
