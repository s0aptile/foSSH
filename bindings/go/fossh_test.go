//go:build !nofossh

package fossh_test

// Exercises the accept/reject/rate-limit paths end to end against a real
// database, using the `fossh` CLI (assumed built and on $PATH, or
// reachable via $FOSSH_CLI_BIN) to `init`/`site create` a throwaway
// environment — the same setup this whole repository's other
// integration tests use, just driven from Go instead of shelling out
// from a Rust test.
//
// Requires CGO_CFLAGS/CGO_LDFLAGS pointed at this repo's include/ and a
// built libfossh (see docs/INTEGRATION-go.md) — not runnable in an
// environment without a Go toolchain, which is the state this was
// authored in; see DECISIONS.md for that limitation.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	fossh "github.com/s0aptile/fossh-go"
)

func cliBin(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("FOSSH_CLI_BIN"); bin != "" {
		return bin
	}
	bin, err := exec.LookPath("fossh")
	if err != nil {
		t.Skip("fossh CLI binary not found on $PATH and $FOSSH_CLI_BIN not set; skipping integration test")
	}
	return bin
}

type testSite struct {
	configPath string
	writeKey   string
}

func setupSite(t *testing.T, allow []string) testSite {
	t.Helper()
	bin := cliBin(t)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")

	initCmd := exec.Command(bin, "init", "--dir", dataDir)
	initCmd.Dir = dir
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("fossh init: %v\n%s", err, out)
	}

	configPath := filepath.Join(dir, "fossh.toml")
	// Direct mode + a tiny burst so the rate-limit test doesn't need
	// hundreds of calls to exhaust it.
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading generated fossh.toml: %v", err)
	}
	patched := strings.Replace(string(contents), `mode = "spool"`, `mode = "direct"`, 1)
	patched += "\n[rate_limit]\nper_sec = 2\nburst = 2\n"
	if err := os.WriteFile(configPath, []byte(patched), 0o600); err != nil {
		t.Fatalf("patching fossh.toml: %v", err)
	}

	args := []string{"site", "create", "testsite"}
	if len(allow) > 0 {
		args = append(args, "--allow", strings.Join(allow, ","))
	}
	createCmd := exec.Command(bin, args...)
	createCmd.Env = append(os.Environ(), "FOSSH_CONFIG="+configPath)
	out, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fossh site create: %v\n%s", err, out)
	}

	var writeKey string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "fossh_testsite_") {
			writeKey = line
			break
		}
	}
	if writeKey == "" {
		t.Fatalf("could not find write key in output:\n%s", out)
	}

	return testSite{configPath: configPath, writeKey: writeKey}
}

func TestPageviewAndEventAccept(t *testing.T) {
	site := setupSite(t, []string{"pageview", "signup"})
	client, err := fossh.New(fossh.Config{Path: site.configPath, Key: site.writeKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if err := client.Event("signup", 1, nil); err != nil {
		t.Errorf("Event(signup): %v", err)
	}
	if err := client.Timing("db.query", 0); err == nil {
		t.Errorf("Timing(db.query) with an unallowlisted name should have been rejected")
	} else if fe, ok := err.(*fossh.Error); !ok || fe.Name != "REJECTED" {
		t.Errorf("expected a REJECTED *fossh.Error, got %v (%T)", err, err)
	}
}

func TestEventWithProps(t *testing.T) {
	site := setupSite(t, []string{"checkout", "tier"})
	client, err := fossh.New(fossh.Config{Path: site.configPath, Key: site.writeKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	if err := client.Event("checkout", 1, map[string]string{"tier": "pro"}); err != nil {
		t.Errorf("Event with allowlisted prop: %v", err)
	}
}

func TestRateLimiting(t *testing.T) {
	site := setupSite(t, []string{"pageview"})
	client, err := fossh.New(fossh.Config{Path: site.configPath, Key: site.writeKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	// burst = 2 (patched into the config in setupSite).
	if err := client.Event("pageview", 1, nil); err != nil {
		t.Fatalf("first event within burst: %v", err)
	}
	if err := client.Event("pageview", 1, nil); err != nil {
		t.Fatalf("second event within burst: %v", err)
	}
	err = client.Event("pageview", 1, nil)
	if err == nil {
		t.Fatal("third event should have exceeded the burst of 2")
	}
	if fe, ok := err.(*fossh.Error); !ok || fe.Name != "RATE_LIMITED" {
		t.Errorf("expected a RATE_LIMITED *fossh.Error, got %v (%T)", err, err)
	}
}

func TestWrongKeyIsUnauthorized(t *testing.T) {
	site := setupSite(t, []string{"pageview"})
	_, err := fossh.New(fossh.Config{Path: site.configPath, Key: "fossh_testsite_" + strings.Repeat("A", 52)})
	if err == nil {
		t.Fatal("expected New to fail with a wrong key")
	}
	if fe, ok := err.(*fossh.Error); !ok || fe.Name != "UNAUTHORIZED" {
		t.Errorf("expected an UNAUTHORIZED *fossh.Error, got %v (%T)", err, err)
	}
}

func TestPropsMarshalAsJSONObjectOfStrings(t *testing.T) {
	// Sanity check on our own assumption about the wire shape fossh_event
	// expects for props_json — not calling into libfossh here.
	b, err := json.Marshal(map[string]string{"a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"a":"b"}` {
		t.Errorf("unexpected JSON shape: %s", b)
	}
}
