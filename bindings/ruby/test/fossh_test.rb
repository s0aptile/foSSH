# frozen_string_literal: true

# Exercises the accept/reject/rate-limit/wrong-key paths end to end
# against a real database, using the `fossh` CLI (assumed built and on
# $PATH, or reachable via $FOSSH_CLI_BIN) to `init`/`site create` a
# throwaway environment — the same pattern bindings/go/fossh_test.go
# uses, just driven from Ruby.
#
# Requires `libfossh.so` findable via `$FOSSH_LIB_PATH` (or already on
# the loader's default search path) — not runnable in an environment
# without a Ruby interpreter, which is the state this was authored in;
# see DECISIONS.md for that limitation.

require "minitest/autorun"
require "English"
require "fileutils"
require "tmpdir"
require_relative "../lib/fossh"

class FosshIntegrationTest < Minitest::Test
  def cli_bin
    bin = ENV["FOSSH_CLI_BIN"]
    return bin if bin && !bin.empty?

    path = ENV["PATH"].split(File::PATH_SEPARATOR).map { |dir| File.join(dir, "fossh") }.find { |p| File.executable?(p) }
    skip "fossh CLI binary not found on $PATH and $FOSSH_CLI_BIN not set; skipping integration test" unless path
    path
  end

  def setup_site(allow: [])
    bin = cli_bin
    dir = Dir.mktmpdir("fossh-ruby-test")
    data_dir = File.join(dir, "data")

    init_out = `#{bin} init --dir #{data_dir} 2>&1`
    raise "fossh init failed:\n#{init_out}" unless $CHILD_STATUS.success?

    config_path = File.join(dir, "fossh.toml")
    contents = File.read(config_path)
    patched = contents.sub('mode = "spool"', 'mode = "direct"')
    patched += "\n[rate_limit]\nper_sec = 2\nburst = 2\n"
    File.write(config_path, patched)
    File.chmod(0o600, config_path)

    args = ["site", "create", "testsite"]
    args += ["--allow", allow.join(",")] unless allow.empty?
    out = IO.popen({ "FOSSH_CONFIG" => config_path }, [bin] + args, err: %i[child out], &:read)
    raise "fossh site create failed:\n#{out}" unless $CHILD_STATUS.success?

    write_key = out.lines.map(&:strip).find { |line| line.start_with?("fossh_testsite_") }
    raise "could not find write key in output:\n#{out}" unless write_key

    [config_path, write_key]
  end

  def test_pageview_and_event_accept_and_reject
    config_path, key = setup_site(allow: %w[pageview signup])
    client = FoSSH::Client.new(config: config_path, key: key)

    assert client.event("signup", value: 1)

    err = assert_raises(FoSSH::Error) { client.timing("db.query", 0) }
    assert_equal "REJECTED", err.name, "an unallowlisted name must be rejected"
  ensure
    client&.close
  end

  def test_event_with_allowlisted_prop
    config_path, key = setup_site(allow: %w[checkout tier])
    client = FoSSH::Client.new(config: config_path, key: key)

    assert client.event("checkout", value: 1, props: { "tier" => "pro" })
  ensure
    client&.close
  end

  def test_rate_limiting
    config_path, key = setup_site(allow: %w[pageview])
    client = FoSSH::Client.new(config: config_path, key: key)

    # burst = 2 (patched into the config in setup_site).
    assert client.event("pageview", value: 1)
    assert client.event("pageview", value: 1)

    err = assert_raises(FoSSH::Error) { client.event("pageview", value: 1) }
    assert_equal "RATE_LIMITED", err.name
  ensure
    client&.close
  end

  def test_wrong_key_is_unauthorized
    config_path, = setup_site(allow: %w[pageview])
    wrong_key = "fossh_testsite_#{"A" * 52}"

    # fossh_set_key failing during construction surfaces as FoSSH::Error
    # (a real, loaded fossh_ctx that rejected the key) — distinct from
    # FoSSH::LoadError, which is specifically "the library/context
    # itself never came up at all."
    err = assert_raises(FoSSH::Error) do
      FoSSH::Client.new(config: config_path, key: wrong_key)
    end
    assert_equal "UNAUTHORIZED", err.name
  end
end
