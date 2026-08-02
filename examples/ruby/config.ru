# Runnable example for the Ruby binding (bindings/ruby). Run with
# `rackup` (or `bundle exec rackup`) per docs/INTEGRATION-ruby.md — set
# FOSSH_LIB_PATH if libfossh.so isn't on the loader's default path, and
# FOSSH_CONFIG/FOSSH_KEY for a site already created with `fossh site create`.
require "rack"
require_relative "../../bindings/ruby/lib/fossh"
require_relative "../../bindings/ruby/lib/fossh/rack"

fossh = FoSSH::Client.new(
  config: ENV["FOSSH_CONFIG"], # nil is fine too — same search order as the CLI
  key: ENV["FOSSH_KEY"]
)
at_exit { fossh.flush }

app = ::Rack::Builder.new do
  use FoSSH::Rack, client: fossh

  map "/signup" do
    run lambda { |_env|
      fossh.event("signup", value: 1, props: { "plan" => "pro" })
      [200, { "content-type" => "text/plain" }, ["signed up\n"]]
    }
  end

  map "/" do
    run lambda { |_env| [200, { "content-type" => "text/plain" }, ["hello from an app with foSSH wired in\n"]] }
  end
end

run app
