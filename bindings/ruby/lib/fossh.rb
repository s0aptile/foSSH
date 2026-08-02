# frozen_string_literal: true

require_relative "fossh/version"
require_relative "fossh/client"
# `fossh/rack.rb` is intentionally not required here — it references
# `::Rack::Request`, and this gem has no hard dependency on Rack (only
# `bindings/ruby/fossh.gemspec`'s optional/dev usage does). Require it
# yourself (`require "fossh/rack"`) in an app that already has Rack
# loaded, same way the `use FoSSH::Rack, client: fossh` example in
# docs/INTEGRATION-ruby.md does.
