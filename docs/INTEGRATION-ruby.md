# Ruby integration

`bindings/ruby` (`FoSSH::Client`, gem `fossh`) wraps foSSH's C ABI using [`Fiddle`](https://docs.ruby-lang.org/en/master/Fiddle.html) — Ruby's standard library, not a native gem extension. No `mkmf`, no compiler needed to install this gem, on any Ruby that ships Fiddle (all supported versions do).

## Install

Not published to RubyGems yet (Open Alpha) — point your `Gemfile` at the path or git repo directly:

```ruby
gem "fossh", path: "vendor/fossh/bindings/ruby"
```

## Basic usage

```ruby
require "fossh"

fossh = FoSSH::Client.new(config: "/etc/fossh/fossh.toml", key: ENV["FOSSH_KEY"])
fossh.event("invoice.paid", value: 1)
```

`FoSSH::Client.new` raises (`FoSSH::LoadError` if `libfossh` itself couldn't be loaded, `FoSSH::Error` if a loaded library rejected the key or failed to initialize) rather than silently degrading — see `bindings/ruby/lib/fossh/client.rb`'s own comment for why that's the right default for a Ruby deployment specifically (you control the environment; a missing library is almost always a setup mistake worth surfacing immediately, not something to route around).

`FOSSH_LIB_PATH` (environment variable) overrides where `libfossh.so` is loaded from; defaults to searching the loader's normal path.

## Rack middleware

```ruby
require "fossh"
require "fossh/rack"

fossh = FoSSH::Client.new(config: "/etc/fossh/fossh.toml", key: ENV["FOSSH_KEY"])
use FoSSH::Rack, client: fossh
```

Records a `pageview` for every request, reading `path`/`referer`/`ip`/`user_agent` off the `Rack::Request`. A recording failure never turns into a 500 for the request it's observing — it's rescued and dropped inside the middleware itself.

## Rails

```ruby
# config/initializers/fossh.rb
require "fossh"
require "fossh/rack"

Rails.application.config.middleware.use FoSSH::Rack, client: FoSSH::Client.new(
  config: Rails.root.join("config", "fossh.toml").to_s,
  key: ENV.fetch("FOSSH_KEY")
)
```

To record a specific action rather than every request, call the same client directly from a controller:

```ruby
class OrdersController < ApplicationController
  def create
    order = Order.create!(order_params)
    Rails.application.config.fossh_client.event("order.placed", value: order.total_cents, props: { "currency" => order.currency })
    redirect_to order
  end
end
```

## Puma / Passenger: initialize the context *after* fork, not before

Both Puma (in clustered mode) and Passenger fork worker processes from a single master. A `fossh_ctx` created in the master **before** the fork is shared, in a broken way, across every forked worker — file descriptors and any internal locking state don't survive a `fork()` the way a fresh `fossh_init` call in each worker does.

Puma (`config/puma.rb`):

```ruby
before_fork do
  # do not create the FoSSH::Client here
end

on_worker_boot do
  Thread.current[:fossh] = FoSSH::Client.new(config: "/etc/fossh/fossh.toml", key: ENV["FOSSH_KEY"])
end
```

Passenger reads the same signal from its own `PhusionPassenger.on_event(:starting_worker_process)` hook — construct the client there, never at the top level of `config.ru` or an initializer that runs once in the master before Passenger forks. If you're not running a forking server (Puma in single mode, a non-forking Rack server), a plain initializer is fine — the fork hazard only exists where a fork actually happens after the master has already constructed something.

## Testing without a real Ruby toolchain

This binding was written and reviewed without a Ruby interpreter available in the authoring environment (no toolchain installed there) — see `DECISIONS.md` for that limitation. `bindings/ruby/test/fossh_test.rb` shells out to the `fossh` CLI the same way `bindings/go/fossh_test.go` does, and skips gracefully if the CLI isn't on `$PATH`.
