# frozen_string_literal: true

require "json"
require_relative "binding"

module FoSSH
  # Raised by every `Client` method on a non-zero `fossh_*` return code,
  # or if the client couldn't be constructed at all. `name` is one of a
  # fixed, small set of strings `fossh_last_error` (§11) maps every
  # variant to — never anything derived from caller-supplied data, so
  # it's always safe to log. Unlike the Go binding, this isn't a
  # graceful-degradation point: if `libfossh` can't be loaded or
  # `fossh_init` fails, `Client.new` raises rather than returning a
  # silently-inert object — a Ruby deployment controls its own
  # environment (unlike PHP's shared-hosting case, which is why that
  # binding's story is different), so a missing/misconfigured library
  # is much more likely a setup mistake worth surfacing loudly than
  # something to route around.
  class Error < StandardError
    attr_reader :code, :name

    def initialize(code, name)
      @code = code
      @name = name
      super("fossh: #{name} (#{code})")
    end
  end

  # Raised specifically when `libfossh` itself couldn't be loaded
  # (`Fiddle::DLError`) — distinct from `Error`, which covers a loaded
  # library returning a real `fossh_err_t` failure code.
  class LoadError < StandardError; end

  # Wraps one `fossh_ctx` (§11). Not fork-safe to share across a fork
  # boundary — construct one `Client` per worker process, after fork,
  # never before (the Puma/Passenger note in `docs/INTEGRATION-ruby.md`
  # and §12 of the implementation spec).
  class Client
    def initialize(config: nil, key: nil)
      raise LoadError, "the 'ffi' extension is not usable in this Ruby (Fiddle failed to load libfossh)" unless Binding::AVAILABLE

      @mutex = Mutex.new
      ctx = Binding.fossh_init(config)
      raise LoadError, "fossh_init failed (bad config path, or the data/salt directory could not be opened)" if ctx.null?

      @ctx = ctx
      # A one-element mutable cell, shared with the finalizer proc
      # below — not just `@ctx` captured directly, because a GC
      # finalizer's closure can't see this instance's ivars change
      # later. Without this indirection, an explicit `close` (which
      # frees the context and nils `@ctx`) wouldn't stop the finalizer
      # from *also* calling `fossh_free` on the same already-freed
      # pointer once the object is eventually collected — a double
      # free. `close` mutates the cell so both sides agree.
      @ctx_cell = [ctx]
      ObjectSpace.define_finalizer(self, self.class.finalizer(@ctx_cell))

      return if key.nil?

      rc = Binding.fossh_set_key(@ctx, key)
      raise_last_error(rc) unless rc.zero?
    end

    # Records a page view. `request` may be any object responding to
    # `#path`, `#referer`, `#ip`, and `#user_agent` — a `Rack::Request`
    # already does (see `fossh/rack.rb`). May be omitted to record a
    # pageview with no path/referrer/IP/UA context.
    def pageview(request = nil)
      path = safe_call(request, :path)
      referrer = safe_call(request, :referer)
      ip = safe_call(request, :ip)
      user_agent = safe_call(request, :user_agent)

      with_ctx do |ctx|
        rc = Binding.fossh_pageview(ctx, path, referrer, ip, user_agent)
        raise_last_error(rc) unless rc.zero?
      end
      true
    end

    # @param props [Hash<String,String>, nil]
    def event(name, value: 1, props: nil)
      props_json = props.nil? ? nil : JSON.generate(props)
      with_ctx do |ctx|
        rc = Binding.fossh_event(ctx, name, value, props_json)
        raise_last_error(rc) unless rc.zero?
      end
      true
    end

    def timing(name, millis)
      with_ctx do |ctx|
        rc = Binding.fossh_timing(ctx, name, millis)
        raise_last_error(rc) unless rc.zero?
      end
      true
    end

    # Drains any spooled events for this process into the database
    # immediately. Safe to call at shutdown so nothing gets stranded.
    def flush
      with_ctx do |ctx|
        rc = Binding.fossh_flush(ctx)
        raise_last_error(rc) unless rc.zero?
      end
      true
    end

    # Safe to call more than once. Also runs automatically at GC via a
    # finalizer, but calling this explicitly (e.g. at shutdown) is
    # still the better path — GC timing is never guaranteed.
    def close
      @mutex.synchronize do
        ctx = @ctx_cell[0]
        next if ctx.nil?

        Binding.fossh_free(ctx)
        @ctx_cell[0] = nil
        @ctx = nil
      end
    end

    # A class method, not an instance method — the `private` keyword
    # below has no effect on `def self.x` definitions, so this is kept
    # above it on purpose rather than implying otherwise. Takes the
    # shared mutable cell, not a bare pointer — see the comment in
    # `initialize` on why.
    def self.finalizer(ctx_cell)
      proc do
        ctx = ctx_cell[0]
        Binding.fossh_free(ctx) if ctx && !ctx.null?
        ctx_cell[0] = nil
      end
    end

    private

    def with_ctx
      @mutex.synchronize do
        raise Error.new(-1, "INTERNAL") if @ctx.nil?

        yield @ctx
      end
    end

    def safe_call(obj, method)
      return nil if obj.nil? || !obj.respond_to?(method)

      value = obj.public_send(method)
      value.nil? || value.to_s.empty? ? nil : value.to_s
    end

    def raise_last_error(code)
      buf = "\x00" * 64
      Binding.fossh_last_error(@ctx, buf, buf.bytesize)
      name = buf.unpack1("Z*")
      raise Error.new(code, name)
    end
  end
end
