require "json"
require_relative "binding"

module FoSSH

  class Error < StandardError
    attr_reader :code, :name

    def initialize(code, name)
      @code = code
      @name = name
      super("fossh: #{name} (#{code})")
    end
  end

  class LoadError < StandardError; end

  class Client
    def initialize(config: nil, key: nil)
      raise LoadError, "the 'ffi' extension is not usable in this Ruby (Fiddle failed to load libfossh)" unless Binding::AVAILABLE

      @mutex = Mutex.new
      ctx = Binding.fossh_init(config)
      raise LoadError, "fossh_init failed (bad config path, or the data/salt directory could not be opened)" if ctx.null?

      @ctx = ctx

      @ctx_cell = [ctx]
      ObjectSpace.define_finalizer(self, self.class.finalizer(@ctx_cell))

      return if key.nil?

      rc = Binding.fossh_set_key(@ctx, key)
      raise_last_error(rc) unless rc.zero?
    end

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

    def flush
      with_ctx do |ctx|
        rc = Binding.fossh_flush(ctx)
        raise_last_error(rc) unless rc.zero?
      end
      true
    end

    def close
      @mutex.synchronize do
        ctx = @ctx_cell[0]
        next if ctx.nil?

        Binding.fossh_free(ctx)
        @ctx_cell[0] = nil
        @ctx = nil
      end
    end

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
