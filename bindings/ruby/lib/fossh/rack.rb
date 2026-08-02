# frozen_string_literal: true

module FoSSH
  # Records a Pageview for every request. `use FoSSH::Rack, client: fossh`.
  #
  # A recording failure is never surfaced as a Rack error response —
  # telemetry must not be able to break the request it's observing —
  # so this rescues `FoSSH::Error`/`FoSSH::LoadError` itself. Call
  # `client.pageview` yourself from your own logging/error-tracking
  # middleware if you need to react to a failure instead of silently
  # swallowing it here.
  class Rack
    def initialize(app, client:)
      @app = app
      @client = client
    end

    def call(env)
      request = ::Rack::Request.new(env)
      begin
        @client.pageview(request)
      rescue FoSSH::Error, FoSSH::LoadError
        # never break the request being observed
      end
      @app.call(env)
    end
  end
end
