module FoSSH

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

      end
      @app.call(env)
    end
  end
end
