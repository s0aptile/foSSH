# frozen_string_literal: true

require_relative "lib/fossh/version"

Gem::Specification.new do |spec|
  spec.name = "fossh"
  spec.version = FoSSH::VERSION
  spec.summary = "Ruby binding for foSSH (privacy-preserving, embeddable telemetry) via Fiddle."
  spec.description = "Pure-stdlib Fiddle wrapper around foSSH's C ABI (libfossh) plus a Rack " \
                      "middleware. No native gem compilation, no mkmf."
  spec.authors = ["$0aptile"]
  spec.homepage = "https://github.com/s0aptile/foSSH"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7"

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.metadata = {
    "source_code_uri" => "https://github.com/s0aptile/foSSH",
    "rubygems_mfa_required" => "true"
  }
end
