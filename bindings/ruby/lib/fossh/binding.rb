require "fiddle"
require "fiddle/import"

module FoSSH

  module Binding
    extend Fiddle::Importer

    LIB_PATH = ENV["FOSSH_LIB_PATH"] || "libfossh.so"

    typealias "int32_t", "int"
    typealias "int64_t", "long long"
    typealias "uint32_t", "unsigned int"
    typealias "size_t", "unsigned long"

    AVAILABLE =
      begin
        dlload LIB_PATH

        extern "uint32_t fossh_abi_version()"
        extern "void *fossh_init(const char *)"
        extern "void fossh_free(void *)"
        extern "int32_t fossh_last_error(const void *, char *, size_t)"
        extern "int32_t fossh_set_key(void *, const char *)"
        extern "int32_t fossh_pageview(void *, const char *, const char *, const char *, const char *)"
        extern "int32_t fossh_event(void *, const char *, int64_t, const char *)"
        extern "int32_t fossh_timing(void *, const char *, int64_t)"
        extern "int32_t fossh_flush(void *)"

        true
      rescue Fiddle::DLError
        false
      end
  end
end
