# frozen_string_literal: true

require "fiddle"
require "fiddle/import"

module FoSSH
  # Loads libfossh (§11) via Fiddle — pure stdlib, no native gem
  # compilation, no `mkmf`, so this works on any Ruby with no build
  # step at all. Mirrors the same small, hand-maintained subset of
  # `include/fossh.h` every other dynamic-FFI binding in this repo
  # keeps (see `bindings/php/src/Client.php`'s `FFI::cdef()` string) —
  # `Fiddle::Importer`'s `extern` parser is a simplified C subset, not a
  # real preprocessor, so the generated header itself still can't be
  # fed in directly. Keep this in sync by hand with `include/fossh.h`
  # when the C ABI changes.
  module Binding
    extend Fiddle::Importer

    LIB_PATH = ENV["FOSSH_LIB_PATH"] || "libfossh.so"

    # Fiddle's own type vocabulary doesn't include the stdint-style
    # aliases the real header uses — these map them onto Fiddle's
    # primitive C types, which is exactly what `typealias` is for, and
    # is correct on every platform this project actually targets
    # (Linux/macOS/BSD, all LP64: `long long` is an unambiguous 8 bytes
    # on all of them, and POSIX defines `size_t` as `unsigned long`).
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
