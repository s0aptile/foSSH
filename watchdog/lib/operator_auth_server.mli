type config = { socket_path : string; operator_key_dir : string }

val run : ?connection_timeout_seconds:float -> config -> (unit, string) result
