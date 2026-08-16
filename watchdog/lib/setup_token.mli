type error = Io_error of string | Hash_error of string

val describe_error : error -> string

val ensure : token_path:string -> operator_key_dir:string -> (unit, error) result

val verify : string -> bool

val burn : unit -> (unit, error) result
