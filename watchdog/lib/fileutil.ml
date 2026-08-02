let read_all_bytes (path : string) : string =
  let ic = open_in_bin path in
  let len = in_channel_length ic in
  let content = really_input_string ic len in
  close_in ic;
  content
