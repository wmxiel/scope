type t = Null | Bool of bool | Int of int | String of string | List of t list | Object of (string * t) list

let string s = String s
let hex x = String (Address.hex x)
let option f = function None -> Null | Some x -> f x

let rec output channel = function
  | Null -> output_string channel "null"
  | Bool b -> output_string channel (string_of_bool b)
  | Int n -> output_string channel (string_of_int n)
  | String s ->
      output_char channel '"';
      String.iter (function
        | '"' -> output_string channel "\\\""
        | '\\' -> output_string channel "\\\\"
        | '\n' -> output_string channel "\\n"
        | '\r' -> output_string channel "\\r"
        | '\t' -> output_string channel "\\t"
        | c when Char.code c < 32 || Char.code c > 126 ->
            Printf.fprintf channel "\\u%04x" (Char.code c)
        | c -> output_char channel c) s;
      output_char channel '"'
  | List values ->
      output_char channel '[';
      List.iteri (fun i value -> if i > 0 then output_char channel ','; output channel value) values;
      output_char channel ']'
  | Object fields ->
      output_char channel '{';
      List.iteri (fun i (key, value) ->
        if i > 0 then output_char channel ',';
        output channel (String key);
        output_char channel ':';
        output channel value) fields;
      output_char channel '}'

let print value = output stdout value; output_char stdout '\n'
