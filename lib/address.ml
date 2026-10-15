module Virtual = struct
  type t = int64
  let of_int64 x = x
  let to_int64 x = x
end

module Physical = struct
  type t = int64
  let of_int64 x = x
  let to_int64 x = x
end

module Machine = struct
  type t = int64
  let of_int64 x = x
  let to_int64 x = x
end

let compare = Int64.unsigned_compare
let hex x = Printf.sprintf "0x%016Lx" x

let parse s =
  if String.length s = 0 || s.[0] = '-' || s.[0] = '+' then
    invalid_arg ("invalid unsigned address: " ^ s);
  try Int64.of_string (if String.starts_with ~prefix:"0x" s then s else "0u" ^ s)
  with Failure _ -> invalid_arg ("invalid unsigned address: " ^ s)

let bit x n = Int64.logand x (Int64.shift_left 1L n) <> 0L
let mask n = Int64.pred (Int64.shift_left 1L n)
let align x n = Int64.logand x (Int64.lognot (mask n))
let canonical x =
  let high = Int64.shift_right x 47 in
  high = 0L || high = -1L
