module Virtual : sig
  type t
  val of_int64 : int64 -> t
  val to_int64 : t -> int64
end

module Physical : sig
  type t
  val of_int64 : int64 -> t
  val to_int64 : t -> int64
end

module Machine : sig
  type t
  val of_int64 : int64 -> t
  val to_int64 : t -> int64
end

val compare : int64 -> int64 -> int
val hex : int64 -> string
val parse : string -> int64
val bit : int64 -> int -> bool
val mask : int -> int64
val align : int64 -> int -> int64
val canonical : int64 -> bool
