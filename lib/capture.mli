type t
val make : Model.context -> (Address.Physical.t * (string, string) result) list -> t
val context : t -> Model.context
val read : t -> Model.reader
val pages : t -> int
val with_root : t -> int64 -> t
val collect : ?max_pages:int -> Model.context -> Model.reader -> t
val complete : t -> bool
val save : string -> t -> unit
val load : string -> t
val import : source:string -> string -> t
