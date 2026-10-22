val available : unit -> bool
val capture : domid:int -> vcpu:int -> pause:bool -> features:Model.features ->
  root:int64 option -> max_pages:int -> Capture.t
