.PHONY: all check guest xen clean

all:
	dune build @all

check:
	dune runtest
	$(MAKE) -C guest check

guest: all
	$(MAKE) -C guest check

xen:
	python3 test/xen.py $(XEN_INCLUDE)

clean:
	dune clean
	$(MAKE) -C guest clean
