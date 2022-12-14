sh4d0wup=cargo run --release --
plots := $(patsubst contrib/%.yaml,build/%.tar.zst,$(wildcard contrib/plot-*.yaml))

all: $(plots)

build/%.tar.zst: contrib/%.yaml
	@mkdir -p build/
	$(sh4d0wup) build -o $@ $^
