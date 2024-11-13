sh4d0wup=cargo run --release --
plots := $(patsubst contrib/%.yaml,build/%.tar.zst,$(wildcard contrib/plot-*.yaml))

all: $(plots)

build/%.tar.zst: contrib/%.yaml
	@mkdir -p build/
	$(sh4d0wup) build -o $@ $^

build:
	repro-env build -- sh -c ' \
	RUSTFLAGS="-C strip=symbols" \
	SOURCE_DATE_EPOCH=0 \
	cargo build --target x86_64-unknown-linux-musl --release --no-default-features -F vendored'

.PHONY: build
