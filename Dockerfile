FROM rust:1-alpine3.16
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add --no-cache musl-dev openssl-dev shared-mime-info xz-dev zstd-dev
WORKDIR /app
COPY ./ /app
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/sh4d0wup .
RUN strip sh4d0wup

FROM alpine:3.16
RUN apk add --no-cache libgcc openssl shared-mime-info xz zstd-libs
COPY --from=0 /app/sh4d0wup /usr/bin
ENV SH4D0WUP_BIND=0.0.0.0:8080
ENTRYPOINT ["sh4d0wup"]
