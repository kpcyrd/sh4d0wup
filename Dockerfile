FROM rust:1-alpine3.17
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add clang-dev musl-dev nettle-dev pcsc-lite-dev openssl-dev shared-mime-info xz-dev zstd-dev
WORKDIR /app
COPY ./ /app
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/sh4d0wup .
RUN strip sh4d0wup

FROM alpine:3.17
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add clang-libs gcc libgcc linux-headers musl-dev nettle pcsc-lite-libs openssl shared-mime-info xz zstd-libs
COPY --from=0 /app/sh4d0wup /usr/bin
ENTRYPOINT ["sh4d0wup"]
