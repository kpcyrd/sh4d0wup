# syntax=docker/dockerfile:1.4

FROM rust:1-alpine3.17 as build
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add clang-dev musl-dev nettle-dev pcsc-lite-dev openssl-dev shared-mime-info xz-dev zstd-dev && \
    rm /etc/apk/cache
WORKDIR /app
COPY ./ /app
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/sh4d0wup .
RUN strip sh4d0wup

FROM alpine:3.17 as basic
# install dependencies
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add clang-libs libgcc nettle pcsc-lite-libs openssl shared-mime-info xz zstd-libs && \
    rm /etc/apk/cache

FROM basic as smol
# copy the binary
COPY --from=0 /app/sh4d0wup /usr/bin
ENTRYPOINT ["sh4d0wup"]

FROM basic as full
# install more dependencies
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add fuse-overlayfs gcc go linux-headers musl-dev podman rustup && \
    rm /etc/apk/cache
RUN rustup-init -y && ln -vs /root/.cargo/bin/rustc /usr/bin
# do some configuration to enable nested rootless podman
RUN adduser -Du 1000 podman && \
    printf "podman:1:999\npodman:1001:64535\n" | tee /etc/subuid | tee /etc/subgid > /dev/null
COPY <<EOF /etc/containers/storage.conf
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options]
additionalimagestores = []
pull_options = {enable_partial_images = "false", use_hard_links = "false", ostree_repos=""}
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev,fsync=0"
[storage.options.thinpool]
EOF
COPY <<EOF /etc/containers/containers.conf
[containers]
netns="host"
userns="host"
ipcns="host"
utsns="host"
cgroupns="host"
cgroups="disabled"
log_driver = "k8s-file"
[engine]
cgroup_manager = "cgroupfs"
events_logger="file"
runtime="crun"
EOF
# copy the binary
COPY --from=0 /app/sh4d0wup /usr/bin
ENTRYPOINT ["sh4d0wup"]
