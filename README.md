# sh4d0wup

```
% docker run -it --rm ghcr.io/kpcyrd/sh4d0wup:edge -h
Usage: sh4d0wup [OPTIONS] <COMMAND>

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
