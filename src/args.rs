use crate::errors::*;
use crate::plot::{PkgFilter, PkgPatchValues};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::io::stdout;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Args {
    /// Turn debugging information on
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    Bait(Bait),
    #[command(subcommand)]
    Infect(Infect),
    #[command(subcommand)]
    Tamper(Tamper),
    #[command(subcommand)]
    Keygen(Keygen),
    #[command(subcommand)]
    Sign(Sign),
    Build(Build),
    Check(Check),
    Completions(Completions),
}

/// Start a malicious update server
#[derive(Debug, Clone, Parser)]
pub struct Bait {
    /// Address to bind to
    #[arg(
        short = 'B',
        long,
        env = "SH4D0WUP_BIND",
        default_value = "0.0.0.0:1337"
    )]
    pub bind: SocketAddr,
    /*
    /// The upstream server to reverse proxy to
    #[arg(short = 'U', long)]
    pub upstream: Option<String>,
    /// Do not modify Host: and similar headers
    #[arg(short = 'K', long)]
    pub keep_headers: bool,
    */
    /// Path to certificate file (enables https)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,
    /// Path to certificate private key (if not bundled with the cert)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
    /// Path to the plot to execute
    pub plot: String,
}

/// High level tampering, inject additional commands into a package
#[derive(Debug, Subcommand)]
pub enum Infect {
    Pacman(InfectPacmanPkg),
    Deb(InfectDebPkg),
    Oci(InfectOci),
    Apk(InfectApkPkg),
    Elf(InfectElf),
}

/// Infect a pacman package
#[derive(Debug, Clone, Parser)]
pub struct InfectPacmanPkg {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Update a key in .PKGINFO (a key can be set multiple times)
    #[arg(long)]
    pub set: Vec<String>,
    /// The command to inject into the package that's executed once during install
    #[arg(short = 'c', long)]
    pub payload: Option<String>,
}

/// Infect a .deb package
#[derive(Debug, Clone, Parser)]
pub struct InfectDebPkg {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Update a key in ./control
    #[arg(long)]
    pub set: Vec<String>,
    /// The command to inject into the package that's executed once during install
    #[arg(short = 'c', long)]
    pub payload: Option<String>,
}

/// Infect an OCI container image .tar
#[derive(Debug, Clone, Parser)]
pub struct InfectOci {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Configure the length of the entrypoint hash, longer names are less likely to collide but more noticable
    #[arg(long, default_value = "14")]
    pub entrypoint_hash_len: usize,
    /// Write the entrypoint to a fixed location instead of a random one
    #[arg(long)]
    pub entrypoint: Option<String>,
    /// The command to inject into the package that's executed once during install
    #[arg(short = 'c', long)]
    pub payload: Option<String>,
}

/// Infect an alpine package
#[derive(Debug, Clone, Parser)]
pub struct InfectApkPkg {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Update a key in .PKGINFO (a key can be set multiple times)
    #[arg(long)]
    pub set: Vec<String>,
    /// Path to the key to sign the package with
    #[arg(short = 'S', long)]
    pub signing_key: String,
    /// The name of the signing key (eg. alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub)
    #[arg(short = 'N', long)]
    pub signing_key_name: String,
    /// The command to inject into the package that's executed once during install
    #[arg(short = 'c', long)]
    pub payload: Option<String>,
}

/// Infect an elf executable
#[derive(Debug, Clone, Parser)]
pub struct InfectElf {
    /// The input executable to bind to
    pub path: PathBuf,
    /// Where to write the modified executable to
    pub out: PathBuf,
    /// The command to inject into the binary
    #[arg(short = 'c', long)]
    pub payload: String,
}

/// Low level tampering, patch a package database to add malicious packages, cause updates or influence dependency resolution
#[derive(Debug, Subcommand)]
pub enum Tamper {
    PacmanDb(TamperPacman),
    AptRelease(TamperAptRelease),
    AptPackageList(TamperAptPackageList),
}

#[derive(Debug, Clone, Parser)]
pub struct TamperPackageDatabaseConfig {
    #[arg(long)]
    pub filter: Vec<PkgFilter>,
    #[arg(long)]
    pub set: Vec<PkgPatchValues<Vec<String>>>,
    #[arg(long)]
    pub exclude: Vec<PkgFilter>,
}

/// Patch a pacman database
#[derive(Debug, Clone, Parser)]
pub struct TamperPacman {
    /// The input database to modify
    pub path: String,
    /// Path to write the patched database to
    pub out: String,
    #[clap(flatten)]
    pub config: TamperPackageDatabaseConfig,
}

/// Patch an apt `InRelease` file
#[derive(Debug, Clone, Parser)]
pub struct TamperAptRelease {
    /// The input database to modify
    pub path: String,
    /// Path to write the patched database to
    pub out: String,
    /// Patch a metadata field on the release instead of a checksum
    #[arg(long)]
    pub release_set: Vec<String>,
    /// Skip signing the final release file
    #[arg(long)]
    pub unsigned: bool,
    /// Path to signing key to sign the release with
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
    #[clap(flatten)]
    pub config: TamperPackageDatabaseConfig,
}

/// Patch an apt `Packages` file
#[derive(Debug, Clone, Parser)]
pub struct TamperAptPackageList {
    /// The input database to modify
    pub path: String,
    /// Path to write the patched database to
    pub out: String,
    #[clap(flatten)]
    pub config: TamperPackageDatabaseConfig,
}

/// Generate signing keys with the given parameters
#[derive(Debug, Subcommand)]
pub enum Keygen {
    Tls(KeygenTls),
    Pgp(KeygenPgp),
}

/// Generate a self-signed tls certificate
#[derive(Debug, Clone, Parser)]
pub struct KeygenTls {
    pub names: Vec<String>,
}

/// Generate a pgp keypair
#[derive(Debug, Clone, Parser)]
pub struct KeygenPgp {
    pub uids: Vec<String>,
}

/// Use signing keys to generate signatures
#[derive(Debug, Subcommand)]
pub enum Sign {
    /// Create a cleartext pgp signature
    PgpCleartext(SignPgp),
    /// Create a detached pgp signature
    PgpDetached(SignPgp),
}

#[derive(Debug, Clone, Parser)]
pub struct SignPgp {
    /// Secret key to use for signing
    #[arg(long)]
    pub secret_key: PathBuf,
    /// Don't use ascii armor
    #[arg(long)]
    pub binary: bool,
    /// Path to data to sign
    pub path: PathBuf,
}

/// Compile an attack based on a plot
#[derive(Debug, Clone, Parser)]
pub struct Build {
    /// Path to plot configuration file
    pub plot: PathBuf,
    /// Run the build in this directory
    #[arg(short = 'C', long)]
    pub context: Option<PathBuf>,
    /// Output the compiled plot here
    #[arg(short, long)]
    pub output: PathBuf,
}

/// Ensure a provided attack can still execute correctly
#[derive(Debug, Clone, Parser)]
pub struct Check {
    /// Path to the plot to execute
    pub plot: String,
    /// Address to bind to
    #[arg(short = 'B', long, env = "SH4D0WUP_BIND")]
    pub bind: Option<SocketAddr>,
    /// Pull the image even if it already exists locally
    #[arg(long)]
    pub pull: bool,
    /// Only load the plot but don't execute it
    #[arg(short, long)]
    pub no_exec: bool,
}

/// Generate shell completions
#[derive(Debug, Parser)]
pub struct Completions {
    pub shell: Shell,
}

pub fn gen_completions(args: &Completions) -> Result<()> {
    clap_complete::generate(args.shell, &mut Args::command(), "sh4d0wup", &mut stdout());
    Ok(())
}
