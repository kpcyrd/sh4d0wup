use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Args {
    /// Turn debugging information on
    #[clap(short, long, global = true, parse(from_occurrences))]
    pub verbose: usize,
    #[clap(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    Bait(Bait),
    #[clap(subcommand)]
    Infect(Infect),
}

/// Start a malicious update server
#[derive(Debug, Clone, Parser)]
pub struct Bait {
    /// Address to bind to
    #[clap(short = 'B', long, env = "SH4D0WUP_BIND")]
    pub bind: SocketAddr,
    /*
    /// The upstream server to reverse proxy to
    #[clap(short = 'U', long)]
    pub upstream: Option<String>,
    /// Do not modify Host: and similar headers
    #[clap(short = 'K', long)]
    pub keep_headers: bool,
    */
    /// Path to the plot to execute
    pub plot: String,
}

/// Inject additional commands into a package
#[derive(Debug, Subcommand)]
pub enum Infect {
    Pacman(InfectPacmanPkg),
    Deb(InfectDebPkg),
    Oci(InfectOci),
    Apk(InfectApkPkg),
}

/// Infect a pacman package
#[derive(Debug, Clone, Parser)]
pub struct InfectPacmanPkg {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Update a key in .PKGINFO (a key can be set multiple times)
    #[clap(long)]
    pub set: Vec<String>,
    /// The command to inject into the package that's executed once during install
    #[clap(short = 'c', long)]
    pub payload: String,
}

/// Infect a .deb package
#[derive(Debug, Clone, Parser)]
pub struct InfectDebPkg {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Update a key in ./control
    #[clap(long)]
    pub set: Vec<String>,
    /// The command to inject into the package that's executed once during install
    #[clap(short = 'c', long)]
    pub payload: String,
}

/// Infect an OCI container image .tar
#[derive(Debug, Clone, Parser)]
pub struct InfectOci {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// The command to inject into the package that's executed once during install
    #[clap(short = 'c', long)]
    pub payload: String,
}

/// Infect a pacman package
#[derive(Debug, Clone, Parser)]
pub struct InfectApkPkg {
    /// The input package to use as a base
    pub path: PathBuf,
    /// Where to write the modified package to
    pub out: PathBuf,
    /// Update a key in .PKGINFO (a key can be set multiple times)
    #[clap(long)]
    pub set: Vec<String>,
    /// The command to inject into the package that's executed once during install
    #[clap(short = 'c', long)]
    pub payload: String,
}
