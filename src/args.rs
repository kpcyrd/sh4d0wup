use clap::{Parser, Subcommand};
use std::net::SocketAddr;

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
}

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
