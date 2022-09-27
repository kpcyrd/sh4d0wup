use clap::Parser;
use env_logger::Env;
use sh4d0wup::args::{Args, Infect, SubCommand};
use sh4d0wup::errors::*;
use sh4d0wup::httpd;
use sh4d0wup::infect;
use sh4d0wup::plot::Plot;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => "sh4d0wup=info",
        1 => "info,sh4d0wup=debug",
        2 => "debug",
        3 => "debug,sh4d0wup=trace",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    match args.subcommand {
        SubCommand::Bait(bait) => {
            info!("Loading plot from {:?}...", bait.plot);
            let plot = Plot::load_from_path(&bait.plot)?;
            trace!("Loaded plot: {:?}", plot);
            httpd::run(bait.bind, plot).await?;
        }
        SubCommand::Infect(Infect::Pacman(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let infected = infect::pacman::infect(&infect, &pkg)?;
            fs::write(infect.out, &infected)?;
        }
        SubCommand::Infect(Infect::Deb(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let infected = infect::deb::infect(&infect, &pkg)?;
            fs::write(infect.out, &infected)?;
        }
        SubCommand::Infect(Infect::Oci(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let infected = infect::oci::infect(&infect, &pkg)?;
            fs::write(infect.out, &infected)?;
        }
    }

    Ok(())
}
