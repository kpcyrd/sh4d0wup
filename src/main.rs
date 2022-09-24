use clap::Parser;
use env_logger::Env;
use sh4d0wup::args::{Args, SubCommand};
use sh4d0wup::errors::*;
use sh4d0wup::httpd;
use sh4d0wup::plot::Plot;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => "sh4d0wup=info",
        1 => "info,sh4d0wup=debug",
        2 => "debug",
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
    }

    Ok(())
}
