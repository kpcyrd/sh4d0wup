use clap::Parser;
use env_logger::Env;
use sh4d0wup::args::{self, Args, Infect, SubCommand, Tamper};
use sh4d0wup::certs;
use sh4d0wup::check;
use sh4d0wup::errors::*;
use sh4d0wup::httpd;
use sh4d0wup::infect;
use sh4d0wup::plot::{PatchAptReleaseConfig, PatchPkgDatabaseConfig, Plot};
use sh4d0wup::tamper_idx;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;

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
            let tls = if let Some(path) = bait.tls_cert {
                let cert = fs::read(&path)
                    .with_context(|| anyhow!("Failed to read certificate from path: {:?}", path))?;

                let key = if let Some(path) = bait.tls_key {
                    fs::read(&path).with_context(|| {
                        anyhow!("Failed to read certificate from path: {:?}", path)
                    })?
                } else {
                    cert.clone()
                };

                Some(httpd::Tls { cert, key })
            } else if let Some(tls) = plot.tls.clone() {
                Some(httpd::Tls::try_from(tls)?)
            } else {
                None
            };

            httpd::run(bait.bind, tls, plot).await?;
        }
        SubCommand::Infect(Infect::Pacman(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let mut out = File::create(&infect.out)?;
            infect::pacman::infect(&infect, &pkg, &mut out)?;
        }
        SubCommand::Infect(Infect::Deb(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let mut out = File::create(&infect.out)?;
            infect::deb::infect(&infect, &pkg, &mut out)?;
        }
        SubCommand::Infect(Infect::Oci(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let mut out = File::create(&infect.out)?;
            infect::oci::infect(&infect, &pkg, &mut out)?;
        }
        SubCommand::Infect(Infect::Apk(infect)) => {
            let pkg = fs::read(&infect.path)?;
            let mut out = File::create(&infect.out)?;
            infect::apk::infect(&infect, &pkg, &mut out)?;
        }
        SubCommand::Infect(Infect::Elf(infect)) => {
            let elf = fs::read(&infect.path)?;
            infect::elf::infect(&infect, &elf, &infect.out).await?;
        }
        SubCommand::Tamper(Tamper::PacmanDb(tamper_idx)) => {
            let db = fs::read(&tamper_idx.path)?;
            let mut out = File::create(&tamper_idx.out)?;

            let config = PatchPkgDatabaseConfig::<Vec<String>>::from_args(tamper_idx.config)?;
            tamper_idx::pacman::patch_database(&config, &db, &mut out)?;
        }
        SubCommand::Tamper(Tamper::AptRelease(tamper_idx)) => {
            let db = fs::read(&tamper_idx.path)?;
            let mut out = File::create(&tamper_idx.out)?;

            let checksum_config = PatchPkgDatabaseConfig::<String>::from_args(tamper_idx.config)?;

            let mut release_fields = BTreeMap::new();

            for s in &tamper_idx.release_set {
                let (key, value) = s.split_once('=').context("Argument is not an assignment")?;
                release_fields.insert(key.to_string(), value.to_string());
            }

            let config = PatchAptReleaseConfig {
                fields: release_fields,
                checksums: checksum_config,
            };
            tamper_idx::apt_release::patch(&config, &db, &mut out)?;
        }
        SubCommand::Tamper(Tamper::AptPackageList(tamper_idx)) => {
            let db = fs::read(&tamper_idx.path)?;
            let mut out = File::create(&tamper_idx.out)?;

            let config = PatchPkgDatabaseConfig::<Vec<String>>::from_args(tamper_idx.config)?;
            tamper_idx::apt_package_list::patch(&config, &db, &mut out)?;
        }
        SubCommand::Check(check) => {
            info!("Loading plot from {:?}...", check.plot);
            let plot = Plot::load_from_path(&check.plot)?;
            trace!("Loaded plot: {:?}", plot);
            check::spawn(check, plot).await?;
        }
        SubCommand::GenCert(gen_cert) => {
            let tls = certs::generate(gen_cert.into())?;
            print!("{}", tls.cert);
            print!("{}", tls.key);
        }
        SubCommand::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
    }

    Ok(())
}
