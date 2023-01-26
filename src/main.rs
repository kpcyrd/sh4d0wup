use clap::Parser;
use env_logger::Env;
use openssl::hash::MessageDigest;
use sh4d0wup::args::{self, Args, Hsm, HsmPgp, Keygen, Sign, SubCommand};
use sh4d0wup::bait;
use sh4d0wup::build;
use sh4d0wup::check;
use sh4d0wup::errors::*;
use sh4d0wup::hsm;
use sh4d0wup::infect;
use sh4d0wup::keygen;
use sh4d0wup::keygen::in_toto::InTotoEmbedded;
use sh4d0wup::keygen::openssl::OpensslEmbedded;
use sh4d0wup::keygen::pgp::PgpEmbedded;
use sh4d0wup::plot;
use sh4d0wup::req;
use sh4d0wup::sign;
use sh4d0wup::tamper;
use std::fs;
use std::io;
use std::io::Write;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match (args.quiet, args.verbose) {
        (0, 0) => "warn,sh4d0wup=info",
        (1, 0) => "warn",
        (_, 0) => "error",
        (_, 1) => "info,sh4d0wup=debug",
        (_, 2) => "debug",
        (_, 3) => "debug,sh4d0wup=trace",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    match args.subcommand {
        SubCommand::Bait(bait) => {
            let ctx = bait.plot.load_into_context().await?;
            bait::run(ctx, &bait.bind, &bait.tls).await?;
        }
        SubCommand::Front(front) => {
            let plot = plot::Plot {
                upstreams: maplit::btreemap! {
                    "upstream".to_string() => plot::Upstream {
                        url: front.upstream,
                        keep_headers: false,
                    },
                },
                routes: vec![plot::Route {
                    path: None,
                    host: None,
                    selector: None,
                    action: plot::RouteAction::Proxy(plot::ProxyRoute {
                        upstream: "upstream".to_string(),
                        path: None,
                    }),
                }],
                ..Default::default()
            };

            let ctx = plot.resolve().await?;
            bait::run(ctx, &front.bind, &front.tls).await?
        }
        SubCommand::Infect(infect) => infect::run(infect).await?,
        SubCommand::Tamper(tamper) => tamper::run(tamper).await?,
        SubCommand::Check(check) => {
            let ctx = check.plot.load_into_context().await?;
            match check.no_exec {
                0 => {
                    check::spawn(check, ctx).await?;
                }
                1 => {
                    serde_json::to_writer_pretty(io::stdout(), &ctx.plot)?;
                    println!();
                }
                _ => {
                    serde_json::to_writer_pretty(io::stdout(), &ctx.plot)?;
                    println!();
                    for (key, value) in &ctx.extras.signing_keys {
                        println!("signing_key {key:?}: {value:?}");
                    }
                    for (key, value) in &ctx.extras.artifacts {
                        println!("artifact {:?}: {} bytes", key, value.len());
                    }
                }
            }
        }
        SubCommand::Keygen(Keygen::Tls(tls)) => {
            let tls =
                keygen::tls::generate(tls.into()).context("Failed to generate tls certificate")?;
            print!("{}", tls.cert);
            print!("{}", tls.key);
        }
        SubCommand::Keygen(Keygen::Pgp(pgp)) => {
            let pgp = keygen::pgp::generate(pgp.into()).context("Failed to generate pgp key")?;
            if let Some(cert) = pgp.cert {
                keygen::pgp::debug_inspect(cert.as_bytes())
                    .context("Failed to inspect serialized pgp data")?;
                print!("{cert}");
            }
            keygen::pgp::debug_inspect(pgp.secret_key.as_bytes())
                .context("Failed to inspect serialized pgp data")?;
            print!("{}", pgp.secret_key);
            if let Some(rev) = pgp.rev {
                keygen::pgp::debug_inspect(rev.as_bytes())
                    .context("Failed to inspect serialized pgp data")?;
                print!("{rev}");
            }
        }
        SubCommand::Keygen(Keygen::Ssh(ssh)) => {
            let ssh =
                keygen::ssh::generate(&ssh.try_into()?).context("Failed to generate ssh key")?;
            if let Some(public_key) = ssh.public_key {
                println!("{public_key}");
            }
            print!("{}", ssh.secret_key);
        }
        SubCommand::Keygen(Keygen::Openssl(openssl)) => {
            let openssl = keygen::openssl::generate(&openssl.try_into()?)
                .context("Failed to generate openssl key")?;
            if let Some(public_key) = openssl.public_key {
                print!("{public_key}");
            }
            print!("{}", openssl.secret_key);
        }
        SubCommand::Keygen(Keygen::InToto(in_toto)) => {
            let in_toto = keygen::in_toto::generate(&in_toto.into())
                .context("Failed to generate in-toto key")?;
            if let Some(public_key) = in_toto.public_key {
                println!("{public_key}");
            }
            println!("{}", in_toto.secret_key);
        }
        SubCommand::Sign(Sign::PgpCleartext(pgp)) => {
            if pgp.binary {
                bail!("Binary output is not supported for cleartext signatures");
            }
            let secret_key = PgpEmbedded::read_from_disk(&pgp.secret_key)
                .context("Failed to load secret key")?;
            debug!("Reading data to sign...");
            let data = fs::read(&pgp.path)
                .with_context(|| anyhow!("Failed to read payload data from {:?}", pgp.path))?;
            let sig = sign::pgp::sign_cleartext(&secret_key, &data)?;
            io::stdout().write_all(&sig)?;
        }
        SubCommand::Sign(Sign::PgpDetached(pgp)) => {
            let secret_key = PgpEmbedded::read_from_disk(&pgp.secret_key)
                .context("Failed to load secret key")?;
            debug!("Reading data to sign...");
            let data = fs::read(&pgp.path)
                .with_context(|| anyhow!("Failed to read payload data from {:?}", pgp.path))?;
            let sig = sign::pgp::sign_detached(&secret_key, &data, pgp.binary)?;
            io::stdout().write_all(&sig)?;
        }
        SubCommand::Sign(Sign::Openssl(openssl)) => {
            if !openssl.binary {
                bail!("Openssl signatures are always binary");
            }
            let secret_key = OpensslEmbedded::read_from_disk(&openssl.secret_key)
                .context("Failed to load secret key")?;
            debug!("Reading data to sign...");
            let data = fs::read(&openssl.path)
                .with_context(|| anyhow!("Failed to read payload data from {:?}", openssl.path))?;

            let digest = if openssl.md5 {
                MessageDigest::md5()
            } else if openssl.sha1 {
                MessageDigest::sha1()
            } else if openssl.sha256 {
                MessageDigest::sha256()
            } else if openssl.sha512 {
                MessageDigest::sha512()
            } else if openssl.sha3_256 {
                MessageDigest::sha3_256()
            } else if openssl.sha3_512 {
                MessageDigest::sha3_512()
            } else {
                bail!("No hash function selected")
            };

            let sig = sign::openssl::sign(&secret_key, &data, digest)?;
            io::stdout().write_all(&sig)?;
        }
        SubCommand::Sign(Sign::InToto(in_toto)) => {
            let secret_key = InTotoEmbedded::read_from_disk(&in_toto.secret_key)
                .context("Failed to load secret key")?;
            let mut sig = sign::in_toto::sign(&secret_key, &in_toto.try_into()?)?;
            sig.push(b'\n');
            io::stdout().write_all(&sig)?;
        }
        SubCommand::Hsm(Hsm::Pgp(HsmPgp::Access(access))) => hsm::pgp::access(&access)?,
        SubCommand::Build(build) => build::run(build).await?,
        SubCommand::Req(req) => req::run(&req).await?,
        SubCommand::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
    }

    Ok(())
}
