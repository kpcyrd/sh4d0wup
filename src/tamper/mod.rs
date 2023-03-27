pub mod apk;
pub mod apt_package_list;
pub mod apt_release;
pub mod pacman;

use crate::args::Tamper;
use crate::artifacts::git;
use crate::artifacts::git::Oid;
use crate::errors::*;
use crate::keygen::openssl::OpensslEmbedded;
use crate::keygen::pgp::PgpEmbedded;
use crate::keygen::EmbeddedKey;
use crate::plot::{PatchAptReleaseConfig, PatchPkgDatabaseConfig, PlotExtras};
use crate::tamper;
use bstr::BString;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{Read, Write};

pub async fn run(tamper: Tamper) -> Result<()> {
    match tamper {
        Tamper::PacmanDb(tamper) => {
            let db = fs::read(&tamper.path)?;
            let mut out = File::create(&tamper.out)?;

            let config = PatchPkgDatabaseConfig::<Vec<String>>::from_args(tamper.config)?;
            let plot_extras = PlotExtras::default();
            tamper::pacman::patch(&config, &plot_extras, &db, &mut out)?;
        }
        Tamper::AptRelease(tamper) => {
            let db = fs::read(&tamper.path)?;
            let mut out = File::create(&tamper.out)?;

            let checksum_config = PatchPkgDatabaseConfig::<String>::from_args(tamper.config)?;

            let mut release_fields = BTreeMap::new();

            for s in &tamper.release_set {
                let (key, value) = s.split_once('=').context("Argument is not an assignment")?;
                release_fields.insert(key.to_string(), value.to_string());
            }

            let signing_key = match (tamper.unsigned, tamper.signing_key) {
                (true, Some(_)) => {
                    warn!("Using --unsigned and --signing-key together is causing the release to be unsigned");
                    None
                }
                (true, None) => None,
                (false, Some(path)) => Some(PgpEmbedded::read_from_disk(path)?),
                (false, None) => bail!("Missing --signing-key and --unsigned wasn't provided"),
            };

            let mut plot_extras = PlotExtras::default();
            let signing_key = if let Some(signing_key) = signing_key {
                plot_extras
                    .signing_keys
                    .insert("pgp".to_string(), EmbeddedKey::Pgp(signing_key));
                Some("pgp".to_string())
            } else {
                None
            };
            let config = PatchAptReleaseConfig {
                fields: release_fields,
                checksums: checksum_config,
                signing_key,
            };
            tamper::apt_release::patch(
                &config,
                &plot_extras.artifacts,
                &plot_extras.signing_keys,
                &db,
                &mut out,
            )?;
        }
        Tamper::AptPackageList(tamper) => {
            let db = fs::read(&tamper.path)?;
            let mut out = File::create(&tamper.out)?;

            let plot_extras = PlotExtras::default();
            let config = PatchPkgDatabaseConfig::<Vec<String>>::from_args(tamper.config)?;
            tamper::apt_package_list::patch(&config, None, &plot_extras.artifacts, &db, &mut out)?;
        }
        Tamper::ApkIndex(tamper) => {
            let db = fs::read(&tamper.path)?;
            let mut out = File::create(&tamper.out)?;

            let signing_key = OpensslEmbedded::read_from_disk(tamper.signing_key)?;

            let mut plot_extras = PlotExtras::default();
            plot_extras
                .signing_keys
                .insert("openssl".to_string(), EmbeddedKey::Openssl(signing_key));

            let config = PatchPkgDatabaseConfig::<String>::from_args(tamper.config)?;
            tamper::apk::patch(
                &config,
                &plot_extras,
                "openssl",
                &tamper.signing_key_name,
                &db,
                &mut out,
            )?;
        }
        Tamper::GitCommit(tamper) => {
            let mut out = Vec::new();

            let mut tree = None;
            let mut parents = Vec::new();
            let mut author = None;
            let mut committer = None;
            let mut extra_headers = Vec::new();
            let mut message = None;

            if tamper.stdin {
                let mut buf = Vec::new();
                io::stdin()
                    .read_to_end(&mut buf)
                    .context("Failed to read commit from stdin")?;

                let commit = gix_object::CommitRef::from_bytes(&buf)
                    .context("Failed to parse stdin as commit")?;

                tree = Some(git_oid_to_string(commit.tree)?);
                parents = commit
                    .parents
                    .into_iter()
                    .map(git_oid_to_string)
                    .collect::<Result<_>>()?;
                author = Some(git_author_to_string(&commit.author)?);
                committer = Some(git_author_to_string(&commit.committer)?);
                extra_headers = commit
                    .extra_headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into_owned()))
                    .collect();
                message = Some(commit.message.into());
            }

            if let Some(value) = tamper.tree {
                tree = Some(value);
            }

            if !tamper.parents.is_empty() {
                parents = tamper.parents;
            }

            if tamper.no_parents {
                parents.clear();
            }

            if let Some(value) = tamper.author {
                author = Some(value);
            }

            if let Some(value) = tamper.committer {
                committer = Some(value);
            }

            if let Some(mut value) = tamper.message {
                value.push('\n');
                message = Some(BString::new(value.into()));
            }

            if tamper.message_stdin {
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf)?;
                message = Some(BString::new(buf));
            }

            let commit = git::Commit {
                tree: Oid::Inline(tree.context("Missing value for tree")?),
                parents: parents.into_iter().map(Oid::Inline).collect(),
                author: author.context("Missing value for git author")?,
                committer: committer.context("Missing value for git committer")?,
                extra_headers,
                message: message.context("Missing message for git commit")?,
                collision_prefix: tamper.collision_prefix,
                nonce: tamper.nonce,
            };

            commit.encode(&mut out, &Default::default()).await?;
            let out = if tamper.strip_header {
                let (_, _, consumed) = gix_object::decode::loose_header(&out)?;
                &out[consumed..]
            } else {
                &out[..]
            };

            io::stdout().write_all(out)?;
        }
    }

    Ok(())
}

pub fn git_oid_to_string(oid: &bstr::BStr) -> Result<String> {
    let s = std::str::from_utf8(oid)?;
    Ok(s.to_string())
}

pub fn git_author_to_string(author: &gix_actor::SignatureRef) -> Result<String> {
    let mut buf = Vec::new();
    author.write_to(&mut buf)?;
    let buf = String::from_utf8(buf)?;
    Ok(buf)
}
