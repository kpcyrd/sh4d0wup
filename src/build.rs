use crate::args;
use crate::artifacts::Artifact;
use crate::errors::*;
use crate::keygen::in_toto::KeygenInToto;
use crate::keygen::openssl::KeygenOpenssl;
use crate::keygen::pgp::KeygenPgp;
use crate::keygen::{EmbeddedKey, Keygen};
use crate::plot::Plot;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::mem;
use zstd::stream::write::Encoder;

pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

pub struct ArchiveBuilder<W: Write> {
    builder: tar::Builder<W>,
}

impl<W: Write> ArchiveBuilder<W> {
    pub fn new(writer: W) -> Self {
        Self {
            builder: tar::Builder::new(writer),
        }
    }

    pub fn append(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o640);
        debug!("Adding to archive: {:?} ({} bytes)", path, data.len());
        self.builder.append_data(&mut header, path, data)?;
        Ok(())
    }

    pub fn append_json<T: serde::Serialize>(&mut self, path: &str, data: &T) -> Result<()> {
        let buf = serde_json::to_vec(data)?;
        self.append(path, &buf)?;
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        debug!("Finishing archive...");
        self.builder.into_inner()?;
        Ok(())
    }
}

pub async fn run(build: args::Build) -> Result<()> {
    info!("Loading plot from {:?}...", build.plot);
    let mut plot = Plot::load_from_path(&build.plot)?;

    debug!("Setting up compressed writer...");
    let f = File::create(&build.output)
        .with_context(|| anyhow!("Failed to open output file: {:?}", build.output))?;
    let w = Encoder::new(f, ZSTD_COMPRESSION_LEVEL)
        .context("Failed to setup zstd stream")?
        .auto_finish();

    let signing_keys = if let Some(keys) = plot.signing_keys.take() {
        keys.into_iter()
            .map(|(key, value)| Ok((key, value.resolve()?)))
            .collect::<Result<_>>()?
    } else {
        BTreeMap::new()
    };

    info!("Loading artifacts...");
    let mut artifacts = BTreeMap::new();
    for (key, value) in &mut plot.artifacts {
        match value {
            Artifact::Path(artifact) => {
                info!("Reading artifact from disk: {:?}", artifact.path);
                let buf = fs::read(&artifact.path)?;
                artifacts.insert(key.to_string(), buf);
                *value = Artifact::Memory
            }
            Artifact::Url(artifact) => {
                info!("Reading artifact from url: {}", artifact.url);
                let buf = artifact.download().await?;
                artifacts.insert(key.to_string(), buf.to_vec());
                *value = Artifact::Memory;
            }
            Artifact::Inline(inline) => {
                let data = mem::take(&mut inline.data);
                let bytes = data.into_bytes();
                artifacts.insert(key.to_string(), bytes);
                *value = Artifact::Memory;
            }
            Artifact::Signature(artifact) => {
                let sig = artifact.resolve(&mut artifacts, &signing_keys)?;
                artifacts.insert(key.to_string(), sig);
            }
            Artifact::Memory => (),
        }
    }

    if !signing_keys.is_empty() {
        info!("Embedding generated/referenced secret keys in plot");
        plot.signing_keys = Some(
            signing_keys
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        match v {
                            EmbeddedKey::Pgp(pgp) => Keygen::Pgp(KeygenPgp::Embedded(pgp)),
                            EmbeddedKey::Openssl(openssl) => {
                                Keygen::Openssl(KeygenOpenssl::Embedded(openssl))
                            }
                            EmbeddedKey::InToto(in_toto) => {
                                Keygen::InToto(KeygenInToto::Embedded(in_toto))
                            }
                        },
                    )
                })
                .collect(),
        );
    }

    info!("Writing archive...");
    let mut tar = ArchiveBuilder::new(w);
    tar.append_json("plot.json", &plot)?;
    for (key, value) in artifacts {
        tar.append(&key, &value)?;
    }

    tar.finish()?;

    Ok(())
}
