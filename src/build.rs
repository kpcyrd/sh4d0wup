use crate::args;
use crate::artifacts::Artifact;
use crate::errors::*;
use crate::plot::{Plot, PlotExtras};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Write;
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

    info!("Resolving plot...");
    let artifacts = BTreeMap::new();
    let PlotExtras {
        mut artifacts,
        signing_keys,
    } = plot
        .resolve_extras(artifacts)
        .await
        .context("Failed to resolve plot into runtime state")?;

    for (key, value) in &mut plot.artifacts {
        if let Artifact::Path(artifact) = value {
            info!("Reading artifact from disk: {:?}", artifact.path);
            let buf = fs::read(&artifact.path)?;
            artifacts.insert(key.to_string(), buf);
            *value = Artifact::Memory
        }
    }

    if !signing_keys.is_empty() {
        info!("Embedding generated/referenced secret keys in plot");
        plot.signing_keys = Some(
            signing_keys
                .into_iter()
                .map(|(k, v)| (k, v.into()))
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
