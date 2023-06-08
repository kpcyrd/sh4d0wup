use crate::args;
use crate::artifacts::{Artifact, HashedArtifact};
use crate::errors::*;
use crate::plot::{Ctx, Plot, PlotExtras};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
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

    pub fn finish(self) -> Result<()> {
        debug!("Finishing archive...");
        self.builder.into_inner()?;
        Ok(())
    }
}

pub struct CompiledArchive {
    pub plot: String,
    pub artifacts: BTreeMap<String, HashedArtifact>,
}

pub async fn build<R: Read>(plot: &mut Plot, cache_from: Option<R>) -> Result<CompiledArchive> {
    let mut artifacts = BTreeMap::new();
    if let Some(f) = cache_from {
        debug!("Loading existing plot as cache...");
        Ctx::load_as_download_cache(f, plot, &mut artifacts)
            .await
            .context("Failed to load existing plot as cache")?;
        debug!("Finished loading existing plot");
    }

    debug!("Setting up compressed writer...");
    info!("Resolving plot...");
    let PlotExtras {
        mut artifacts,
        signing_keys,
        sessions: _,
    } = plot
        .resolve_extras(artifacts)
        .await
        .context("Failed to resolve plot into runtime state")?;

    for (key, value) in &mut plot.artifacts {
        if let Artifact::File(artifact) = value {
            info!("Reading artifact from disk: {:?}", artifact.path);
            let buf = fs::read(&artifact.path)?;
            artifacts.insert(key.to_string(), HashedArtifact::new(buf));
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

    let plot = serde_json::to_string(&plot)?;

    Ok(CompiledArchive { plot, artifacts })
}

impl CompiledArchive {
    pub fn write<W: Write>(&self, w: W) -> Result<()> {
        info!("Writing archive...");
        let w = Encoder::new(w, ZSTD_COMPRESSION_LEVEL)
            .context("Failed to setup zstd stream")?
            .auto_finish();

        let mut tar = ArchiveBuilder::new(w);
        tar.append("plot.json", self.plot.as_bytes())?;
        for (key, value) in &self.artifacts {
            tar.append(key, value.as_bytes())?;
        }

        tar.finish()?;
        Ok(())
    }
}

pub async fn run(args: args::Build) -> Result<()> {
    let mut plot = Plot::load_from_path(&args.plot.path)?;

    if args.no_build {
        serde_json::to_writer_pretty(io::stdout(), &plot)?;
        println!();
        return Ok(());
    }

    let cache_from = if let Some(path) = args.plot.cache_from {
        info!("Opening existing plot as cache: {:?}", path);
        let f = File::open(&path)
            .with_context(|| anyhow!("Failed to open cache plot at {:?}", path))?;
        Some(f)
    } else {
        None
    };

    let output_path = args
        .output
        .as_ref()
        .context("Missing mandatory option for output: --output ./plot.tar.zst")?;
    let f = File::create(output_path)
        .with_context(|| anyhow!("Failed to open output file: {:?}", args.output))?;

    let archive = build(&mut plot, cache_from).await?;
    archive.write(&f)?;
    Ok(())
}
