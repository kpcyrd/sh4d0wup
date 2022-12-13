use crate::errors::*;
use crate::plot::Artifacts;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "extract", rename_all = "kebab-case")]
pub enum ExtractArtifact {
    Zip(GenericExtractArtifact),
}

impl ExtractArtifact {
    pub fn resolve(&self, artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        match self {
            ExtractArtifact::Zip(extract) => {
                extract.log();

                let artifact = artifacts.get(&extract.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        extract.artifact
                    )
                })?;

                let cursor = Cursor::new(artifact.as_ref());
                let mut archive = zip::ZipArchive::new(cursor).with_context(|| {
                    anyhow!(
                        "Failed to open artifact {:?} as zip archive",
                        extract.artifact
                    )
                })?;

                for i in 0..archive.len() {
                    trace!("Accessing zip entry {}/{}", i, archive.len());
                    let mut entry = archive
                        .by_index(i)
                        .with_context(|| anyhow!("Failed to access entry at index {:?}", i))?;

                    let name = entry.name();
                    if entry.is_dir() {
                        trace!("Skipping directory in zip file: {:?}", name);
                        continue;
                    }

                    if !extract.matches(name)? {
                        trace!("Skipping file in zip file: {:?}", name);
                        continue;
                    }

                    debug!("Extracting {:?} from archive...", name);
                    let mut buf = Vec::new();
                    entry
                        .read_to_end(&mut buf)
                        .context("Failed to extract file from zip")?;
                    return Ok(buf);
                }

                bail!("Archive did not contain any matching file");
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericExtractArtifact {
    pub artifact: String,
    pub path: Option<String>,
    pub regex: Option<String>,
}

impl GenericExtractArtifact {
    pub fn log(&self) {
        if let Some(path) = &self.path {
            info!(
                "Extracting from artifact {:?} with path={:?}...",
                self.artifact, path
            );
        } else if let Some(regex) = &self.regex {
            info!(
                "Extracting from artifact {:?} with regex {:?}...",
                self.artifact, regex
            );
        } else {
            info!(
                "Extracting first entry from artifact {:?}...",
                self.artifact
            );
        }
    }

    pub fn matches(&self, name: &str) -> Result<bool> {
        if let Some(path) = &self.path {
            Ok(path == name)
        } else if let Some(regex) = &self.regex {
            // TODO: doing this in a loop is bad
            let re = Regex::new(regex)
                .with_context(|| anyhow!("Failed to compile regex: {:?}", regex))?;
            Ok(re.is_match(name))
        } else {
            Ok(true)
        }
    }
}
