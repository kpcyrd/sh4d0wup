use crate::compression;
use crate::errors::*;
use crate::plot::{Artifacts, PkgFilter, PkgRef};
use crate::tamper;
use crate::templates;
use serde::{Deserialize, Serialize};
use std::io::Read;
use tar::{Archive, EntryType};
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacmanPkg {
    pub artifact: String,
    pub url: Url,
    pub pkg: PkgFilter,
}

impl PacmanPkg {
    pub fn resolve(&self, artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        let artifact = artifacts.get(&self.artifact).with_context(|| {
            anyhow!(
                "Referencing artifact that doesn't exist: {:?}",
                self.artifact
            )
        })?;

        let comp = compression::detect_compression(artifact.as_bytes());
        let tar = compression::stream_decompress(artifact.as_bytes(), comp)?;
        let mut archive = Archive::new(tar);

        for entry in archive.entries()? {
            let mut entry = entry?;
            trace!("tar entry: {:?}", entry.header());
            if entry.header().entry_type() == EntryType::Regular {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;

                let pkg = tamper::pacman::Pkg::parse(&buf)?;
                trace!("Found pkg: {:?}", pkg);

                if self.pkg.matches_pkg(&pkg) {
                    let filename = pkg
                        .get_key_str("%FILENAME%")
                        .context("Package metadata has no %FILENAME%")?;
                    let url = self.url.join(filename)?;

                    let version = Some(pkg.version().to_string());
                    let sha256 = pkg.get_key_str("%SHA256SUM%").map(String::from);

                    let artifact = templates::ArtifactMetadata {
                        url,
                        filename: Some(filename.to_string()),
                        version,
                        sha256,
                    };
                    let json = artifact.to_json()?;
                    return Ok(json);
                }
            }
        }

        bail!("Did not find any matching package in pacman pkg database")
    }
}
