use crate::compression;
use crate::errors::*;
use crate::plot::{Artifacts, PkgFilter, PkgRef};
use crate::tamper;
use crate::templates;
use serde::{Deserialize, Serialize};
use std::io::Read;
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AptPkg {
    pub artifact: String,
    pub url: Url,
    pub pkg: PkgFilter,
}

impl AptPkg {
    pub fn resolve(&self, artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        let artifact = artifacts.get(&self.artifact).with_context(|| {
            anyhow!(
                "Referencing artifact that doesn't exist: {:?}",
                self.artifact
            )
        })?;
        let bytes = artifact.as_bytes();

        let detected_compression = compression::detect_compression(bytes);

        let mut reader = compression::stream_decompress(bytes, detected_compression)?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let mut bytes = &bytes[..];

        while !bytes.is_empty() {
            let (pkg, remaining) = tamper::apt_package_list::Pkg::parse(bytes)
                .context("Failed to parse package index")?;
            bytes = remaining;

            if self.pkg.matches_pkg(&pkg) {
                let filename = pkg
                    .get_key_str("Filename")
                    .context("Package metadata has no `Filename`")?;
                let url = self.url.join(filename)?;

                let version = Some(pkg.version().to_string());
                let sha256 = pkg.get_key_str("SHA256").map(String::from);

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

        bail!("Did not find any matching package in apt pkg index")
    }
}
