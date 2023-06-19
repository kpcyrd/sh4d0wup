use crate::errors::*;
use crate::plot::{Artifacts, PkgFilter, PkgRef};
use crate::tamper;
use crate::templates;
use crate::utils;
use serde::{Deserialize, Serialize};
use std::io::BufReader;
use std::io::Read;
use tar::Archive;
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApkPkg {
    pub artifact: String,
    pub url: Url,
    pub pkg: PkgFilter,
}

impl ApkPkg {
    pub fn resolve(&self, artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        let artifact = artifacts.get(&self.artifact).with_context(|| {
            anyhow!(
                "Referencing artifact that doesn't exist: {:?}",
                self.artifact
            )
        })?;

        let mut reader = BufReader::new(artifact.as_bytes());
        let _signature_buf = utils::apk::read_gzip_to_end(&mut reader)?;
        let index_buf = utils::apk::read_gzip_to_end(&mut reader)?;
        let mut archive = Archive::new(&index_buf[..]);

        for entry in archive.entries()?.raw(true) {
            let mut entry = entry?;
            let header = entry.header().clone();
            trace!("Found entry in tar: {:?}", header.path());
            let filename = header.path()?;

            if filename.to_str() == Some("APKINDEX") {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                let mut bytes = &bytes[..];

                while !bytes.is_empty() {
                    let (pkg, remaining) =
                        tamper::apk::Pkg::parse(bytes).context("Failed to parse package index")?;
                    bytes = remaining;

                    trace!("Found package in archive: {pkg:?}");

                    if self.pkg.matches_pkg(&pkg) {
                        debug!("Found matching package in archive: {pkg:?}");

                        let name = pkg.name();
                        let version = pkg.version().to_string();
                        let filename = format!("{}-{}.apk", name, version);
                        let url = self.url.join(&filename)?;

                        // TODO: extract sha1 hash from index: https://wiki.alpinelinux.org/wiki/Apk_spec#Package_Checksum_Field

                        let artifact = templates::ArtifactMetadata {
                            url,
                            filename: Some(filename),
                            version: Some(version),
                            sha256: None,
                        };
                        let json = artifact.to_json()?;
                        return Ok(json);
                    }
                }
            }
        }

        bail!("Did not find any matching package in apk pkg index")
    }
}
