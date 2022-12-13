pub mod compress;
pub mod extract;
pub mod git;
pub mod infect;
pub mod signature;
pub mod tamper;
pub mod url;

use crate::errors::*;
use crate::plot::PlotExtras;
use maplit::hashset;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::mem;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Artifact {
    File(FileArtifact),
    Url(url::UrlArtifact),
    Inline(InlineArtifact),
    Signature(signature::SignatureArtifact),
    Infect(infect::InfectArtifact),
    Tamper(tamper::TamperArtifact),
    Compress(compress::CompressArtifact),
    Extract(extract::ExtractArtifact),
    Git(git::GitArtifact),
    Memory,
}

impl Artifact {
    pub fn depends_on(&self) -> Option<HashSet<&str>> {
        match self {
            Artifact::File(_) => None,
            Artifact::Url(_) => None,
            Artifact::Inline(_) => None,
            Artifact::Signature(sign) => Some(hashset![sign.artifact.as_str()]),
            Artifact::Infect(infect::InfectArtifact::Pacman(infect)) => {
                Some(hashset![infect.artifact.as_str()])
            }
            Artifact::Infect(infect::InfectArtifact::Deb(infect)) => {
                Some(hashset![infect.artifact.as_str()])
            }
            Artifact::Infect(infect::InfectArtifact::Apk(infect)) => {
                Some(hashset![infect.artifact.as_str()])
            }
            Artifact::Infect(infect::InfectArtifact::Elf(infect)) => {
                Some(hashset![infect.artifact.as_str()])
            }
            Artifact::Tamper(tamper::TamperArtifact::PatchAptRelease(tamper)) => {
                let mut set = hashset![tamper.artifact.as_str()];
                for patch in &tamper.config.checksums.patch {
                    if let Some(artifact) = &patch.artifact {
                        set.insert(artifact);
                    }
                }
                Some(set)
            }
            Artifact::Tamper(tamper::TamperArtifact::PatchAptPackageList(tamper)) => {
                let mut set = hashset![tamper.artifact.as_str()];
                for patch in &tamper.config.patch {
                    if let Some(artifact) = &patch.artifact {
                        set.insert(artifact);
                    }
                }
                Some(set)
            }
            Artifact::Tamper(tamper::TamperArtifact::PatchApkIndex(tamper)) => {
                let mut set = hashset![tamper.artifact.as_str()];
                for patch in &tamper.config.patch {
                    if let Some(artifact) = &patch.artifact {
                        set.insert(artifact);
                    }
                }
                Some(set)
            }
            Artifact::Compress(compress) => Some(hashset![compress.artifact.as_str()]),
            Artifact::Extract(extract::ExtractArtifact::Zip(extract)) => {
                Some(hashset![extract.artifact.as_str()])
            }
            Artifact::Git(git::GitArtifact::Commit(_git)) => None,
            Artifact::Memory => None,
        }
    }

    pub async fn resolve(&mut self, plot_extras: &mut PlotExtras) -> Result<Option<Vec<u8>>> {
        match self {
            Artifact::File(_) => Ok(None),
            Artifact::Url(artifact) => {
                info!(
                    "Downloading artifact into memory: {:?}",
                    artifact.url.to_string()
                );
                let buf = artifact
                    .download(&mut plot_extras.sessions)
                    .await
                    .context("Failed to resolve url artifact")?;
                *self = Artifact::Memory;
                Ok(Some(buf.to_vec()))
            }
            Artifact::Inline(inline) => {
                let data = mem::take(&mut inline.data);
                let bytes = data.into_bytes();
                *self = Artifact::Memory;
                Ok(Some(bytes))
            }
            Artifact::Signature(artifact) => {
                let sig = artifact
                    .resolve(plot_extras)
                    .context("Failed to resolve signature artifact")?;
                Ok(Some(sig))
            }
            Artifact::Infect(artifact) => {
                info!("Infecting artifact...");
                let buf = artifact
                    .resolve(plot_extras)
                    .await
                    .context("Failed to infect artifact")?;
                Ok(Some(buf))
            }
            Artifact::Tamper(artifact) => {
                info!("Tampering with index...");
                let buf = artifact
                    .resolve(plot_extras)
                    .context("Failed to tamper with artifact")?;
                Ok(Some(buf))
            }
            Artifact::Compress(compress) => {
                info!(
                    "Compressing artifact {:?} with {:?}...",
                    compress.artifact, compress.compression
                );
                let buf = compress
                    .resolve(&mut plot_extras.artifacts)
                    .context("Failed to compress artifact")?;
                Ok(Some(buf))
            }
            Artifact::Extract(extract) => {
                let buf = extract
                    .resolve(&mut plot_extras.artifacts)
                    .context("Failed to extract from artifact")?;
                Ok(Some(buf))
            }
            Artifact::Git(git) => {
                let buf = git
                    .resolve(&mut plot_extras.artifacts)
                    .context("Failed to build git object")?;
                Ok(Some(buf))
            }
            Artifact::Memory => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineArtifact {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedArtifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub md5: String,
}

impl HashedArtifact {
    pub fn new(bytes: Vec<u8>) -> HashedArtifact {
        debug!("Computing md5sum for artifact...");
        let mut hasher = Md5::new();
        hasher.update(&bytes);
        let md5 = hex::encode(hasher.finalize());

        debug!("Computing sha256sum for artifact...");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let sha256 = hex::encode(hasher.finalize());

        HashedArtifact { bytes, sha256, md5 }
    }
}

impl HashedArtifact {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl AsRef<[u8]> for HashedArtifact {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
