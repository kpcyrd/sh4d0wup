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
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

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
            Artifact::Infect(infect::InfectArtifact::ElfFwdStdin(infect)) => infect
                .artifact
                .as_ref()
                .map(|artifact| hashset![artifact.as_str()]),
            Artifact::Infect(infect::InfectArtifact::Sh(infect)) => {
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
            Artifact::Tamper(tamper::TamperArtifact::PatchPacmanDb(tamper)) => {
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
            Artifact::Git(git::GitArtifact::Commit(git)) => {
                let mut set = HashSet::new();
                if let git::Oid::Artifact(oid) = &git.tree {
                    set.insert(oid.artifact.as_str());
                }
                for parent in &git.parents {
                    if let git::Oid::Artifact(oid) = parent {
                        set.insert(oid.artifact.as_str());
                    }
                }
                Some(set)
            }
            Artifact::Git(git::GitArtifact::Tree(git)) => {
                let mut set = HashSet::new();
                for entry in &git.entries {
                    if let git::Oid::Artifact(oid) = &entry.oid {
                        set.insert(oid.artifact.as_str());
                    }
                }
                Some(set)
            }
            Artifact::Git(git::GitArtifact::Blob(git)) => git
                .artifact
                .as_ref()
                .map(|artifact| hashset![artifact.as_str()]),
            Artifact::Git(git::GitArtifact::RefList(git)) => {
                let mut set = HashSet::new();
                for (_, r) in &git.refs {
                    if let git::Oid::Artifact(oid) = r {
                        set.insert(oid.artifact.as_str());
                    }
                }
                Some(set)
            }
            Artifact::Memory => None,
        }
    }

    pub async fn resolve(
        &mut self,
        plot_extras: &mut PlotExtras,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        let existing_artifact = plot_extras.artifacts.get(key);

        match self {
            Artifact::File(_) => Ok(None),
            Artifact::Url(artifact) => {
                if existing_artifact.is_some() {
                    debug!("Artifact {:?} is already registered, skipping...", key);
                    *self = Artifact::Memory;
                    Ok(None)
                } else {
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
            }
            Artifact::Inline(inline) => {
                let data = mem::take(&mut inline.data);
                let bytes = data.into_bytes();
                *self = Artifact::Memory;
                Ok(Some(bytes))
            }
            Artifact::Signature(artifact) => {
                // TODO: reuse signature form existing_artifact if it is valid

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
                    .await
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

#[derive(Debug)]
pub struct HashedArtifact {
    pub bytes: Vec<u8>,
    sha256: RwLock<Option<Arc<String>>>,
    sha1: RwLock<Option<Arc<String>>>,
    md5: RwLock<Option<Arc<String>>>,
}

impl HashedArtifact {
    pub fn new(bytes: Vec<u8>) -> HashedArtifact {
        HashedArtifact {
            bytes,
            sha256: RwLock::new(None),
            md5: RwLock::new(None),
            sha1: RwLock::new(None),
        }
    }

    fn lazy_init_hash<D: Digest>(
        &self,
        ptr: &RwLock<Option<Arc<String>>>,
        hash_name: &str,
    ) -> Arc<String> {
        {
            let lock = ptr.read().expect("rw lock panic");
            if let Some(hash) = lock.as_ref() {
                return hash.clone();
            }
        }
        let mut lock = ptr.write().expect("rw lock panic");
        if let Some(hash) = lock.as_ref() {
            hash.clone()
        } else {
            debug!("Computing {} for artifact...", hash_name);
            let mut hasher = D::new();
            hasher.update(&self.bytes);
            let hash = Arc::new(hex::encode(hasher.finalize()));
            *lock = Some(hash.clone());
            hash
        }
    }

    pub fn sha256(&self) -> Arc<String> {
        self.lazy_init_hash::<Sha256>(&self.sha256, "sha256sum")
    }

    pub fn sha1(&self) -> Arc<String> {
        self.lazy_init_hash::<Sha1>(&self.sha1, "sha1sum")
    }

    pub fn md5(&self) -> Arc<String> {
        self.lazy_init_hash::<Md5>(&self.md5, "md5sum")
    }

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
