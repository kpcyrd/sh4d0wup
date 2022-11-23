use crate::compression::{self, CompressedWith};
use crate::errors::*;
use crate::infect;
use crate::plot::{Artifacts, PatchAptReleaseConfig, PatchPkgDatabaseConfig, SigningKeys};
use crate::sign;
use crate::tamper;
use crate::upstream;
use http::Method;
use maplit::hashset;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::mem;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Artifact {
    Path(PathArtifact),
    Url(UrlArtifact),
    Inline(InlineArtifact),
    Signature(SignatureArtifact),
    Infect(InfectArtifact),
    Tamper(TamperArtifact),
    Compress(CompressArtifact),
    Memory,
}

impl Artifact {
    pub fn depends_on(&self) -> Option<HashSet<&str>> {
        match self {
            Artifact::Path(_) => None,
            Artifact::Url(_) => None,
            Artifact::Inline(_) => None,
            Artifact::Signature(sign) => Some(hashset![sign.artifact.as_str()]),
            Artifact::Infect(InfectArtifact::Pacman(infect)) => {
                Some(hashset![infect.artifact.as_str()])
            }
            Artifact::Infect(InfectArtifact::Deb(infect)) => {
                Some(hashset![infect.artifact.as_str()])
            }
            Artifact::Tamper(TamperArtifact::PatchAptRelease(tamper)) => {
                let mut set = hashset![tamper.artifact.as_str()];
                for patch in &tamper.config.checksums.patch {
                    if let Some(artifact) = &patch.artifact {
                        set.insert(artifact);
                    }
                }
                Some(set)
            }
            Artifact::Tamper(TamperArtifact::PatchAptPackageList(tamper)) => {
                let mut set = hashset![tamper.artifact.as_str()];
                for patch in &tamper.config.patch {
                    if let Some(artifact) = &patch.artifact {
                        set.insert(artifact);
                    }
                }
                Some(set)
            }
            Artifact::Compress(compress) => Some(hashset![compress.artifact.as_str()]),
            Artifact::Memory => None,
        }
    }

    pub async fn resolve(
        &mut self,
        artifacts: &mut Artifacts,
        signing_keys: &SigningKeys,
    ) -> Result<Option<Vec<u8>>> {
        match self {
            Artifact::Path(_) => Ok(None),
            Artifact::Url(artifact) => {
                info!(
                    "Downloading artifact into memory: {:?}",
                    artifact.url.to_string()
                );
                let buf = artifact
                    .download()
                    .await
                    .context("Failed to resolve url artifact")?;
                *self = Artifact::Memory;
                Ok(Some(buf.to_vec()))
            }
            Artifact::Inline(inline) => {
                let data = mem::take(&mut inline.data);
                let bytes = data.into_bytes();
                Ok(Some(bytes))
            }
            Artifact::Signature(artifact) => {
                let sig = artifact
                    .resolve(artifacts, signing_keys)
                    .context("Failed to resolve signature artifact")?;
                Ok(Some(sig))
            }
            Artifact::Infect(artifact) => {
                info!("Infecting artifact...");
                let buf = artifact
                    .resolve(artifacts, signing_keys)
                    .context("Failed to infect artifact")?;
                Ok(Some(buf))
            }
            Artifact::Tamper(artifact) => {
                info!("Tampering with index...");
                let buf = artifact
                    .resolve(artifacts, signing_keys)
                    .context("Failed to tamper with artifact")?;
                Ok(Some(buf))
            }
            Artifact::Compress(artifact) => {
                info!("Compressing artifact...");
                let buf = artifact
                    .resolve(artifacts)
                    .context("Failed to tamper with artifact")?;
                Ok(Some(buf))
            }
            Artifact::Memory => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathArtifact {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlArtifact {
    pub url: Url,
    pub sha256: Option<String>,
}

impl UrlArtifact {
    pub async fn download(&self) -> Result<warp::hyper::body::Bytes> {
        let response = upstream::send_req(Method::GET, self.url.clone())
            .await?
            .error_for_status()?;
        let buf = response.bytes().await?;

        self.verify_sha256(&buf)?;

        Ok(buf)
    }

    pub fn verify_sha256(&self, bytes: &[u8]) -> Result<()> {
        if let Some(expected) = &self.sha256 {
            debug!("Calculating hash sum...");
            let mut h = Sha256::new();
            h.update(bytes);
            let h = hex::encode(h.finalize());
            debug!("Calcuated sha256: {:?}", h);
            debug!("Expected sha256: {:?}", expected);

            if h != *expected {
                bail!(
                    "Calculated sha256 {:?} doesn't match expected sha256 {:?}",
                    h,
                    expected
                );
            }

            Ok(())
        } else {
            trace!("No sha256 configured for url artifact, skipping pinning");
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineArtifact {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureArtifact {
    pub artifact: String,
    pub sign_with: String,
}

impl SignatureArtifact {
    pub fn resolve(
        &self,
        artifacts: &mut Artifacts,
        signing_keys: &SigningKeys,
    ) -> Result<Vec<u8>> {
        let artifact = artifacts.get(&self.artifact).with_context(|| {
            anyhow!(
                "Referencing artifact that doesn't exist: {:?}",
                self.artifact
            )
        })?;
        let key = signing_keys.get(&self.sign_with).with_context(|| {
            anyhow!(
                "Referencing signing key that doesn't exist: {:?}",
                self.sign_with
            )
        })?;
        let sig = sign::sign(artifact.as_bytes(), key).context("Failed to sign artifact")?;
        Ok(sig)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "infect")]
pub enum InfectArtifact {
    #[serde(rename = "pacman")]
    Pacman(InfectPacmanArtifact),
    #[serde(rename = "deb")]
    Deb(InfectDebArtifact),
}

impl InfectArtifact {
    pub fn resolve(
        &self,
        artifacts: &mut Artifacts,
        _signing_keys: &SigningKeys,
    ) -> Result<Vec<u8>> {
        match self {
            InfectArtifact::Pacman(infect) => {
                let artifact = artifacts.get(&infect.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        infect.artifact
                    )
                })?;

                let mut out = Vec::new();
                infect::pacman::infect(&infect.config, artifact.as_bytes(), &mut out)?;
                Ok(out)
            }
            InfectArtifact::Deb(infect) => {
                let artifact = artifacts.get(&infect.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        infect.artifact
                    )
                })?;

                let mut out = Vec::new();
                infect::deb::infect(&infect.config, artifact.as_bytes(), &mut out)?;
                Ok(out)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectPacmanArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: infect::pacman::Infect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectDebArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: infect::deb::Infect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "tamper")]
pub enum TamperArtifact {
    #[serde(rename = "patch-apt-release")]
    PatchAptRelease(PatchAptReleaseArtifact),
    #[serde(rename = "patch-apt-package-list")]
    PatchAptPackageList(PatchPkgDatabaseArtifact),
}

impl TamperArtifact {
    pub fn resolve(
        &self,
        artifacts: &mut Artifacts,
        signing_keys: &SigningKeys,
    ) -> Result<Vec<u8>> {
        match self {
            TamperArtifact::PatchAptRelease(tamper) => {
                let bytes = artifacts.get(&tamper.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        tamper.artifact
                    )
                })?;

                let mut out = Vec::new();
                tamper::apt_release::patch(
                    &tamper.config,
                    artifacts,
                    signing_keys,
                    bytes.as_bytes(),
                    &mut out,
                )?;
                Ok(out)
            }
            TamperArtifact::PatchAptPackageList(tamper) => {
                let artifact = artifacts.get(&tamper.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        tamper.artifact
                    )
                })?;

                let mut out = Vec::new();
                tamper::apt_package_list::patch(
                    &tamper.config,
                    tamper.compression,
                    artifacts,
                    signing_keys,
                    artifact.as_bytes(),
                    &mut out,
                )?;
                Ok(out)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAptReleaseArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: PatchAptReleaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPkgDatabaseArtifact {
    pub artifact: String,
    pub compression: Option<CompressedWith>,
    #[serde(flatten)]
    pub config: PatchPkgDatabaseConfig<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressArtifact {
    pub artifact: String,
    pub compression: CompressedWith,
}

impl CompressArtifact {
    pub fn resolve(&self, artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        let artifact = artifacts.get(&self.artifact).with_context(|| {
            anyhow!(
                "Referencing artifact that doesn't exist: {:?}",
                self.artifact
            )
        })?;
        compression::compress(self.compression, artifact.as_bytes())
    }
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
