use crate::errors::*;
use crate::infect;
use crate::plot::{Artifacts, SigningKeys};
use crate::sign;
use crate::upstream;
use http::Method;
use maplit::hashset;
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
    Memory,
}

impl Artifact {
    pub fn depends_on(&self) -> Option<HashSet<&str>> {
        match self {
            Artifact::Path(_) => None,
            Artifact::Url(_) => None,
            Artifact::Inline(_) => None,
            Artifact::Signature(artifact) => Some(hashset![artifact.artifact.as_str()]),
            Artifact::Infect(InfectArtifact::Pacman(artifact)) => {
                Some(hashset![artifact.artifact.as_str()])
            }
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
                let buf = artifact
                    .resolve(artifacts, signing_keys)
                    .context("Failed to infect artifact")?;
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
        let response = upstream::send_req(Method::GET, self.url.clone()).await?;
        let buf = response.bytes().await?;

        if let Some(expected) = &self.sha256 {
            debug!("Calculating hash sum...");
            let mut h = Sha256::new();
            h.update(&buf);
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
        }

        Ok(buf)
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
        let bytes = artifacts.get(&self.artifact).with_context(|| {
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
        let sig = sign::sign(bytes, key).context("Failed to sign artifact")?;
        Ok(sig)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "infect")]
pub enum InfectArtifact {
    #[serde(rename = "pacman")]
    Pacman(InfectPacmanArtifact),
}

impl InfectArtifact {
    pub fn resolve(
        &self,
        artifacts: &mut Artifacts,
        _signing_keys: &SigningKeys,
    ) -> Result<Vec<u8>> {
        match self {
            InfectArtifact::Pacman(infect) => {
                let bytes = artifacts.get(&infect.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        infect.artifact
                    )
                })?;

                let mut out = Vec::new();
                infect::pacman::infect(&infect.infect, bytes, &mut out)?;
                Ok(out)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectPacmanArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub infect: infect::pacman::Infect,
}
