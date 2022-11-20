use crate::errors::*;
use crate::plot::{Artifacts, SigningKeys};
use crate::sign;
use crate::upstream;
use http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Artifact {
    Path(PathArtifact),
    Url(UrlArtifact),
    Inline(InlineArtifact),
    Signature(SignatureArtifact),
    Memory,
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
        // TODO: this might be an ordering issue and the artifact is created further in the list
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
