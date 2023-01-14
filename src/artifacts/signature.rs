use crate::errors::*;
use crate::plot::PlotExtras;
use crate::sign;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureArtifact {
    pub artifact: String,
    pub sign_with: String,
}

impl SignatureArtifact {
    pub fn resolve(&self, plot_extras: &mut PlotExtras) -> Result<Vec<u8>> {
        let artifact = plot_extras.artifacts.get(&self.artifact).with_context(|| {
            anyhow!(
                "Referencing artifact that doesn't exist: {:?}",
                self.artifact
            )
        })?;
        let key = plot_extras
            .signing_keys
            .get(&self.sign_with)
            .with_context(|| {
                anyhow!(
                    "Referencing signing key that doesn't exist: {:?}",
                    self.sign_with
                )
            })?;
        let sig = sign::sign(artifact.as_bytes(), key).context("Failed to sign artifact")?;
        Ok(sig)
    }
}
