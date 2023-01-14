use crate::compression::{self, CompressedWith};
use crate::errors::*;
use crate::plot::Artifacts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
