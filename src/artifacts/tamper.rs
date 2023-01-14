use crate::compression::CompressedWith;
use crate::errors::*;
use crate::plot::{PatchAptReleaseConfig, PatchPkgDatabaseConfig, PlotExtras};
use crate::tamper;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "tamper", rename_all = "kebab-case")]
pub enum TamperArtifact {
    PatchAptRelease(PatchAptReleaseArtifact),
    PatchAptPackageList(PatchPkgDatabaseArtifact),
    PatchApkIndex(PatchApkIndexArtifact),
    PatchPacmanDb(PatchPacmanDbArtifact),
}

impl TamperArtifact {
    pub fn resolve(&self, plot_extras: &mut PlotExtras) -> Result<Vec<u8>> {
        match self {
            TamperArtifact::PatchAptRelease(tamper) => {
                let bytes = plot_extras
                    .artifacts
                    .get(&tamper.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            tamper.artifact
                        )
                    })?;

                let mut out = Vec::new();
                tamper::apt_release::patch(
                    &tamper.config,
                    &plot_extras.artifacts,
                    &plot_extras.signing_keys,
                    bytes.as_bytes(),
                    &mut out,
                )?;
                Ok(out)
            }
            TamperArtifact::PatchAptPackageList(tamper) => {
                let artifact = plot_extras
                    .artifacts
                    .get(&tamper.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            tamper.artifact
                        )
                    })?;

                let mut out = Vec::new();
                tamper::apt_package_list::patch(
                    &tamper.config,
                    tamper.compression,
                    &plot_extras.artifacts,
                    artifact.as_bytes(),
                    &mut out,
                )?;
                Ok(out)
            }
            TamperArtifact::PatchApkIndex(tamper) => {
                let artifact = plot_extras
                    .artifacts
                    .get(&tamper.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            tamper.artifact
                        )
                    })?;

                let mut out = Vec::new();
                tamper::apk::patch(
                    &tamper.config,
                    plot_extras,
                    &tamper.signing_key,
                    &tamper.signing_key_name,
                    artifact.as_bytes(),
                    &mut out,
                )?;
                Ok(out)
            }
            TamperArtifact::PatchPacmanDb(tamper) => {
                let artifact = plot_extras
                    .artifacts
                    .get(&tamper.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            tamper.artifact
                        )
                    })?;

                let mut out = Vec::new();
                tamper::pacman::patch(&tamper.config, plot_extras, artifact.as_bytes(), &mut out)?;
                Ok(out)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchAptReleaseArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: PatchAptReleaseConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchPkgDatabaseArtifact {
    pub artifact: String,
    pub compression: Option<CompressedWith>,
    #[serde(flatten)]
    pub config: PatchPkgDatabaseConfig<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchApkIndexArtifact {
    pub artifact: String,
    pub signing_key: String,
    pub signing_key_name: String,
    #[serde(flatten)]
    pub config: PatchPkgDatabaseConfig<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchPacmanDbArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: PatchPkgDatabaseConfig<Vec<String>>,
}
