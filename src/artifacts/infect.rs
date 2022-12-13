use crate::errors::*;
use crate::infect;
use crate::plot::PlotExtras;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "infect", rename_all = "kebab-case")]
pub enum InfectArtifact {
    Pacman(InfectPacmanArtifact),
    Deb(InfectDebArtifact),
    Apk(InfectApkArtifact),
    Elf(InfectElfArtifact),
}

impl InfectArtifact {
    pub async fn resolve(&self, plot_extras: &mut PlotExtras) -> Result<Vec<u8>> {
        match self {
            InfectArtifact::Pacman(infect) => {
                let artifact = plot_extras
                    .artifacts
                    .get(&infect.artifact)
                    .with_context(|| {
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
                let artifact = plot_extras
                    .artifacts
                    .get(&infect.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            infect.artifact
                        )
                    })?;

                let mut out = Vec::new();
                infect::deb::infect(&infect.config, artifact.as_bytes(), &mut out)?;
                Ok(out)
            }
            InfectArtifact::Apk(infect) => {
                let artifact = plot_extras
                    .artifacts
                    .get(&infect.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            infect.artifact
                        )
                    })?;

                let mut out = Vec::new();
                infect::apk::infect(
                    &infect.config,
                    &plot_extras.signing_keys,
                    artifact.as_bytes(),
                    &mut out,
                )?;
                Ok(out)
            }
            InfectArtifact::Elf(infect) => {
                let artifact = plot_extras
                    .artifacts
                    .get(&infect.artifact)
                    .with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            infect.artifact
                        )
                    })?;

                let mut out = Vec::new();
                infect::elf::infect(&infect.config, artifact.as_bytes(), &mut out).await?;
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
pub struct InfectApkArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: infect::apk::Infect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectElfArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: infect::elf::Infect,
}
