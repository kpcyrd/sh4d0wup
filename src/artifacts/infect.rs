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
    ElfFwdStdin(InfectElfFwdStdinArtifact),
    Sh(InfectShArtifact),
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

                let elf_artifact = if let Some(name) = &infect.elf_artifact {
                    let elf_artifact = plot_extras.artifacts.get(name).with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            infect.artifact
                        )
                    })?;

                    Some(elf_artifact.as_bytes())
                } else {
                    None
                };

                let mut out = Vec::new();
                infect::elf::infect(&infect.config, artifact.as_bytes(), elf_artifact, &mut out)
                    .await?;
                Ok(out)
            }
            InfectArtifact::ElfFwdStdin(infect) => {
                let bytes = if let Some(artifact) = &infect.artifact {
                    let artifact = plot_extras.artifacts.get(artifact).with_context(|| {
                        anyhow!(
                            "Referencing artifact that doesn't exist: {:?}",
                            infect.artifact
                        )
                    })?;
                    artifact.as_bytes()
                } else if let Some(data) = &infect.data {
                    data.as_bytes()
                } else {
                    bail!("When using elf-fwd-stdin you need to provide either `artifact:` or `data:`");
                };

                let mut out = Vec::new();
                infect::elf_fwd_stdin::infect(&infect.config, bytes, &mut out).await?;
                Ok(out)
            }
            InfectArtifact::Sh(infect) => {
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
                infect::sh::infect(&infect.config, artifact.as_bytes(), &mut out).await?;
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
    pub elf_artifact: Option<String>,
    #[serde(flatten)]
    pub config: infect::elf::Infect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectElfFwdStdinArtifact {
    pub artifact: Option<String>,
    pub data: Option<String>,
    #[serde(flatten)]
    pub config: infect::elf_fwd_stdin::Infect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectShArtifact {
    pub artifact: String,
    #[serde(flatten)]
    pub config: infect::sh::Infect,
}
