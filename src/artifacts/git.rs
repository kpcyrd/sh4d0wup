use crate::errors::*;
use crate::plot::Artifacts;
use git_object::WriteTo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "git", rename_all = "kebab-case")]
pub enum GitArtifact {
    Commit(git_object::Commit),
}

impl GitArtifact {
    pub fn resolve(&self, _artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            GitArtifact::Commit(commit) => {
                out.extend(&git_object::encode::loose_header(
                    commit.kind(),
                    commit.size(),
                ));
                commit.write_to(&mut out)?;
            }
        }
        Ok(out)
    }
}
