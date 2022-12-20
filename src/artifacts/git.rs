use crate::errors::*;
use crate::plot::Artifacts;
use git_hash::ObjectId;
use git_object::tree::EntryMode;
use git_object::WriteTo;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "git", rename_all = "kebab-case")]
pub enum GitArtifact {
    Commit(Commit),
    Tree(Tree),
    Blob(Blob),
    RefList(RefList),
}

impl GitArtifact {
    pub fn resolve(&self, artifacts: &mut Artifacts) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            GitArtifact::Commit(commit) => commit.encode(&mut out, artifacts)?,
            GitArtifact::Tree(tree) => tree.encode(&mut out, artifacts)?,
            GitArtifact::Blob(blob) => blob.encode(&mut out, artifacts)?,
            GitArtifact::RefList(refs) => refs.encode(&mut out, artifacts)?,
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Oid {
    Inline(String),
    Artifact(ArtifactOid),
}

impl Oid {
    pub fn resolve_oid(&self, artifacts: &Artifacts) -> Result<ObjectId> {
        let oid = match self {
            Oid::Inline(s) => {
                ObjectId::from_hex(s.as_bytes()).context("Failed to decode parent id")?
            }
            Oid::Artifact(oid) => {
                let artifact = artifacts.get(&oid.artifact).with_context(|| {
                    anyhow!(
                        "Referencing artifact that doesn't exist: {:?}",
                        oid.artifact
                    )
                })?;
                Oid::hash(artifact.as_bytes())
            }
        };
        Ok(oid)
    }

    pub fn hash(bytes: &[u8]) -> ObjectId {
        let mut sha1 = Sha1::new();
        sha1.update(bytes);
        let hash = sha1.finalize();
        ObjectId::from(&hash[..])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactOid {
    pub artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub tree: Oid,
    #[serde(default)]
    pub parents: Vec<Oid>,
    pub author: String,
    pub committer: String,
    pub message: String,
}

impl Commit {
    pub fn encode(&self, out: &mut Vec<u8>, artifacts: &Artifacts) -> Result<()> {
        let tree = self.tree.resolve_oid(artifacts)?;
        let author = git_actor::SignatureRef::from_bytes::<()>(self.author.as_bytes())
            .context("Failed to parse author")?
            .to_owned();
        let committer = git_actor::SignatureRef::from_bytes::<()>(self.committer.as_bytes())
            .context("Failed to parse committer")?
            .to_owned();
        let parents = self
            .parents
            .iter()
            .map(|o| o.resolve_oid(artifacts))
            .collect::<Result<_>>()?;
        let commit = git_object::Commit {
            tree,
            parents,
            author,
            committer,
            message: self.message.clone().into(),
            encoding: None,
            extra_headers: Vec::new(),
        };
        out.extend(&git_object::encode::loose_header(
            commit.kind(),
            commit.size(),
        ));
        commit.write_to(out)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn encode(&self, out: &mut Vec<u8>, artifacts: &Artifacts) -> Result<()> {
        let entries = self
            .entries
            .iter()
            .map(|e| e.resolve(artifacts))
            .collect::<Result<_>>()?;
        let tree = git_object::Tree { entries };
        out.extend(&git_object::encode::loose_header(tree.kind(), tree.size()));
        tree.write_to(out)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub mode: String,
    pub filename: String,
    pub oid: Oid,
}

impl TreeEntry {
    pub fn resolve(&self, artifacts: &Artifacts) -> Result<git_object::tree::Entry> {
        let mode = match self.mode.as_str() {
            "tree" => EntryMode::Tree,
            "blob" => EntryMode::Blob,
            "blob-executable" => EntryMode::BlobExecutable,
            "link" => EntryMode::Link,
            "commit" => EntryMode::Commit,
            unknown => bail!("Unknown tree entry mode: {:?}", unknown),
        };
        let oid = self.oid.resolve_oid(artifacts)?;
        Ok(git_object::tree::Entry {
            mode,
            filename: self.filename.clone().into(),
            oid,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blob {
    pub data: Option<String>,
    pub artifact: Option<String>,
}

impl Blob {
    pub fn encode(&self, out: &mut Vec<u8>, artifacts: &Artifacts) -> Result<()> {
        let data = self.resolve(artifacts)?;
        let blob = git_object::BlobRef { data };
        out.extend(&git_object::encode::loose_header(blob.kind(), blob.size()));
        blob.write_to(out)?;
        Ok(())
    }

    pub fn resolve<'a>(&'a self, artifacts: &'a Artifacts) -> Result<&'a [u8]> {
        match (&self.data, &self.artifact) {
            (Some(_), Some(_)) => bail!("Git blob can't have both data and artifact reference"),
            (Some(data), None) => Ok(data.as_bytes()),
            (None, Some(artifact)) => {
                let artifact = artifacts.get(artifact).with_context(|| {
                    anyhow!("Referencing artifact that doesn't exist: {:?}", artifact)
                })?;
                Ok(artifact.as_bytes())
            }
            (None, None) => bail!("Git blob has neither data nor artifact reference"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefList {
    pub refs: IndexMap<String, Oid>,
}

impl RefList {
    pub fn encode(&self, out: &mut Vec<u8>, artifacts: &Artifacts) -> Result<()> {
        for (k, v) in &self.refs {
            let oid = v.resolve_oid(artifacts)?;
            writeln!(out, "{}\t{}", oid, k)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_encode() {
        let commit = Commit {
            tree: Oid::Inline("14e41dda390b0ec5a35a42f3ecadb97ca18ff32e".to_string()),
            parents: vec![Oid::Inline(
                "e98fe89d6eef1a8da9663dda20317eebebffe57b".to_string(),
            )],
            author: "kpcyrd <git@rxv.cc> 1637076383 +0100".to_string(),
            committer: "kpcyrd <git@rxv.cc> 1637076383 +0100".to_string(),
            message: "Release v0.3.0\n".to_string(),
        };
        let mut out = Vec::new();
        commit.encode(&mut out, &Default::default()).unwrap();

        let mut sha1 = Sha1::new();
        sha1.update(&out);
        let hash = hex::encode(sha1.finalize());
        assert_eq!(hash, "248bc188602dc3552b1c15634afd7592b88ed4bd");
    }
}
