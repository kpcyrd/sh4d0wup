use crate::errors::*;
use crate::plot::Artifacts;
use bstr::BString;
use git_hash::ObjectId;
use git_object::tree::EntryMode;
use git_object::WriteTo;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::io::Write;
use std::sync::mpsc;
use std::thread;

const STEP: usize = 25_000;

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
    #[serde(default)]
    pub extra_headers: Vec<(BString, BString)>,
    pub message: BString,
    pub collision_prefix: Option<String>,
    pub nonce: Option<String>,
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
        let mut extra_headers = self.extra_headers.clone();
        if let Some(nonce) = &self.nonce {
            extra_headers.push(("nonce".into(), nonce.as_str().into()));
        }
        let mut commit = git_object::Commit {
            tree,
            parents,
            author,
            committer,
            message: self.message.clone(),
            encoding: None,
            extra_headers,
        };

        if let Some(prefix) = &self.collision_prefix {
            Self::bruteforce_partial_collision(&mut commit, prefix)?;
        }

        out.extend(&git_object::encode::loose_header(
            commit.kind(),
            commit.size(),
        ));
        commit.write_to(out)?;

        Ok(())
    }

    pub fn try_nonce_for_commit(
        commit: &mut git_object::Commit,
        commit_buf: &mut Vec<u8>,
        prefix: &str,
        idx: usize,
        nonce: usize,
    ) -> Result<Option<String>> {
        let mut nonce_buf = BString::new(vec![]);
        write!(nonce_buf, "{}", nonce)?;
        commit.extra_headers[idx].1 = nonce_buf;

        commit_buf.clear();
        commit_buf.extend(&git_object::encode::loose_header(
            commit.kind(),
            commit.size(),
        ));
        commit.write_to(commit_buf as &mut Vec<u8>)?;

        let mut sha1 = Sha1::new();
        sha1.update(&commit_buf);
        let hash = sha1.finalize();

        // only hex encode what we use
        let mut n = prefix.len();
        n += n % 2;
        n /= 2;

        let short_hash = hex::encode(&hash[..n]);
        if short_hash.starts_with(prefix) {
            // hex encode the whole hash this time
            let hash = hex::encode(hash);
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    pub fn bruteforce_partial_collision(
        commit: &mut git_object::Commit,
        prefix: &str,
    ) -> Result<()> {
        info!(
            "Starting bruteforce of partial collision for git commit... (prefix={:?})",
            prefix
        );

        let idx = commit.extra_headers.len();
        commit.extra_headers.push(("nonce".into(), "".into()));

        let mut workers = Vec::new();
        let (ctr_tx, ctr_rx) = mpsc::sync_channel::<Option<mpsc::Sender<usize>>>(1);
        workers.push(thread::spawn(|| {
            let mut ctr = 0;
            for req in ctr_rx {
                if let Some(req) = req {
                    debug!("Assigning chunk to worker: {:?}", ctr);
                    req.send(ctr).ok();
                    ctr += STEP;
                } else {
                    // this is our shutdown signal, dropping our sender to shutdown workers
                    break;
                }
            }
        }));

        let (found_tx, found_rx) = mpsc::sync_channel(1);
        for worker_num in 0..num_cpus::get() {
            debug!("Starting bruteforce worker #{}", worker_num);
            let ctr_tx = ctr_tx.clone();
            let found_tx = found_tx.clone();
            let mut commit = commit.clone();
            let prefix = prefix.to_string();

            workers.push(thread::spawn(move || {
                let mut commit_buf = Vec::new();
                'outer: loop {
                    let (tx, rx) = mpsc::channel();
                    let Ok(()) = ctr_tx.send(Some(tx)) else { break };
                    let Ok(start) = rx.recv() else { break };

                    let end = start + STEP;
                    for nonce in start..end {
                        match Self::try_nonce_for_commit(
                            &mut commit,
                            &mut commit_buf,
                            &prefix,
                            idx,
                            nonce,
                        ) {
                            Ok(Some(hash)) => {
                                debug!("Trying to inform main thread about partial colliding hash: {:?}", hash);
                                if found_tx.send((hash.clone(), commit)).is_err() {
                                    debug!("Hash wasn't selected, discarding: {:?}", hash);
                                }
                                break 'outer;
                            }
                            Ok(None) => (),
                            Err(err) => error!("Error in worker thread: {:#}", err),
                        }
                    }
                }
            }));
        }

        let (hash, found) = found_rx
            .recv()
            .context("Failed to receive result from workers")?;
        drop(found_rx);
        info!("Found colliding hash: {:?} (prefix={:?})", hash, prefix);

        ctr_tx
            .send(None)
            .map_err(|_| anyhow!("Failed to send shutdown signal to worker"))?;
        drop(ctr_tx);

        debug!("Waiting for workers to shutdown");
        for worker in workers {
            worker
                .join()
                .map_err(|_| anyhow!("Failed to wait for thread"))?;
        }
        debug!("All workers have terminated");

        *commit = found;

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
            extra_headers: Vec::new(),
            message: "Release v0.3.0\n".into(),
            collision_prefix: None,
            nonce: None,
        };
        let mut out = Vec::new();
        commit.encode(&mut out, &Default::default()).unwrap();

        let mut sha1 = Sha1::new();
        sha1.update(&out);
        let hash = hex::encode(sha1.finalize());
        assert_eq!(hash, "248bc188602dc3552b1c15634afd7592b88ed4bd");
    }
}
