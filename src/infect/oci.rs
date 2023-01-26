use crate::args;
use crate::errors::*;
use blake2::Blake2b512;
use oci_spec::image::Config as ImageConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::str;
use tar::{Archive, Builder};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct LayerConfig {
    config: Option<ImageConfig>,
    rootfs: Option<RootFs>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

impl LayerConfig {
    pub fn set_id(&mut self, value: String) {
        self.extra
            .insert("id".to_string(), serde_json::Value::String(value));
    }

    pub fn set_parent(&mut self, value: String) {
        self.extra
            .insert("parent".to_string(), serde_json::Value::String(value));
    }

    pub fn set_entrypoint(&mut self, value: Vec<String>) {
        if let Some(config) = &mut self.config {
            config.set_entrypoint(Some(value));
        }
    }

    pub fn add_rootfs_diff(&mut self, value: String) {
        if let Some(rootfs) = &mut self.rootfs {
            rootfs.diff_ids.push(value);
        }
    }

    pub fn user(&self) -> Option<&String> {
        let config = self.config.as_ref()?;
        config.user().as_ref()
    }

    pub fn entrypoint(&self) -> Option<&[String]> {
        let config = self.config.as_ref()?;
        let entrypoint = config.entrypoint().as_deref()?;
        Some(entrypoint)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct RootFs {
    pub r#type: String,
    pub diff_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "Config")]
    pub config: String,
    #[serde(rename = "Layers")]
    pub layers: Vec<String>,
    #[serde(rename = "RepoTags")]
    pub repo_tags: Vec<String>,
}

pub fn generate_entrypoint_hook(payload: &str, entrypoint: Option<&[String]>) -> String {
    let mut exec = Vec::new();
    if let Some(entrypoint) = entrypoint {
        for arg in entrypoint {
            exec.push(shell_escape::escape(Cow::Borrowed(arg)).to_string());
        }
    }
    exec.push("\"$@\"".to_string());
    let buf = format!("#!/bin/sh\n{}\nexec {}\n", payload, exec.join(" "));
    debug!("Generated entrypoint hook: {:?}", buf);
    buf
}

pub fn generate_layer_fs_data(
    path: &str,
    payload: &str,
    entrypoint: Option<&[String]>,
) -> Result<(String, Vec<u8>)> {
    info!("Generating filesystem layer for payload: {:?}", payload);
    let mut layer_data = Vec::new();
    {
        let buf = generate_entrypoint_hook(payload, entrypoint);
        let buf = buf.as_bytes();
        let mut builder = tar::Builder::new(&mut layer_data);
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o755);
        header.set_path(path)?;
        header.set_size(buf.len() as u64);
        header.set_cksum();
        builder.append(&header, &mut &buf[..])?;
        builder.finish()?;
    }

    let mut rootfs_hash = Sha256::new();
    rootfs_hash.update(&layer_data);
    let rootfs_hash = rootfs_hash.finalize();
    let rootfs_hash = format!("sha256:{}", hex::encode(rootfs_hash));

    Ok((rootfs_hash, layer_data))
}

pub fn write_tar_entry<W: Write>(
    builder: &mut Builder<W>,
    header: &mut tar::Header,
    id: &str,
    key: &str,
    buf: &[u8],
) -> Result<()> {
    header.set_path(format!("{id}/{key}"))?;
    header.set_size(buf.len() as u64);
    header.set_cksum();
    builder.append(header, &mut &buf[..])?;
    Ok(())
}

// this gives us a filename in a way that's guaranteed to not conflict
pub fn hash_rootfs(args: &args::InfectOci, layer: &LayerConfig) -> Result<String> {
    let rootfs = layer
        .rootfs
        .as_ref()
        .context("Layer config has no rootfs we can hash")?;

    let mut hasher = Blake2b512::new();
    for id in &rootfs.diff_ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }

    let res = hasher.finalize();
    let mut id = hex::encode(&res[..]);
    id.truncate(args.entrypoint_hash_len);
    Ok(id)
}

pub fn write_patch_layer<W: Write>(
    builder: &mut Builder<W>,
    args: &args::InfectOci,
    mut config: LayerConfig,
    parent: &str,
) -> Result<(String, Option<String>)> {
    let id = "patched".to_string();

    if let Some(user) = &config.user() {
        if !user.is_empty() {
            info!("User is set: {:?}", user);
        }
    }

    if let Some(entrypoint) = &config.entrypoint() {
        info!("Entrypoint is set: {:?}", entrypoint);
    }

    info!("Creating new layer in image: {:?}", id);
    config.set_id(id.to_string());
    config.set_parent(parent.to_string());
    if let Some(payload) = &args.payload {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o755);
        header.set_path(format!("{id}/"))?;
        header.set_cksum();
        builder.append(&header, &mut io::empty())?;

        let entrypoint_name = if let Some(entrypoint) = &args.entrypoint {
            entrypoint
                .strip_prefix('/')
                .unwrap_or(entrypoint)
                .to_string()
        } else {
            hash_rootfs(args, &config)?
        };
        let (rootfs_hash, layer_data) =
            generate_layer_fs_data(&entrypoint_name, payload, config.entrypoint())?;

        let buf = "1.0";
        debug!("Adding version to layer: {:?}", buf);
        header.set_mode(0o644);
        write_tar_entry(builder, &mut header, &id, "VERSION", buf.as_bytes())?;

        debug!("Generating metadata...");
        config.set_entrypoint(vec![format!("/{entrypoint_name}")]);
        config.add_rootfs_diff(rootfs_hash);
        let buf = serde_json::to_string(&config)?;
        debug!("Adding metadata to layer: {:?}", buf);
        write_tar_entry(builder, &mut header, &id, "json", buf.as_bytes())?;

        debug!("Adding fs data to layer");
        write_tar_entry(builder, &mut header, &id, "layer.tar", &layer_data)?;
        Ok((format!("{id}/json"), Some(format!("{id}/layer.tar"))))
    } else {
        let buf = serde_json::to_string(&config)?;
        debug!("Adding metadata to layer: {:?}", buf);
        let buf = buf.as_bytes();

        let path = format!("{id}.json");
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_path(&path)?;
        header.set_size(buf.len() as u64);
        header.set_cksum();
        builder.append(&header, &mut &buf[..])?;

        Ok((path, None))
    }
}

pub fn layer_id_from_filename(filename: &str) -> Result<&str> {
    if let Some(id) = filename.strip_suffix("/layer.tar") {
        Ok(id)
    } else if let Some(id) = filename.strip_suffix(".tar") {
        Ok(id)
    } else {
        bail!("Can't detect id of parent layer")
    }
}

pub fn infect<W: Write>(args: &args::InfectOci, pkg: &[u8], out: &mut W) -> Result<()> {
    let mut archive = Archive::new(pkg);
    let mut builder = tar::Builder::new(out);

    let mut config_map = HashMap::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let mut header = entry.header().clone();
        debug!("Found entry in tar: {:?}", header.path());

        match header.path()?.to_str() {
            Some("manifest.json") => {
                let mut buf = String::new();
                entry.read_to_string(&mut buf)?;
                trace!("Read manifest from image: {:?}", buf);

                let mut manifests = serde_json::from_str::<Vec<Manifest>>(&buf)
                    .context("Failed to parse image layer json")?;
                debug!("Parsed image manifests: {:?}", manifests);

                let mut manifest = manifests.pop().context("Image has no manifest items")?;
                if !manifests.is_empty() {
                    bail!("Image has more than one manifest item");
                }

                let config = config_map
                    .remove(&manifest.config)
                    .context("Manifest is referencing a config we don't know about")?;

                info!(
                    "Original image is referencing config {:?}: {:?}",
                    &manifest.config, config
                );

                let parent = layer_id_from_filename(
                    manifest
                        .layers
                        .last()
                        .context("Image manifest has no layers")?,
                )?;

                let (config_path, layer_path) =
                    write_patch_layer(&mut builder, args, config, parent)
                        .context("Failed to add patch layer")?;

                if !args.tags.is_empty() {
                    info!("Updating tags of image to {:?}", args.tags);
                    manifest.repo_tags = args.tags.clone();
                }

                info!("Writing modified manifest...");
                manifest.config = config_path;
                if let Some(layer_path) = layer_path {
                    manifest.layers.push(layer_path);
                }
                let buf = serde_json::to_string(&[&manifest])?;
                debug!("Modified manifest: {:?}", buf);
                let buf = buf.as_bytes();
                header.set_size(buf.len() as u64);
                header.set_cksum();
                builder.append(&header, &mut &buf[..])?;
            }
            Some("repositories") => {
                builder.append(&header, &mut entry)?;
            }
            None => bail!("Invalid filename encoding in image"),
            Some(name) => {
                if name.ends_with("json") {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf)?;
                    trace!("Read json from layer: {:?}", buf);

                    let layer = serde_json::from_str::<LayerConfig>(&buf)
                        .context("Failed to parse image layer json")?;
                    debug!("Parsed layer metadata: {:?}", layer);

                    config_map.insert(name.to_string(), layer);

                    builder.append(&header, &mut buf.as_bytes())?;
                } else {
                    builder.append(&header, &mut entry)?;
                }
            }
        }
    }

    builder.finish()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_entrypoint_hook_scratch() {
        let hook = generate_entrypoint_hook("echo hello world", None);
        assert_eq!(hook, "#!/bin/sh\necho hello world\nexec \"$@\"\n");
    }

    #[test]
    fn test_generate_entrypoint_hook_simple() {
        let hook = generate_entrypoint_hook("echo hello world", Some(&["/foo/bar".to_string()]));
        assert_eq!(hook, "#!/bin/sh\necho hello world\nexec /foo/bar \"$@\"\n");
    }

    #[test]
    fn test_generate_entrypoint_hook_tricky() {
        let hook = generate_entrypoint_hook(
            "echo hello world",
            Some(&["echo".to_string(), "hello $world\n".to_string()]),
        );
        assert_eq!(
            hook,
            "#!/bin/sh\necho hello world\nexec echo 'hello $world\n' \"$@\"\n"
        );
    }

    #[test]
    fn test_layer_id_from_filename() -> Result<()> {
        assert_eq!(
            layer_id_from_filename(
                "2f7048230bc73ff091490aa5764f9c160d1a4efe04935da731a22e8d5fcccfcc.tar"
            )?,
            "2f7048230bc73ff091490aa5764f9c160d1a4efe04935da731a22e8d5fcccfcc"
        );
        assert_eq!(
            layer_id_from_filename(
                "df829f9c635ceba6eeeac38345533af768999a177e86a235aaf650529affc415/layer.tar"
            )?,
            "df829f9c635ceba6eeeac38345533af768999a177e86a235aaf650529affc415"
        );
        Ok(())
    }
}
