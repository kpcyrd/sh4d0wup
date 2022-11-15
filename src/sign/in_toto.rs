use crate::args;
use crate::errors::*;
use crate::keygen::in_toto::InTotoEmbedded;
use in_toto::crypto::{self, HashAlgorithm, HashValue, PrivateKey, SignatureScheme};
use in_toto::interchange::Json;
use in_toto::models::{LinkMetadataBuilder, VirtualTargetPath};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug)]
pub struct SigningConfig {
    pub name: String,
    pub materials: Vec<VirtualEntry>,
    pub products: Vec<VirtualEntry>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VirtualEntry {
    pub name: String,
    pub path: PathBuf,
}

impl FromStr for VirtualEntry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (name, path) = s
            .split_once('=')
            .context("Invalid format, expected `name=/path/to/file.txt`")?;
        Ok(VirtualEntry {
            name: name.into(),
            path: path.into(),
        })
    }
}

impl TryFrom<args::SignInToto> for SigningConfig {
    type Error = Error;

    fn try_from(in_toto: args::SignInToto) -> Result<Self> {
        Ok(Self {
            name: in_toto.name,
            materials: in_toto.material,
            products: in_toto.product,
        })
    }
}

pub fn read_artifact(
    name: String,
    path: &Path,
) -> Result<(VirtualTargetPath, HashMap<HashAlgorithm, HashValue>)> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let hash_algorithms = &[HashAlgorithm::Sha256];
    let (_length, hashes) = crypto::calculate_hashes(&mut reader, hash_algorithms)?;
    Ok((VirtualTargetPath::new(name)?, hashes))
}

pub fn sign(signer: &InTotoEmbedded, config: &SigningConfig) -> Result<Vec<u8>> {
    let secret_key =
        base64::decode(signer.secret_key.trim()).context("Failed to decode signing key")?;
    let secret_key = PrivateKey::from_pkcs8(&secret_key, SignatureScheme::Ed25519)
        .context("Failed to load signing key")?;

    let materials = config
        .materials
        .iter()
        .map(|e| read_artifact(e.name.to_string(), &e.path))
        .collect::<Result<_>>()
        .context("Failed to collect materials")?;

    let products = config
        .products
        .iter()
        .map(|e| read_artifact(e.name.to_string(), &e.path))
        .collect::<Result<_>>()
        .context("Failed to collect materials")?;

    let link_metadata_builder = LinkMetadataBuilder::new()
        .name(config.name.to_string())
        .materials(materials)
        .products(products);

    let attestation = link_metadata_builder.signed::<Json>(&secret_key)?;

    let buf = serde_json::to_vec(&attestation)?;
    Ok(buf)
}
