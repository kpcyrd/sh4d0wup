use crate::args;
use crate::errors::*;
use data_encoding::BASE64;
use in_toto::crypto::{KeyType, PrivateKey, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeygenInToto {
    Embedded(InTotoEmbedded),
    Generate(InTotoGenerate),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InTotoEmbedded {
    pub public_key: Option<String>,
    pub secret_key: String,
}

impl InTotoEmbedded {
    pub fn read_from_disk<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        debug!("Reading in-toto secret key from path: {:?}", path);
        let secret_key = fs::read_to_string(path)
            .with_context(|| anyhow!("Failed to read from file {:?}", path))?;

        Ok(InTotoEmbedded {
            public_key: None,
            secret_key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InTotoGenerate {}

impl From<args::KeygenInToto> for InTotoGenerate {
    fn from(_in_toto: args::KeygenInToto) -> Self {
        Self {}
    }
}

pub fn generate(_config: &InTotoGenerate) -> Result<InTotoEmbedded> {
    debug!("Generating keypair...");
    let secret_key_buf =
        PrivateKey::new(KeyType::Ed25519).context("Failed to generate ed25519 key")?;
    let secret_key = PrivateKey::from_pkcs8(&secret_key_buf, SignatureScheme::Ed25519)
        .context("Failed to load generated key")?;

    let public_key = secret_key.public().as_bytes();
    let public_key = BASE64.encode(public_key);
    let secret_key = BASE64.encode(&secret_key_buf);

    Ok(InTotoEmbedded {
        public_key: Some(public_key),
        secret_key,
    })
}
