use crate::args;
use crate::errors::*;
use osshkeys::cipher::Cipher;
use osshkeys::keys::{KeyPair, KeyType};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeygenSsh {
    Embedded(SshEmbedded),
    Generate(SshGenerate),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshEmbedded {
    pub public_key: Option<String>,
    pub secret_key: String,
}

impl SshEmbedded {
    pub fn read_from_disk<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        debug!("Reading ssh key from path: {:?}", path);
        let secret_key = fs::read_to_string(path)
            .with_context(|| anyhow!("Failed to read from file {:?}", path))?;
        Ok(SshEmbedded {
            public_key: None,
            secret_key,
        })
    }

    pub fn to_cert(&self) -> Result<Vec<u8>> {
        let seckey = KeyPair::from_keystr(&self.secret_key, None)
            .context("Failed to parse secret ssh key")?;
        let pubkey = seckey
            .clone_public_key()
            .context("Failed to derive public key from secret key")?;
        let public_key = pubkey.serialize()?;
        Ok(public_key.into_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeypairType {
    Rsa,
    Dsa,
    Ecdsa,
    Ed25519,
}

impl KeypairType {
    pub fn default_bit_size(&self) -> usize {
        match self {
            KeypairType::Rsa => 4096,
            KeypairType::Dsa => 1024,
            KeypairType::Ecdsa => 256,
            KeypairType::Ed25519 => 256,
        }
    }
}

impl FromStr for KeypairType {
    type Err = Error;

    fn from_str(s: &str) -> Result<KeypairType> {
        Ok(match s {
            "rsa" => KeypairType::Rsa,
            "dsa" => KeypairType::Dsa,
            "ecdsa" => KeypairType::Ecdsa,
            "ed25519" => KeypairType::Ed25519,
            _ => bail!("Unsupported key type: {:?}", s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshGenerate {
    pub keypair_type: KeypairType,
    pub bits: Option<usize>,
}

impl TryFrom<args::KeygenSsh> for SshGenerate {
    type Error = Error;

    fn try_from(ssh: args::KeygenSsh) -> Result<Self> {
        Ok(Self {
            keypair_type: ssh.keytype,
            bits: ssh.bits,
        })
    }
}

pub fn generate(config: &SshGenerate) -> Result<SshEmbedded> {
    let keypair_type = config.keypair_type;
    let bits = config.bits.unwrap_or_else(|| keypair_type.default_bit_size());
    debug!("Generating {bits} bit {keypair_type:?} keypair...");
    let kt = match config.keypair_type {
        KeypairType::Rsa => KeyType::RSA,
        KeypairType::Dsa => KeyType::DSA,
        KeypairType::Ecdsa => KeyType::ECDSA,
        KeypairType::Ed25519 => KeyType::ED25519,
    };
    let seckey = KeyPair::generate(kt, bits).context("Failed to generate keypair")?;

    let pubkey = seckey
        .clone_public_key()
        .context("Failed to derive public key from secret key")?;

    let secret_key = seckey.serialize_openssh(None, Cipher::Null)?;
    let public_key = pubkey.serialize()?;

    Ok(SshEmbedded {
        public_key: Some(public_key),
        secret_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ssh_keys() -> Result<()> {
        for keypair_type in [
            KeypairType::Rsa,
            KeypairType::Dsa,
            KeypairType::Ecdsa,
            KeypairType::Ed25519,
        ] {
            let config = SshGenerate {
                keypair_type,
                bits: None,
            };
            generate(&config)?;
        }
        Ok(())
    }
}
