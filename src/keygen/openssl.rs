use crate::args;
use crate::errors::*;
use openssl::ec::{EcGroup, EcKey};
use openssl::pkey::{self, PKey};
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeygenOpenssl {
    Embedded(OpensslEmbedded),
    Generate(OpensslGenerate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpensslEmbedded {
    pub public_key: Option<String>,
    pub secret_key: String,
}

impl OpensslEmbedded {
    pub fn read_from_disk<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        debug!("Reading openssl secret key from path: {:?}", path);
        let secret_key = fs::read_to_string(path)
            .with_context(|| anyhow!("Failed to read openssl secret key from file {:?}", path))?;

        Ok(OpensslEmbedded {
            public_key: None,
            secret_key,
        })
    }

    pub fn key_algo_id(&self) -> Result<&'static str> {
        let keypair = PKey::private_key_from_pem(self.secret_key.as_bytes())
            .context("Failed to load openssl key")?;
        match keypair.id() {
            pkey::Id::RSA => Ok("RSA"),
            id => bail!("Unknown key type: {:?}", id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeypairType {
    Rsa,
    Secp256k1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpensslGenerate {
    pub keypair_type: KeypairType,
    pub bits: Option<u32>,
}

impl TryFrom<args::KeygenOpenssl> for OpensslGenerate {
    type Error = Error;

    fn try_from(openssl: args::KeygenOpenssl) -> Result<Self> {
        let keypair_type = if openssl.rsa {
            KeypairType::Rsa
        } else if openssl.secp256k1 {
            KeypairType::Secp256k1
        } else {
            bail!("No keypair type selected")
        };
        Ok(Self {
            keypair_type,
            bits: openssl.bits,
        })
    }
}

pub fn generate(config: &OpensslGenerate) -> Result<OpensslEmbedded> {
    debug!("Generating keypair...");
    let pkey = match config.keypair_type {
        KeypairType::Rsa => {
            let bits = config.bits.context("Missing bits option for rsa")?;
            let rsa = Rsa::generate(bits)?;
            PKey::from_rsa(rsa)?
        }
        KeypairType::Secp256k1 => {
            let group = EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)?;
            let secp256k1 = EcKey::generate(&group)?;
            PKey::from_ec_key(secp256k1)?
        }
    };

    let public_key = String::from_utf8(pkey.public_key_to_pem()?)?;
    let secret_key = String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?;

    Ok(OpensslEmbedded {
        public_key: Some(public_key),
        secret_key,
    })
}
