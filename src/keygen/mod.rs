pub mod in_toto;
pub mod openssl;
pub mod pgp;
pub mod tls;

use self::in_toto::KeygenInToto;
use self::openssl::KeygenOpenssl;
use self::pgp::KeygenPgp;
use crate::errors::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Keygen {
    Pgp(pgp::KeygenPgp),
    Openssl(openssl::KeygenOpenssl),
    InToto(in_toto::KeygenInToto),
}

impl Keygen {
    pub fn resolve(self) -> Result<EmbeddedKey> {
        Ok(match self {
            Keygen::Pgp(KeygenPgp::Embedded(pgp)) => EmbeddedKey::Pgp(pgp),
            Keygen::Pgp(KeygenPgp::Generate(pgp)) => {
                let pgp = pgp::generate(pgp).context("Failed to generate pgp key")?;
                EmbeddedKey::Pgp(pgp)
            }
            Keygen::Openssl(KeygenOpenssl::Embedded(openssl)) => EmbeddedKey::Openssl(openssl),
            Keygen::Openssl(KeygenOpenssl::Generate(openssl)) => {
                let openssl =
                    openssl::generate(&openssl).context("Failed to generate openssl key")?;
                EmbeddedKey::Openssl(openssl)
            }
            Keygen::InToto(KeygenInToto::Embedded(in_toto)) => EmbeddedKey::InToto(in_toto),
            Keygen::InToto(KeygenInToto::Generate(in_toto)) => {
                let in_toto =
                    in_toto::generate(&in_toto).context("Failed to generate in-toto key")?;
                EmbeddedKey::InToto(in_toto)
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmbeddedKey {
    Pgp(pgp::PgpEmbedded),
    Openssl(openssl::OpensslEmbedded),
    InToto(in_toto::InTotoEmbedded),
}

impl EmbeddedKey {
    pub fn pgp(&self) -> Result<&pgp::PgpEmbedded> {
        if let EmbeddedKey::Pgp(key) = self {
            Ok(key)
        } else {
            bail!("Referenced signing key is not of type pgp");
        }
    }
}
