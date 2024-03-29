pub mod in_toto;
pub mod openssl;
pub mod pgp;
pub mod ssh;
pub mod tls;

use self::in_toto::KeygenInToto;
use self::openssl::KeygenOpenssl;
use self::pgp::KeygenPgp;
use self::ssh::KeygenSsh;
use crate::errors::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Keygen {
    Pgp(pgp::KeygenPgp),
    Ssh(ssh::KeygenSsh),
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
            Keygen::Ssh(KeygenSsh::Embedded(ssh)) => EmbeddedKey::Ssh(ssh),
            Keygen::Ssh(KeygenSsh::Generate(ssh)) => {
                let ssh = ssh::generate(&ssh).context("Failed to generate ssh key")?;
                EmbeddedKey::Ssh(ssh)
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

impl From<EmbeddedKey> for Keygen {
    fn from(key: EmbeddedKey) -> Self {
        match key {
            EmbeddedKey::Pgp(pgp) => Keygen::Pgp(KeygenPgp::Embedded(pgp)),
            EmbeddedKey::Ssh(ssh) => Keygen::Ssh(KeygenSsh::Embedded(ssh)),
            EmbeddedKey::Openssl(openssl) => Keygen::Openssl(KeygenOpenssl::Embedded(openssl)),
            EmbeddedKey::InToto(in_toto) => Keygen::InToto(KeygenInToto::Embedded(in_toto)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EmbeddedKey {
    Pgp(pgp::PgpEmbedded),
    Ssh(ssh::SshEmbedded),
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

    pub fn openssl(&self) -> Result<&openssl::OpensslEmbedded> {
        if let EmbeddedKey::Openssl(key) = self {
            Ok(key)
        } else {
            bail!("Referenced signing key is not of type openssl");
        }
    }
}
