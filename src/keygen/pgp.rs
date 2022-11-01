use crate::args;
use crate::errors::*;
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::serialize::{Marshal, MarshalInto};
use sequoia_openpgp::types::KeyFlags;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Pgp {
    Embedded(PgpEmbedded),
    Generate(PgpGenerate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpEmbedded {
    pub cert: String,
    pub key: String,
    pub rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpGenerate {
    pub uids: Vec<String>,
}

impl From<args::Pgp> for PgpGenerate {
    fn from(pgp: args::Pgp) -> Self {
        Self { uids: pgp.uids }
    }
}

pub fn generate(config: PgpGenerate) -> Result<PgpEmbedded> {
    let mut builder = CertBuilder::new();
    for uid in &config.uids {
        builder = builder.add_userid(uid.as_str());
    }
    let (pgp, rev) = builder
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey()
        .add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            None,
        )
        .set_validity_period(None)
        .generate()?;

    let cert = String::from_utf8(pgp.armored().to_vec()?)?;
    let key = String::from_utf8(pgp.as_tsk().armored().to_vec()?)?;

    let rev = {
        let headers = pgp.armor_headers();
        let mut headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let mut w = armor::Writer::with_headers(Vec::new(), armor::Kind::Signature, headers)?;
        Packet::Signature(rev).serialize(&mut w)?;
        String::from_utf8(w.finalize()?)?
    };

    Ok(PgpEmbedded {
        cert,
        key,
        rev: Some(rev),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() -> Result<()> {
        generate(PgpGenerate {
            uids: vec!["ohai".to_string()],
        })?;
        Ok(())
    }

    #[test]
    fn test_keygen_anonymous() -> Result<()> {
        generate(PgpGenerate { uids: vec![] })?;
        Ok(())
    }
}
