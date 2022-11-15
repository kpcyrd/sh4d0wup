use crate::args;
use crate::errors::*;
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
use sequoia_openpgp::serialize::{Marshal, MarshalInto};
use sequoia_openpgp::types::KeyFlags;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeygenPgp {
    Embedded(PgpEmbedded),
    Generate(PgpGenerate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpEmbedded {
    pub cert: Option<String>,
    pub secret_key: String,
    pub rev: Option<String>,
}

impl PgpEmbedded {
    pub fn read_from_disk<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        debug!("Reading pgp key from path: {:?}", path);
        let secret_key = fs::read_to_string(path)
            .with_context(|| anyhow!("Failed to read from file {:?}", path))?;
        Ok(PgpEmbedded {
            cert: None,
            secret_key,
            rev: None,
        })
    }

    pub fn to_cert(&self, binary: bool) -> Result<Vec<u8>> {
        let input = if let Some(cert) = &self.cert {
            cert
        } else {
            &self.secret_key
        };

        let cert = Cert::from_reader(input.as_bytes())?;

        let mut output = Vec::new();
        if binary {
            cert.serialize(&mut output)?;
        } else {
            cert.armored().serialize(&mut output)?;
        }

        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpGenerate {
    pub uids: Vec<String>,
}

impl From<args::KeygenPgp> for PgpGenerate {
    fn from(pgp: args::KeygenPgp) -> Self {
        Self { uids: pgp.uids }
    }
}

pub fn debug_inspect(data: &[u8]) -> Result<()> {
    if !log::log_enabled!(log::Level::Debug) {
        return Ok(());
    }
    let mut ppr = PacketParser::from_bytes(data)?;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next_ppr) = pp.recurse()?;
        ppr = next_ppr;
        debug!("Found packet in pgp data: {:?}", packet);
    }
    Ok(())
}

pub fn generate(config: PgpGenerate) -> Result<PgpEmbedded> {
    let mut builder = CertBuilder::new();
    for uid in &config.uids {
        debug!("Adding uid to key: {:?}", uid);
        builder = builder.add_userid(uid.as_str());
    }
    debug!("Generating keypair...");
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
    let secret_key = String::from_utf8(pgp.as_tsk().armored().to_vec()?)?;

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
        cert: Some(cert),
        secret_key,
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
