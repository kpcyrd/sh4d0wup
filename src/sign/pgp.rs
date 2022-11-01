use crate::errors::*;
use crate::keygen::pgp::PgpEmbedded;
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp::types::SignatureType;
use std::io::Write;

pub fn parse_secret_signing_key(pgp: &PgpEmbedded) -> Result<KeyPair> {
    let cert = Cert::from_bytes(&pgp.key).context("Failed to parse pgp secret key")?;
    if !cert.is_tsk() {
        bail!("Loaded certificate is not a secret key");
    }
    debug!("Loaded secret key: {}", cert.fingerprint());

    let p = StandardPolicy::new();
    let keypair = cert
        .keys()
        .unencrypted_secret()
        .with_policy(&p, None)
        .supported()
        .for_signing()
        .next()
        .context("No signing subkey available")?
        .key()
        .clone()
        .into_keypair()?;
    debug!(
        "Selected signing subkey: {}",
        keypair.public().fingerprint()
    );

    Ok(keypair)
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum EncodingType {
    Cleartext,
    DetachedAscii,
    DetachedBinary,
}

pub fn sign(signer: &PgpEmbedded, data: &[u8], encoding: EncodingType) -> Result<Vec<u8>> {
    let keypair = parse_secret_signing_key(signer).context("Failed to get signing key")?;

    debug!("Generating pgp signature of type {:?}", encoding);
    let mut output = Vec::new();
    {
        let mut message = Message::new(&mut output);

        if encoding == EncodingType::DetachedAscii {
            message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
        }

        let builder = SignatureBuilder::new(SignatureType::Text);
        let signer = Signer::with_template(message, keypair, builder);

        let signer = match encoding {
            EncodingType::Cleartext => signer.cleartext(),
            EncodingType::DetachedAscii | EncodingType::DetachedBinary => signer.detached(),
        };

        let mut message = signer.build().context("Failed to create signer")?;
        message.write_all(data).context("Failed to sign")?;
        message.finalize().context("Failed to sign")?;
    }

    Ok(output)
}

pub fn sign_cleartext(signer: &PgpEmbedded, data: &[u8]) -> Result<Vec<u8>> {
    sign(signer, data, EncodingType::Cleartext)
}

pub fn sign_detached(signer: &PgpEmbedded, data: &[u8], binary: bool) -> Result<Vec<u8>> {
    sign(
        signer,
        data,
        if binary {
            EncodingType::DetachedBinary
        } else {
            EncodingType::DetachedAscii
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::pgp;

    #[test]
    fn test_sign_detached() -> Result<()> {
        let key = pgp::generate(pgp::PgpGenerate {
            uids: vec!["Alice".to_string()],
        })?;
        let _sig = sign_detached(&key, b"ohai\n", false)?;
        Ok(())
    }

    #[test]
    fn test_sign_cleartext() -> Result<()> {
        let key = pgp::generate(pgp::PgpGenerate {
            uids: vec!["Alice".to_string()],
        })?;
        let _sig = sign_cleartext(&key, b"ohai\n")?;
        Ok(())
    }
}
