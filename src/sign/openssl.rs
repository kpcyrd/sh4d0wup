use crate::errors::*;
use crate::keygen::openssl::OpensslEmbedded;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

pub fn sign(signer: &OpensslEmbedded, data: &[u8], digest: MessageDigest) -> Result<Vec<u8>> {
    let secret_key = PKey::private_key_from_pem(signer.secret_key.as_bytes())
        .context("Failed to load signing key")?;

    let mut signer = Signer::new(digest, &secret_key).context("Failed to setup signer")?;
    signer.update(data).context("Failed to hash data")?;
    let signature = signer.sign_to_vec().context("Failed to sign data")?;

    debug!(
        "Generated signature ({} bytes): {:?}",
        signature.len(),
        signature
    );

    Ok(signature)
}
