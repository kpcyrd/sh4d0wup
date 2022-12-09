pub mod in_toto;
pub mod openssl;
pub mod pgp;

use crate::errors::*;
use crate::keygen::EmbeddedKey;

pub fn sign(data: &[u8], key: &EmbeddedKey) -> Result<Vec<u8>> {
    match key {
        EmbeddedKey::Pgp(key) => pgp::sign(key, data, pgp::EncodingType::DetachedBinary),
        EmbeddedKey::Ssh(_key) => bail!("Creating ssh signatures isn't supported yet"),
        EmbeddedKey::Openssl(_key) => bail!("Creating openssl signatures isn't supported yet"),
        EmbeddedKey::InToto(_key) => bail!("Creating in-toto signatures isn't supported yet"),
    }
}
