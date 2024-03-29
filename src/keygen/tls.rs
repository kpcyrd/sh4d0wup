use crate::args;
use crate::errors::*;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeygenTls {
    Embedded(TlsEmbedded),
    Generate(TlsGenerate),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsEmbedded {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsGenerate {
    pub names: Vec<String>,
}

impl From<args::KeygenTls> for TlsGenerate {
    fn from(tls: args::KeygenTls) -> Self {
        Self { names: tls.names }
    }
}

pub fn generate(config: TlsGenerate) -> Result<TlsEmbedded> {
    let mut params = CertificateParams::default();

    // configure CN= distinguished name
    // this is mandatory but not really used by anything
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "flowers are blooming in antarctica");

    // configure Subject Alternative Names (SAN)
    params.subject_alt_names = config
        .names
        .into_iter()
        .map(|name| {
            let san = if let Ok(ip) = name.parse() {
                SanType::IpAddress(ip)
            } else {
                SanType::DnsName(name)
            };
            debug!("Adding subject alt name to certificate: {:?}", san);
            san
        })
        .collect();

    debug!("Generating certificate...");
    let cert = Certificate::from_params(params).context("Failed to generate certificate")?;
    Ok(TlsEmbedded {
        cert: cert.serialize_pem()?,
        key: cert.serialize_private_key_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() -> Result<()> {
        generate(TlsGenerate {
            names: vec!["example.com".to_string()],
        })?;
        Ok(())
    }
}
