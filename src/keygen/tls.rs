use crate::args;
use crate::errors::*;
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeygenTls {
    Embedded(TlsEmbedded),
    Generate(TlsGenerate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsEmbedded {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    for name in config.names {
        let san = if let Ok(ip) = name.parse() {
            SanType::IpAddress(ip)
        } else {
            SanType::DnsName(name)
        };
        params.subject_alt_names.push(san);
    }
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
