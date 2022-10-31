use crate::args;
use crate::errors::*;
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Tls {
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

impl From<args::Tls> for TlsGenerate {
    fn from(gen: args::Tls) -> Self {
        Self { names: gen.names }
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
