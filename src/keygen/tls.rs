use crate::args;
use crate::errors::*;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType, SignatureAlgorithm};
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

#[derive(Debug, Default, Copy, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Algorithm {
    #[default]
    PkcsEcdsaP256Sha256,
    PkcsEd25519,
    PkcsRsaSha256,
    PkcsRsaSha512,
}

impl From<Algorithm> for &SignatureAlgorithm {
    fn from(algo: Algorithm) -> Self {
        match algo {
            Algorithm::PkcsEcdsaP256Sha256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            Algorithm::PkcsEd25519 => &rcgen::PKCS_ED25519,
            Algorithm::PkcsRsaSha256 => &rcgen::PKCS_RSA_SHA256,
            Algorithm::PkcsRsaSha512 => &rcgen::PKCS_RSA_SHA512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsGenerate {
    pub names: Vec<String>,
    #[serde(default)]
    pub algorithm: Algorithm,
}

impl From<args::KeygenTls> for TlsGenerate {
    fn from(tls: args::KeygenTls) -> Self {
        let algorithm = if tls.ecdsa {
            Algorithm::PkcsEcdsaP256Sha256
        } else if tls.rsa || tls.rsa_sha256 {
            Algorithm::PkcsRsaSha256
        } else if tls.rsa_sha512 {
            Algorithm::PkcsRsaSha512
        } else if tls.ed25519 {
            Algorithm::PkcsEd25519
        } else {
            Algorithm::default()
        };
        Self {
            names: tls.names,
            algorithm,
        }
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
                SanType::DnsName(name.parse()?)
            };
            debug!("Adding subject alt name to certificate: {:?}", san);
            Ok(san)
        })
        .collect::<Result<_>>()?;

    debug!("Generating certificate...");
    let keypair =
        KeyPair::generate_for(config.algorithm.into()).context("Failed to generate keypair")?;
    let cert = params
        .self_signed(&keypair)
        .context("Failed to generate certificate")?;
    Ok(TlsEmbedded {
        cert: cert.pem(),
        key: keypair.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        generate(TlsGenerate {
            names: vec!["example.com".to_string()],
            algorithm: Algorithm::default(),
        })
        .unwrap();
    }

    #[test]
    fn parse_tls_generate_default() {
        let s = r#"
names:
- example.com
        "#;
        let tls = serde_yaml::from_str::<TlsGenerate>(s).unwrap();
        assert_eq!(
            tls,
            TlsGenerate {
                names: vec!["example.com".to_string()],
                algorithm: Algorithm::default(),
            }
        );
    }

    #[test]
    fn parse_tls_generate_ecdsa() {
        let s = r#"
names:
- example.com
algorithm: PKCS_ECDSA_P256_SHA256
        "#;
        let tls = serde_yaml::from_str::<TlsGenerate>(s).unwrap();
        assert_eq!(
            tls,
            TlsGenerate {
                names: vec!["example.com".to_string()],
                algorithm: Algorithm::PkcsEcdsaP256Sha256,
            }
        );
        generate(tls).unwrap();
    }

    #[test]
    fn parse_tls_generate_ed25519() {
        let s = r#"
names:
- example.com
algorithm: PKCS_ED25519
        "#;
        let tls = serde_yaml::from_str::<TlsGenerate>(s).unwrap();
        assert_eq!(
            tls,
            TlsGenerate {
                names: vec!["example.com".to_string()],
                algorithm: Algorithm::PkcsEd25519,
            }
        );
        generate(tls).unwrap();
    }

    #[test]
    fn parse_tls_generate_rsa_sha256() {
        let s = r#"
names:
- example.com
algorithm: PKCS_RSA_SHA256
        "#;
        let tls = serde_yaml::from_str::<TlsGenerate>(s).unwrap();
        assert_eq!(
            tls,
            TlsGenerate {
                names: vec!["example.com".to_string()],
                algorithm: Algorithm::PkcsRsaSha256,
            }
        );
        generate(tls).unwrap();
    }

    #[test]
    fn parse_tls_generate_rsa_sha512() {
        let s = r#"
names:
- example.com
algorithm: PKCS_RSA_SHA512
        "#;
        let tls = serde_yaml::from_str::<TlsGenerate>(s).unwrap();
        assert_eq!(
            tls,
            TlsGenerate {
                names: vec!["example.com".to_string()],
                algorithm: Algorithm::PkcsRsaSha512,
            }
        );
        generate(tls).unwrap();
    }
}
