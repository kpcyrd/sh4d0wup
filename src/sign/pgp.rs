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
    let cert = Cert::from_bytes(&pgp.secret_key).context("Failed to parse pgp secret key")?;
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

        let builder = SignatureBuilder::new(SignatureType::Binary);
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
    use crate::utils;
    use std::fs;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    const SQ_BINARY: &str = utils::compile_env!("SH4D0WUP_SQ_BINARY", "sq");

    fn sq_version() -> Result<semver::Version> {
        for version_arg in ["version", "-V"] {
            // figure out how to invoke sq correctly
            let version = Command::new(SQ_BINARY)
                .arg(version_arg)
                .output()
                .with_context(|| anyhow!("Failed to execute sq binary: {SQ_BINARY:?}"))?;

            // `sq -V` got renamed to `sq version` at some point, try the old option next
            if !version.status.success() {
                continue;
            }

            let output = if version.stdout.is_empty() {
                version.stderr
            } else {
                version.stdout
            };

            let version = String::from_utf8(output)?;

            // find version line
            let mut version = version.split(' ');
            assert_eq!(version.next(), Some("sq"));
            let version = version.next().with_context(|| {
                anyhow!("Missing version string from `sq {version_arg}` output")
            })?;

            // remove remaining data
            let mut version = version.split('\n');
            let version = version.next().unwrap();

            // parse and compare version
            let version = semver::Version::parse(version).context("Failed to parse sq version")?;
            return Ok(version);
        }

        bail!("Failed to detect sq version");
    }

    fn sq_signer_file_arg_name() -> Result<&'static str> {
        let version = sq_version()?;
        let req = semver::VersionReq::parse("<0.30.0").unwrap();

        if req.matches(&version) {
            // legacy name for backwards compat
            Ok("--signer-cert")
        } else {
            // latest argument name
            Ok("--signer-file")
        }
    }

    fn sq_signature_file_arg_name() -> Result<&'static str> {
        let version = sq_version()?;
        let req = semver::VersionReq::parse("<0.39.0").unwrap();

        if req.matches(&version) {
            // legacy name for backwards compat
            Ok("--detached")
        } else {
            // latest argument name
            Ok("--signature-file")
        }
    }

    fn sq_inline_arg_name() -> Result<Option<&'static str>> {
        let version = sq_version()?;
        let req = semver::VersionReq::parse("<1.0.0").unwrap();

        if req.matches(&version) {
            // back then no flag was needed
            Ok(None)
        } else {
            // latest version needs a flag
            Ok(Some("--message"))
        }
    }

    fn sq_verify(args: &[&str], data: &[u8]) -> Result<Vec<u8>> {
        let mut child = Command::new(SQ_BINARY)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to execute sq binary")?;
        {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(data)?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            bail!("Command failed: {:?}, error={:?}", output.status, error);
        }
        Ok(output.stdout)
    }

    fn temp_put<B: AsRef<[u8]>>(dir: &TempDir, name: &str, data: B) -> Result<String> {
        let path = dir.path().join(name);
        let path = path.to_str().context("Path contains invalid utf8")?;
        fs::write(path, data)?;
        Ok(path.to_string())
    }

    #[test]
    fn test_sign_detached_ascii() -> Result<()> {
        let key = pgp::generate(pgp::PgpGenerate {
            uids: vec!["Alice".to_string()],
        })?;
        let data = b"ohai\n";
        let sig = sign_detached(&key, data, false)?;

        let dir = tempfile::tempdir()?;
        let cert_path = temp_put(&dir, "cert.pgp", key.cert.context("Missing public key")?)?;
        let sig_path = temp_put(&dir, "sig.txt", sig)?;

        let output = sq_verify(
            &[
                "verify",
                sq_signer_file_arg_name()?,
                &cert_path,
                sq_signature_file_arg_name()?,
                &sig_path,
            ],
            data,
        )?;
        assert_eq!(output, b"");
        Ok(())
    }

    #[test]
    fn test_sign_detached_binary() -> Result<()> {
        let key = pgp::generate(pgp::PgpGenerate {
            uids: vec!["Alice".to_string()],
        })?;
        let data = b"ohai\n";
        let sig = sign_detached(&key, data, true)?;

        let dir = tempfile::tempdir()?;
        let cert_path = temp_put(&dir, "cert.pgp", key.cert.context("Missing public key")?)?;
        let sig_path = temp_put(&dir, "sig.txt", sig)?;

        let output = sq_verify(
            &[
                "verify",
                sq_signer_file_arg_name()?,
                &cert_path,
                sq_signature_file_arg_name()?,
                &sig_path,
            ],
            data,
        )?;
        assert_eq!(output, b"");
        Ok(())
    }

    #[test]
    fn test_sign_cleartext() -> Result<()> {
        let key = pgp::generate(pgp::PgpGenerate {
            uids: vec!["Alice".to_string()],
        })?;
        let data = "ohai\n";
        let msg = sign_cleartext(&key, data.as_bytes())?;

        let dir = tempfile::tempdir()?;
        let cert_path = temp_put(&dir, "cert.pgp", key.cert.context("Missing public key")?)?;
        let msg_path = temp_put(&dir, "msg.txt", msg)?;

        let output = sq_verify(
            &[
                Some("verify"),
                Some(sq_signer_file_arg_name()?),
                Some(&cert_path),
                sq_inline_arg_name()?,
                Some(&msg_path),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
            data.as_bytes(),
        )?;
        let output = String::from_utf8(output)?;

        // old versions of sq append a `\n`, causing an output of `ohai\n\n`
        // keep this around until at least ubuntu 24.04 is out
        // later we can narrow down support for old sq versions, especially since this is a unit test
        let output = output.replace("\n\n", "\n");

        assert_eq!(output, data);
        Ok(())
    }
}
