use crate::errors::*;
use crate::plot::{self, PkgRef, PlotExtras};
use crate::sign;
use crate::utils;
use indexmap::IndexMap;
use openssl::hash::{hash, MessageDigest};
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;
use tar::Archive;

type PatchPkgDatabaseConfig = plot::PatchPkgDatabaseConfig<String>;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct Pkg {
    name: String,
    version: String,
    map: IndexMap<String, String>,
}

impl PkgRef for Pkg {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }
}

impl fmt::Display for Pkg {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        for (key, value) in &self.map {
            writeln!(w, "{}:{}", key, value)?;
        }
        Ok(())
    }
}

impl Pkg {
    pub fn parse(mut bytes: &[u8]) -> Result<(Pkg, &[u8])> {
        let mut fields = IndexMap::<String, String>::new();
        while let Some(idx) = memchr::memchr(b'\n', bytes) {
            let line = str::from_utf8(&bytes[..idx])
                .context("Failed to utf-8 decode line in package index")?;
            bytes = &bytes[idx + 1..];

            if line.is_empty() {
                let mut map = IndexMap::new();
                std::mem::swap(&mut fields, &mut map);

                let name = map.get("P").context("Missing package name")?.to_string();
                let version = map.get("V").context("Missing package version")?.to_string();

                let pkg = Pkg { name, version, map };
                trace!("Found pkg in index: {:?}", pkg);
                return Ok((pkg, bytes));
            } else {
                let (key, value) = line
                    .split_once(':')
                    .context("Non-empty line in apk index contains no assignment")?;
                fields.insert(key.to_string(), value.to_string());
            }
        }

        bail!("Unexpected end of index, trailing fields: {:?}", fields);
    }

    pub fn set_key<I1: Into<String>, I2: Into<String>>(&mut self, key: I1, value: I2) {
        let key = key.into();
        let value = value.into();
        match key.as_str() {
            "P" => {
                debug!("Updating name to: {:?}", value);
                self.name = value.to_string();
            }
            "V" => {
                debug!("Updating version to: {:?}", value);
                self.version = value.to_string();
            }
            _ => (),
        }
        self.map.insert(key, value);
    }
}

// https://wiki.alpinelinux.org/wiki/Apk_spec#Index_Format_V2
pub fn calculate_pkg_data_body(pkg: &[u8]) -> Result<String> {
    let mut reader = pkg;
    let _sig = utils::apk::read_gzip_to_end(&mut reader)?;
    let res = hash(MessageDigest::sha1(), reader)?;
    Ok(format!("Q1{}", base64::encode(res)))
}

pub fn patch_index_buf(
    config: &PatchPkgDatabaseConfig,
    plot_extras: &PlotExtras,
    buf: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut builder = tar::Builder::new(&mut out);
    let mut archive = Archive::new(buf);
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        let mut header = entry.header().clone();
        debug!("Found entry in tar: {:?}", header.path());
        let path = header.path()?;

        let filename = path
            .to_str()
            .with_context(|| anyhow!("Package contains paths with invalid encoding: {:?}", path))?;

        if filename == "APKINDEX" {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let mut bytes = &bytes[..];

            let mut index = Vec::new();
            while !bytes.is_empty() {
                let (mut pkg, remaining) =
                    Pkg::parse(bytes).context("Failed to parse package index")?;
                bytes = remaining;

                if config.is_excluded(&pkg) {
                    debug!("Filtering package: {:?}", pkg.name());
                    continue;
                }

                if let Some(artifact) = config.artifact(&pkg) {
                    let artifact = plot_extras.artifacts.get(artifact).with_context(|| {
                        anyhow!("Referencing undefined artifact: {:?}", artifact)
                    })?;

                    let chksum = calculate_pkg_data_body(artifact.as_bytes())?;
                    pkg.set_key("C", chksum);
                    pkg.set_key("S", artifact.as_bytes().len().to_string());
                }

                if let Some(patch) = config.get_patches(&pkg) {
                    debug!("Patching package {:?} with {:?}", pkg.name(), patch);
                    for (key, value) in patch {
                        pkg.set_key(key, value);
                    }
                }

                writeln!(index, "{}", pkg)?;
            }

            // TODO: this check shouldn't be needed but updating it corrupts the archive (even if the value is equal)
            if header.size()? != index.len() as u64 {
                header.set_size(index.len() as u64);
            }
            header.set_cksum();

            builder.append(&header, &mut &index[..])?;
        } else {
            builder.append(&header, &mut entry)?;
        }
    }

    builder.into_inner()?;

    Ok(out)
}

pub fn patch<W: Write>(
    config: &PatchPkgDatabaseConfig,
    plot_extras: &PlotExtras,
    signing_key: &str,
    signing_key_name: &str,
    bytes: &[u8],
    out: &mut W,
) -> Result<()> {
    let mut reader = BufReader::new(bytes);

    debug!("Reading compressed signature buffer...");
    let signature_buf = utils::apk::read_gzip_to_end(&mut reader)?;

    let mut index = Vec::new();
    debug!("Reading compressed index buffer...");
    let index_buf = utils::apk::read_gzip_to_end(&mut reader)?;
    let index_buf = patch_index_buf(config, plot_extras, &index_buf)?;
    utils::apk::write_compressed(&mut &index_buf[..], &mut index)?;

    info!("Signing index...");
    let signing_key = plot_extras
        .signing_keys
        .get(signing_key)
        .with_context(|| anyhow!("Invalid signing key reference: {:?}", signing_key))?
        .openssl()?;

    let sig = sign::openssl::sign(signing_key, &index, MessageDigest::sha1())
        .context("Failed to sign index")?;

    debug!("Patching apk signature container...");
    let signature_buf = utils::apk::patch_signature_container(
        &signature_buf,
        &sig,
        signing_key.key_algo_id()?,
        signing_key_name,
    )?;

    debug!("Writing compiled index...");
    utils::apk::write_compressed(&mut &signature_buf[..], out)?;
    io::copy(&mut &index[..], out)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_pkg() -> Result<()> {
        let data = b"C:Q15smkfju5lcqyVMwWJH7HE5/My7Y=
P:zsh
V:5.9-r0
A:x86_64
S:1655715
I:6778880
T:Very advanced and programmable command interpreter (shell)
U:https://www.zsh.org/
L:custom
o:zsh
m:Natanael Copa <ncopa@alpinelinux.org>
t:1656806331
c:5e45686dd4e544d3a6b163b0eedc6af355e25811
D:/bin/sh so:libc.musl-x86_64.so.1 so:libcap.so.2 so:libncursesw.so.6
p:cmd:zsh-5.9=5.9-r0 cmd:zsh=5.9-r0

";

        let (pkg, remaining) = Pkg::parse(data)?;
        assert_eq!(remaining, b"");

        let mut expected = Pkg::default();
        expected.set_key("C", "Q15smkfju5lcqyVMwWJH7HE5/My7Y=");
        expected.set_key("P", "zsh");
        expected.set_key("V", "5.9-r0");
        expected.set_key("A", "x86_64");
        expected.set_key("S", "1655715");
        expected.set_key("I", "6778880");
        expected.set_key(
            "T",
            "Very advanced and programmable command interpreter (shell)",
        );
        expected.set_key("U", "https://www.zsh.org/");
        expected.set_key("L", "custom");
        expected.set_key("o", "zsh");
        expected.set_key("m", "Natanael Copa <ncopa@alpinelinux.org>");
        expected.set_key("t", "1656806331");
        expected.set_key("c", "5e45686dd4e544d3a6b163b0eedc6af355e25811");
        expected.set_key(
            "D",
            "/bin/sh so:libc.musl-x86_64.so.1 so:libcap.so.2 so:libncursesw.so.6",
        );
        expected.set_key("p", "cmd:zsh-5.9=5.9-r0 cmd:zsh=5.9-r0");

        assert_eq!(pkg, expected);
        assert_eq!(format!("{}\n", pkg).as_bytes(), data);

        Ok(())
    }
}
