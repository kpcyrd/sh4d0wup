use crate::compression;
use crate::errors::*;
use crate::plot::{PatchPkgDatabaseConfig, PkgRef};
use indexmap::IndexMap;
use std::fmt;
use std::io::prelude::*;
use std::str;
use warp::hyper::body::Bytes;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct Pkg {
    name: String,
    version: String,
    map: IndexMap<String, Vec<String>>,
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
        for (key, values) in &self.map {
            // we always expect at least one value
            if let Some((first, extra)) = values.split_first() {
                write!(w, "{}", key)?;

                match first.as_str() {
                    "" => writeln!(w, ":")?,
                    " " => writeln!(w, ": ")?,
                    _ => writeln!(w, ": {}", first)?,
                }

                for value in extra {
                    writeln!(w, " {}", value)?;
                }
            }
        }

        Ok(())
    }
}

impl Pkg {
    fn from_map<'a>(map: &'a IndexMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
        map.get(key)?.first().map(String::as_str)
    }

    pub fn parse(mut bytes: &[u8]) -> Result<(Pkg, &[u8])> {
        let mut fields = IndexMap::<String, Vec<String>>::new();
        while let Some(idx) = memchr::memchr(b'\n', bytes) {
            let line = str::from_utf8(&bytes[..idx])
                .context("Failed to utf-8 decode line in package index")?;
            bytes = &bytes[idx + 1..];

            if line.is_empty() {
                let mut map = IndexMap::new();
                std::mem::swap(&mut fields, &mut map);

                let name = Self::from_map(&map, "Package")
                    .context("Missing package name")?
                    .to_string();
                let version = Self::from_map(&map, "Version")
                    .context("Missing package version")?
                    .to_string();

                let pkg = Pkg { name, version, map };
                trace!("Found pkg in index: {:?}", pkg);
                return Ok((pkg, bytes));
            } else if let Some(line) = line.strip_prefix(' ') {
                let (_, last) = fields
                    .last_mut()
                    .context("Can't continue non-existant previous line")?;
                last.push(line.to_string());
            } else if let Some((key, value)) = line.split_once(": ") {
                let value = if value.is_empty() {
                    " ".to_string()
                } else {
                    value.to_string()
                };
                fields.entry(key.to_string()).or_default().push(value);
            } else if let Some(key) = line.strip_suffix(": ") {
                fields
                    .entry(key.to_string())
                    .or_default()
                    .push(" ".to_string());
            } else if let Some(key) = line.strip_suffix(':') {
                fields
                    .entry(key.to_string())
                    .or_default()
                    .push("".to_string());
            } else {
                bail!("Unrecognized input: {:?}", line);
            }
        }

        bail!("Unexpected end of index, trailing fields: {:?}", fields);
    }

    pub fn delete_key(&mut self, key: &str) -> Result<()> {
        if key == "Package" {
            bail!("Can't delete `Package` from debian package");
        }
        if key == "Version" {
            bail!("Can't delete `Version` from debian package");
        }
        debug!("Removing {:?} from package", key);
        self.map.remove(key);
        Ok(())
    }

    pub fn set_key(&mut self, key: String, values: Vec<String>) -> Result<()> {
        let first = if let Some(value) = values.first() {
            value
        } else {
            return self.delete_key(&key);
        };

        if key == "Package" {
            debug!("Updating name to: {:?}", first);
            self.name = first.to_string();
        }
        if key == "Version" {
            debug!("Updating version to: {:?}", first);
            self.version = first.to_string();
        }

        debug!("Setting {:?} to {:?}", key, values);
        self.map.insert(key.to_string(), values);
        Ok(())
    }

    pub fn add_values(&mut self, key: &str, values: &[&str]) -> Result<()> {
        let values = values.iter().map(|x| String::from(*x)).collect();
        self.set_key(key.to_string(), values)?;
        Ok(())
    }
}

pub fn patch<W: Write>(config: &PatchPkgDatabaseConfig, bytes: &[u8], out: &mut W) -> Result<()> {
    let comp = compression::detect_compression(bytes);

    let mut out = compression::stream_compress(comp, out)?;
    let mut reader = compression::stream_decompress(comp, bytes)?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let mut bytes = &bytes[..];

    while !bytes.is_empty() {
        let (mut pkg, remaining) = Pkg::parse(bytes).context("Failed to parse package index")?;
        bytes = remaining;

        if config.is_excluded(&pkg) {
            debug!("Filtering package: {:?}", pkg.name());
            continue;
        }

        if let Some(patch) = config.is_patched(&pkg) {
            debug!("Patching package: {:?}", pkg.name());
            for (key, value) in patch {
                pkg.set_key(key.to_string(), value.clone())
                    .context("Failed to patch package")?;
            }
        }

        writeln!(out, "{}", pkg.to_string())?;
    }

    Ok(())
}

pub fn modify_response(config: &PatchPkgDatabaseConfig, bytes: &[u8]) -> Result<Bytes> {
    let mut out = Vec::new();
    patch(config, bytes, &mut out)?;
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_pkg() -> Result<()> {
        let data = b"Package: sniffglue
Source: rust-sniffglue (0.11.1-6)
Version: 0.11.1-6+b1
Installed-Size: 2812
Maintainer: Debian Rust Maintainers <pkg-rust-maintainers@alioth-lists.debian.net>
Architecture: amd64
Depends: libc6 (>= 2.18), libgcc-s1 (>= 4.2), libpcap0.8 (>= 1.5.1), libseccomp2 (>= 0.0.0~20120605)
Description: Secure multithreaded packet sniffer
Multi-Arch: allowed
Built-Using: rust-nix (= 0.19.0-1), rust-pktparse (= 0.5.0-1), rust-seccomp-sys (= 0.1.3-1), rustc (= 1.48.0+dfsg1-2)
Description-md5: bf43056627c9a77e6e736a953362be2c
X-Cargo-Built-Using: gcc-10 (= 10.2.1-6), rust-aho-corasick (= 0.7.10-1), rust-ansi-term (= 0.12.1-1), rust-atty (= 0.2.14-2), rust-backtrace (= 0.3.44-6), rust-backtrace-sys (= 0.1.35-1), rust-base64 (= 0.12.1-1), rust-bitflags (= 1.2.1-1), rust-block-buffer (= 0.9.0-4), rust-block-padding (= 0.2.1-1), rust-byteorder (= 1.3.4-1), rust-cfg-if-0.1 (= 0.1.10-2), rust-cfg-if (= 1.0.0-1), rust-clap (= 2.33.3-1), rust-cpuid-bool (= 0.1.2-4), rust-dhcp4r (= 0.2.0-1), rust-digest (= 0.9.0-1), rust-dirs (= 3.0.1-1), rust-dirs-sys (= 0.3.5-1), rust-dns-parser (= 0.8.0-1), rust-enum-primitive (= 0.1.1-1), rust-env-logger (= 0.7.1-2), rust-failure (= 0.1.7-1), rust-generic-array (= 0.14.4-1), rust-humantime (= 2.0.0-1), rust-itoa (= 0.4.3-1), rust-lazy-static (= 1.4.0-1), rust-lexical-core (= 0.4.3-2), rust-libc (= 0.2.80-1), rust-log (= 0.4.11-2), rust-memchr (= 2.3.3-1), rust-nix (= 0.19.0-1), rust-nom (= 5.0.1-4), rust-num-cpus (= 1.13.0-1), rust-num-traits (= 0.2.14-1), rust-opaque-debug (= 0.3.0-1), rust-pcap-sys (= 0.1.3-2), rust-phf (= 0.8.0-2), rust-phf-shared (= 0.8.0-1), rust-pktparse (= 0.5.0-1), rust-quick-error (= 1.2.3-1), rust-reduce (= 0.1.1-1), rust-regex (= 1.3.7-1), rust-regex-syntax (= 0.6.17-1), rust-rustc-demangle (= 0.1.16-4), rust-rusticata-macros (= 2.0.4-1), rust-ryu (= 1.0.2-1), rust-seccomp-sys (= 0.1.3-1), rust-serde (= 1.0.106-1), rust-serde-json (= 1.0.41-1), rust-sha2 (= 0.9.2-2), rust-siphasher (= 0.3.1-1), rust-stackvector (= 1.0.6-3), rust-static-assertions (= 1.1.0-1), rust-strsim (= 0.9.3-1), rust-structopt (= 0.3.20-1), rust-strum (= 0.19.2-1), rust-syscallz (= 0.15.0-1), rust-termcolor (= 1.1.0-1), rust-textwrap (= 0.11.0-1), rust-thread-local (= 1.0.1-1), rust-time (= 0.1.42-1), rust-tls-parser (= 0.9.2-3), rust-toml (= 0.5.5-1), rust-typenum (= 1.12.0-1), rust-unicode-width (= 0.1.8-1), rust-unreachable (= 1.0.0-1), rust-users (= 0.10.0-1), rust-vec-map (= 0.8.1-2), rust-void (= 1.0.2-1), rustc (= 1.48.0+dfsg1-2)
Section: net
Priority: optional
Filename: pool/main/r/rust-sniffglue/sniffglue_0.11.1-6+b1_amd64.deb
Size: 789284
MD5sum: 9cf8663a1276fee4e54aeea078186ca3
SHA256: 406a3de1f6357554e1606f4dd7c7a8d1360d815cf1453d9e72cee36d92eba7c7

";
        let (pkg, remaining) = Pkg::parse(data)?;
        assert_eq!(remaining, b"");

        let mut expected = Pkg::default();
        expected.add_values("Package", &["sniffglue"])?;
        expected.add_values("Source", &["rust-sniffglue (0.11.1-6)"])?;
        expected.add_values("Version", &["0.11.1-6+b1"])?;
        expected.add_values("Installed-Size", &["2812"])?;
        expected.add_values(
            "Maintainer",
            &["Debian Rust Maintainers <pkg-rust-maintainers@alioth-lists.debian.net>"],
        )?;
        expected.add_values("Architecture", &["amd64"])?;
        expected.add_values("Depends", &["libc6 (>= 2.18), libgcc-s1 (>= 4.2), libpcap0.8 (>= 1.5.1), libseccomp2 (>= 0.0.0~20120605)"])?;
        expected.add_values("Description", &["Secure multithreaded packet sniffer"])?;
        expected.add_values("Multi-Arch", &["allowed"])?;
        expected.add_values("Built-Using", &["rust-nix (= 0.19.0-1), rust-pktparse (= 0.5.0-1), rust-seccomp-sys (= 0.1.3-1), rustc (= 1.48.0+dfsg1-2)"])?;
        expected.add_values("Description-md5", &["bf43056627c9a77e6e736a953362be2c"])?;
        expected.add_values("X-Cargo-Built-Using", &["gcc-10 (= 10.2.1-6), rust-aho-corasick (= 0.7.10-1), rust-ansi-term (= 0.12.1-1), rust-atty (= 0.2.14-2), rust-backtrace (= 0.3.44-6), rust-backtrace-sys (= 0.1.35-1), rust-base64 (= 0.12.1-1), rust-bitflags (= 1.2.1-1), rust-block-buffer (= 0.9.0-4), rust-block-padding (= 0.2.1-1), rust-byteorder (= 1.3.4-1), rust-cfg-if-0.1 (= 0.1.10-2), rust-cfg-if (= 1.0.0-1), rust-clap (= 2.33.3-1), rust-cpuid-bool (= 0.1.2-4), rust-dhcp4r (= 0.2.0-1), rust-digest (= 0.9.0-1), rust-dirs (= 3.0.1-1), rust-dirs-sys (= 0.3.5-1), rust-dns-parser (= 0.8.0-1), rust-enum-primitive (= 0.1.1-1), rust-env-logger (= 0.7.1-2), rust-failure (= 0.1.7-1), rust-generic-array (= 0.14.4-1), rust-humantime (= 2.0.0-1), rust-itoa (= 0.4.3-1), rust-lazy-static (= 1.4.0-1), rust-lexical-core (= 0.4.3-2), rust-libc (= 0.2.80-1), rust-log (= 0.4.11-2), rust-memchr (= 2.3.3-1), rust-nix (= 0.19.0-1), rust-nom (= 5.0.1-4), rust-num-cpus (= 1.13.0-1), rust-num-traits (= 0.2.14-1), rust-opaque-debug (= 0.3.0-1), rust-pcap-sys (= 0.1.3-2), rust-phf (= 0.8.0-2), rust-phf-shared (= 0.8.0-1), rust-pktparse (= 0.5.0-1), rust-quick-error (= 1.2.3-1), rust-reduce (= 0.1.1-1), rust-regex (= 1.3.7-1), rust-regex-syntax (= 0.6.17-1), rust-rustc-demangle (= 0.1.16-4), rust-rusticata-macros (= 2.0.4-1), rust-ryu (= 1.0.2-1), rust-seccomp-sys (= 0.1.3-1), rust-serde (= 1.0.106-1), rust-serde-json (= 1.0.41-1), rust-sha2 (= 0.9.2-2), rust-siphasher (= 0.3.1-1), rust-stackvector (= 1.0.6-3), rust-static-assertions (= 1.1.0-1), rust-strsim (= 0.9.3-1), rust-structopt (= 0.3.20-1), rust-strum (= 0.19.2-1), rust-syscallz (= 0.15.0-1), rust-termcolor (= 1.1.0-1), rust-textwrap (= 0.11.0-1), rust-thread-local (= 1.0.1-1), rust-time (= 0.1.42-1), rust-tls-parser (= 0.9.2-3), rust-toml (= 0.5.5-1), rust-typenum (= 1.12.0-1), rust-unicode-width (= 0.1.8-1), rust-unreachable (= 1.0.0-1), rust-users (= 0.10.0-1), rust-vec-map (= 0.8.1-2), rust-void (= 1.0.2-1), rustc (= 1.48.0+dfsg1-2)"])?;
        expected.add_values("Section", &["net"])?;
        expected.add_values("Priority", &["optional"])?;
        expected.add_values(
            "Filename",
            &["pool/main/r/rust-sniffglue/sniffglue_0.11.1-6+b1_amd64.deb"],
        )?;
        expected.add_values("Size", &["789284"])?;
        expected.add_values("MD5sum", &["9cf8663a1276fee4e54aeea078186ca3"])?;
        expected.add_values(
            "SHA256",
            &["406a3de1f6357554e1606f4dd7c7a8d1360d815cf1453d9e72cee36d92eba7c7"],
        )?;

        assert_eq!(pkg, expected);
        assert_eq!(format!("{}\n", pkg.to_string()).as_bytes(), data);
        Ok(())
    }

    #[test]
    pub fn test_parse_src_pkg() -> Result<()> {
        let data = b"Package: rust-sniffglue
Binary: librust-sniffglue-dev, sniffglue
Version: 0.11.1-6
Maintainer: Debian Rust Maintainers <pkg-rust-maintainers@alioth-lists.debian.net>
Uploaders: kpcyrd <git@rxv.cc>
Build-Depends: debhelper (>= 11), dh-cargo (>= 18), cargo:native, rustc:native, libstd-rust-dev, librust-ansi-term-0.12+default-dev, librust-atty-0.2+default-dev, librust-base64-0.12+default-dev, librust-dhcp4r-0.2+default-dev, librust-dirs-3+default-dev, librust-dns-parser-0.8+default-dev, librust-env-logger-0.7+default-dev, librust-failure-0.1+default-dev, librust-libc-0.2+default-dev, librust-log-0.4+default-dev, librust-nix-0.19+default-dev, librust-nom-5+default-dev, librust-num-cpus-1+default-dev (>= 1.6-~~), librust-pcap-sys-0.1+default-dev (>= 0.1.3-~~), librust-pktparse-0.5+default-dev, librust-pktparse-0.5+serde-dev, librust-reduce-0.1+default-dev (>= 0.1.1-~~), librust-serde-1+default-dev, librust-serde-derive-1+default-dev, librust-serde-json-1+default-dev, librust-sha2-0.9+default-dev, librust-structopt-0.3+default-dev, librust-syscallz-0.15+default-dev, librust-tls-parser-0.9+default-dev, librust-toml-0.5+default-dev, librust-users-0.10+default-dev
Architecture: any
Standards-Version: 4.2.0
Format: 3.0 (quilt)
Files:
 ad1fcb8ad604c9459b0c91c8391a6510 3044 rust-sniffglue_0.11.1-6.dsc
 13b61029622b872d22b529f40917b79b 143493 rust-sniffglue_0.11.1.orig.tar.gz
 5ca448f901ce5a5536066ce3c8b289d2 4624 rust-sniffglue_0.11.1-6.debian.tar.xz
Vcs-Browser: https://salsa.debian.org/rust-team/debcargo-conf/tree/master/src/sniffglue
Vcs-Git: https://salsa.debian.org/rust-team/debcargo-conf.git [src/sniffglue]
Checksums-Sha256:
 d03c20d775a88fe8b06252281fb18119225f270795f6972687d2cf39c280a2db 3044 rust-sniffglue_0.11.1-6.dsc
 1f6957f4a803e171690bb9cbe8260f40c84b14e0eca7ba8c1cc31f6b47bbe9ab 143493 rust-sniffglue_0.11.1.orig.tar.gz
 69d7feab89c8d1c444a2f5a118dc41a3cd67a6539e07325d6a71b844da37a0a3 4624 rust-sniffglue_0.11.1-6.debian.tar.xz
Package-List: 
 librust-sniffglue-dev deb net optional arch=any
 sniffglue deb net optional arch=any
Testsuite: autopkgtest
Testsuite-Triggers: dh-cargo
Directory: pool/main/r/rust-sniffglue
Priority: extra
Section: misc

";
        let (pkg, remaining) = Pkg::parse(data)?;
        assert_eq!(remaining, b"");

        let mut expected = Pkg::default();
        expected.add_values("Package", &["rust-sniffglue"])?;
        expected.add_values("Binary", &["librust-sniffglue-dev, sniffglue"])?;
        expected.add_values("Version", &["0.11.1-6"])?;
        expected.add_values(
            "Maintainer",
            &["Debian Rust Maintainers <pkg-rust-maintainers@alioth-lists.debian.net>"],
        )?;
        expected.add_values("Uploaders", &["kpcyrd <git@rxv.cc>"])?;
        expected.add_values("Build-Depends", &["debhelper (>= 11), dh-cargo (>= 18), cargo:native, rustc:native, libstd-rust-dev, librust-ansi-term-0.12+default-dev, librust-atty-0.2+default-dev, librust-base64-0.12+default-dev, librust-dhcp4r-0.2+default-dev, librust-dirs-3+default-dev, librust-dns-parser-0.8+default-dev, librust-env-logger-0.7+default-dev, librust-failure-0.1+default-dev, librust-libc-0.2+default-dev, librust-log-0.4+default-dev, librust-nix-0.19+default-dev, librust-nom-5+default-dev, librust-num-cpus-1+default-dev (>= 1.6-~~), librust-pcap-sys-0.1+default-dev (>= 0.1.3-~~), librust-pktparse-0.5+default-dev, librust-pktparse-0.5+serde-dev, librust-reduce-0.1+default-dev (>= 0.1.1-~~), librust-serde-1+default-dev, librust-serde-derive-1+default-dev, librust-serde-json-1+default-dev, librust-sha2-0.9+default-dev, librust-structopt-0.3+default-dev, librust-syscallz-0.15+default-dev, librust-tls-parser-0.9+default-dev, librust-toml-0.5+default-dev, librust-users-0.10+default-dev"])?;
        expected.add_values("Architecture", &["any"])?;
        expected.add_values("Standards-Version", &["4.2.0"])?;
        expected.add_values("Format", &["3.0 (quilt)"])?;
        expected.add_values(
            "Files",
            &[
                "",
                "ad1fcb8ad604c9459b0c91c8391a6510 3044 rust-sniffglue_0.11.1-6.dsc",
                "13b61029622b872d22b529f40917b79b 143493 rust-sniffglue_0.11.1.orig.tar.gz",
                "5ca448f901ce5a5536066ce3c8b289d2 4624 rust-sniffglue_0.11.1-6.debian.tar.xz",
            ],
        )?;
        expected.add_values(
            "Vcs-Browser",
            &["https://salsa.debian.org/rust-team/debcargo-conf/tree/master/src/sniffglue"],
        )?;
        expected.add_values(
            "Vcs-Git",
            &["https://salsa.debian.org/rust-team/debcargo-conf.git [src/sniffglue]"],
        )?;
        expected.add_values("Checksums-Sha256", &["", "d03c20d775a88fe8b06252281fb18119225f270795f6972687d2cf39c280a2db 3044 rust-sniffglue_0.11.1-6.dsc", "1f6957f4a803e171690bb9cbe8260f40c84b14e0eca7ba8c1cc31f6b47bbe9ab 143493 rust-sniffglue_0.11.1.orig.tar.gz", "69d7feab89c8d1c444a2f5a118dc41a3cd67a6539e07325d6a71b844da37a0a3 4624 rust-sniffglue_0.11.1-6.debian.tar.xz"])?;
        expected.add_values(
            "Package-List",
            &[
                " ",
                "librust-sniffglue-dev deb net optional arch=any",
                "sniffglue deb net optional arch=any",
            ],
        )?;
        expected.add_values("Testsuite", &["autopkgtest"])?;
        expected.add_values("Testsuite-Triggers", &["dh-cargo"])?;
        expected.add_values("Directory", &["pool/main/r/rust-sniffglue"])?;
        expected.add_values("Priority", &["extra"])?;
        expected.add_values("Section", &["misc"])?;

        assert_eq!(pkg, expected);
        assert_eq!(format!("{}\n", pkg.to_string()).as_bytes(), data);
        Ok(())
    }
}
