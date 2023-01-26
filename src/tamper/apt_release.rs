use crate::errors::*;
use crate::plot::{Artifacts, PatchAptReleaseConfig, PkgRef, PlotExtras, SigningKeys};
use crate::sign;
use indexmap::IndexMap;
use std::fmt;
use std::io::prelude::*;
use std::str;
use warp::hyper::body::Bytes;

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Release {
    pub fields: IndexMap<String, String>,
    pub checksums: IndexMap<String, Vec<ChecksumEntry>>,
}

impl fmt::Display for Release {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        for (key, value) in &self.fields {
            writeln!(w, "{key}: {value}")?;
        }
        for (key, checksums) in &self.checksums {
            writeln!(w, "{key}:")?;
            for entry in checksums {
                writeln!(w, " {entry}")?;
            }
        }
        Ok(())
    }
}

impl Release {
    pub fn parse(mut bytes: &[u8]) -> Result<Self> {
        bytes = bytes
            .strip_prefix(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
            .context("InRelease is expected to be a pgp signed message")?;

        while let Some(idx) = memchr::memchr(b'\n', bytes) {
            bytes = &bytes[idx + 1..];
            if idx == 0 {
                break;
            }
        }

        let mut release = Release::default();
        while let Some(idx) = memchr::memchr(b'\n', bytes) {
            let line = str::from_utf8(&bytes[..idx])
                .context("Failed to utf-8 decode line in package index")?;
            bytes = &bytes[idx + 1..];

            if line == "-----BEGIN PGP SIGNATURE-----" {
                break;
            }

            if let Some(line) = line.strip_prefix(' ') {
                let (namespace, group) = release
                    .checksums
                    .last_mut()
                    .context("Can't add checksums if no section has started yet")?;
                let chksum = ChecksumEntry::parse(namespace.to_string(), line)
                    .context("Failed to parse checksum line")?;
                group.push(chksum);
            } else if let Some((key, value)) = line.split_once(": ") {
                release.fields.insert(key.to_string(), value.to_string());
            } else if let Some(key) = line.strip_suffix(':') {
                release.checksums.insert(key.to_string(), Vec::new());
            } else {
                bail!("Unrecognized input: {:?}", line);
            }
        }

        Ok(release)
    }
}

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ChecksumEntry {
    pub namespace: String,
    pub hash: String,
    pub size: u64,
    pub size_width: usize,
    pub path: String,
}

impl fmt::Display for ChecksumEntry {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(
            w,
            "{} {:width$} {}",
            self.hash,
            self.size,
            self.path,
            width = self.size_width
        )?;
        Ok(())
    }
}

impl PkgRef for ChecksumEntry {
    fn name(&self) -> &str {
        &self.path
    }

    fn version(&self) -> &str {
        &self.hash
    }

    fn namespace(&self) -> Option<&str> {
        Some(&self.namespace)
    }
}

impl ChecksumEntry {
    pub fn new<I: Into<String>>(
        namespace: String,
        hash: I,
        size: u64,
        size_width: usize,
        path: I,
    ) -> Self {
        ChecksumEntry {
            namespace,
            hash: hash.into(),
            size,
            size_width,
            path: path.into(),
        }
    }

    pub fn parse(namespace: String, mut line: &str) -> Result<Self> {
        let idx = line.find(' ').context("Invalid input")?;
        let hash = line[..idx].to_string();
        line = &line[idx + 1..];

        let mut size_width = 0;
        while line[size_width..].starts_with(' ') {
            size_width += 1;
        }

        let idx = line[size_width..].find(' ').context("Invalid input")?;
        let size = line[size_width..][..idx]
            .parse()
            .context("Failed to parse size as number")?;
        size_width += idx;

        let path = line[size_width + 1..].to_string();
        Ok(ChecksumEntry {
            namespace,
            hash,
            size,
            size_width,
            path,
        })
    }
}

pub fn patch<W: Write>(
    config: &PatchAptReleaseConfig,
    artifacts: &Artifacts,
    signing_keys: &SigningKeys,
    bytes: &[u8],
    out: &mut W,
) -> Result<()> {
    let mut release = Release::parse(bytes).context("Failed to parse release")?;

    debug!("Got release: {:?}", release.fields);
    trace!("Checksums in release: {:?}", release.checksums);

    for (key, value) in &config.fields {
        release.fields.insert(key.to_string(), value.to_string());
    }

    for (key, group) in &mut release.checksums {
        debug!("Processing checksum section: {:?}", key);
        group.retain(|checksum| {
            if config.checksums.is_excluded(checksum) {
                info!("Filtering {:?} checksum: {:?}", key, checksum.name());
                false
            } else {
                true
            }
        });

        for checksum in group {
            if let Some(artifact) = config.checksums.artifact(checksum) {
                let artifact = artifacts
                    .get(artifact)
                    .with_context(|| anyhow!("Referencing undefined artifact: {:?}", artifact))?;

                debug!(
                    "Patching size for {:?} to {:?}",
                    checksum.path,
                    artifact.len()
                );
                checksum.size = artifact.len() as u64;

                match checksum.namespace.as_str() {
                    "MD5Sum" => {
                        let md5 = artifact.md5().to_string();
                        debug!("Patching md5 for {:?} to {:?}", checksum.path, md5);
                        checksum.hash = md5;
                    }
                    "SHA1" => {
                        let sha1 = artifact.sha1().to_string();
                        debug!("Patching sha1 for {:?} to {:?}", checksum.path, sha1);
                        checksum.hash = sha1;
                    }
                    "SHA256" => {
                        let sha256 = artifact.sha256().to_string();
                        debug!("Patching sha256 for {:?} to {:?}", checksum.path, sha256);
                        checksum.hash = sha256;
                    }
                    ns => warn!("Unknown checksum namespace: {:?}", ns),
                }
            }

            if let Some(patch) = config.checksums.get_patches(checksum) {
                debug!("Patching checksum {:?} with {:?}", checksum, patch);
                for (key, value) in patch {
                    match key {
                        "hash" => checksum.hash = value.to_string(),
                        "size" => {
                            checksum.size =
                                value.parse().context("Failed to parse size as number")?
                        }
                        "size_width" => {
                            checksum.size_width = value
                                .parse()
                                .context("Failed to parse size_width as number")?
                        }
                        "path" => checksum.path = value.to_string(),
                        _ => bail!(
                            "Unrecognized key for apt InRelease checksum entry: {:?}",
                            key
                        ),
                    }
                }
            }
        }
    }

    if let Some(signing_key) = &config.signing_key {
        let signing_key = signing_keys
            .get(signing_key)
            .with_context(|| anyhow!("Invalid signing key reference: {:?}", signing_key))?
            .pgp()?;

        let release = sign::pgp::sign_cleartext(signing_key, release.to_string().as_bytes())
            .context("Failed to sign release")?;
        out.write_all(&release)?;
    } else {
        // serialize directly to stdout for performance
        write!(out, "{release}")?;
    }

    Ok(())
}

pub fn modify_response(
    config: &PatchAptReleaseConfig,
    plot_extras: &PlotExtras,
    bytes: &[u8],
) -> Result<Bytes> {
    let mut out = Vec::new();
    patch(
        config,
        &plot_extras.artifacts,
        &plot_extras.signing_keys,
        bytes,
        &mut out,
    )?;
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_release() -> Result<()> {
        let data = b"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: Debian
Label: Debian
Suite: stable
Version: 11.5
Codename: bullseye
Changelogs: https://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog
Date: Sat, 10 Sep 2022 10:18:01 UTC
Acquire-By-Hash: yes
No-Support-for-Architecture-all: Packages
Architectures: all amd64 arm64 armel armhf i386 mips64el mipsel ppc64el s390x
Components: main contrib non-free
Description: Debian 11.5 Released 10 September 2022
MD5Sum:
 7fdf4db15250af5368cc52a91e8edbce   738242 contrib/Contents-all
 cbd7bc4d3eb517ac2b22f929dfc07b47    57319 contrib/Contents-all.gz
 6e4ef0f159fa08f5ba74067e0a94b5e6   787321 contrib/Contents-amd64
 98583d055424774c060fdf4b02291da5    54668 contrib/Contents-amd64.gz
 61e10f1703d718d584f381a943bfe4d7   370915 contrib/Contents-arm64
 86a145a0d8d7346449f2cf62098a5553    29596 contrib/Contents-arm64.gz
 b6d2673f17fbdb3a5ce92404a62c2d7e   359292 contrib/Contents-armel
 d02d94be587d56a1246b407669d2a24c    28039 contrib/Contents-armel.gz
 d272ba9da0f302b6c09a36899e738115   367655 contrib/Contents-armhf
 317aa67ea34d625837d245f6fb00bdc4    29236 contrib/Contents-armhf.gz
 ccb13401b0f48dded08ed089f8074765   407328 contrib/Contents-i386
 e496015d7e6e8d5a91cec31fc4bde74c    33556 contrib/Contents-i386.gz
 44384de1db64f592fc69693b355a0ec7   359402 contrib/Contents-mips64el
 a2abf38d14c1c7e3aafcb21881b0fe7d    27962 contrib/Contents-mips64el.gz
 457feed233db5ce7db62cc69e7a8a5c6   360549 contrib/Contents-mipsel
 90ec76d0dca539a4c4aa33404de4c633    27942 contrib/Contents-mipsel.gz
 02985cbbdd1e790b29a9911ba00b5650   370025 contrib/Contents-ppc64el
 b34b90df14207eafe94313e6d466b28e    29381 contrib/Contents-ppc64el.gz
 e2089c91540f7adb693675935dacf9e5   357860 contrib/Contents-s390x
 bb90fb42e72d39da53b3e1e2c2f46bc3    27518 contrib/Contents-s390x.gz
 ba62d5cf69ffc155d75fa9e16228b039  6722669 contrib/Contents-source
 fec97c652e41904e73f17cc5f7b0b2ff   469817 contrib/Contents-source.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-all
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-all.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-amd64
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-amd64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-arm64
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-arm64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-armel
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-armel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-armhf
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-armhf.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-i386
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-i386.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-mips64el
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-mips64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-mipsel
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-mipsel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-ppc64el
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-ppc64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-s390x
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-s390x.gz
 73d0ad5df01464248f578fb7d7ba10b0   103239 contrib/binary-all/Packages
 6848b84ab94b0624ad15f5afea5f49bd    27385 contrib/binary-all/Packages.gz
 a9e21972669e0355e9a875ea31f25c63    23916 contrib/binary-all/Packages.xz
 ef97d6ef5ce0b25eec3dbe21f7754bb8      117 contrib/binary-all/Release
 b6541899bd7907d9dc5afe604d26a719   231878 contrib/binary-amd64/Packages
 7cb1a35df9e7ef744685d28932cc1ef2    60884 contrib/binary-amd64/Packages.gz
 4ee4184e78f4b0d06e981706a6118dc7    50588 contrib/binary-amd64/Packages.xz
 54210b9b5bd9ff75c5d2e127069cd9a1      119 contrib/binary-amd64/Release
 4b9c68a7d2d23357dc171d29a03565c6   180884 contrib/binary-arm64/Packages
 c2d2253fb81e2a397e4a42d4d475bd24    48958 contrib/binary-arm64/Packages.gz
 f57a0a52945226cc76c241ce57c182be    40964 contrib/binary-arm64/Packages.xz
 d4f283e2fa848306dacf11b0d473e7b6      119 contrib/binary-arm64/Release
 1636c115e53ef208266fcc6b024f7b34   163042 contrib/binary-armel/Packages
 ed80c2afd00562cee8543a3835ed0907    44389 contrib/binary-armel/Packages.gz
 ef8175333695e1554eeb8766d74c4795    37452 contrib/binary-armel/Packages.xz
 f42988db392c15b4e1fcadb80c23c6e4      119 contrib/binary-armel/Release
 900f4a8949a535dfd1af4326b43e6fa4   175566 contrib/binary-armhf/Packages
 11db111d1dd40616866a8b6d4e59ca8d    47805 contrib/binary-armhf/Packages.gz
 512198b43afc25d9da1e078b44f5b4a8    40220 contrib/binary-armhf/Packages.xz
 7a54c1263cb41ede50e965f8eda25b11      119 contrib/binary-armhf/Release
 feb05a736bdfbd41bfdd4d87fd34f72a   203514 contrib/binary-i386/Packages
 89a79f0c9d4bb2df7d3dc3d165f02242    54100 contrib/binary-i386/Packages.gz
 130d6b77d3b32c1ec94097e694d66718    45340 contrib/binary-i386/Packages.xz
 50990a45073139784d6111c7dd85f578      118 contrib/binary-i386/Release
 825bc5698936bc26f5bb28c20287aeb1   163507 contrib/binary-mips64el/Packages
 190dd8f6a3e97c3ebe8ab216e79ed867    44652 contrib/binary-mips64el/Packages.gz
 9302a32bad830648c066bfb13a35b6b9    37496 contrib/binary-mips64el/Packages.xz
 3ff11782d530f1913a76bcf893091bc4      122 contrib/binary-mips64el/Release
 4e717be16d235fb7e6e118c898ac80af   164647 contrib/binary-mipsel/Packages
 f73fd75fc0a6371ae7e6b709a4d8d939    44883 contrib/binary-mipsel/Packages.gz
 9c8d77e03dcdc178465c28095f4e8d64    37816 contrib/binary-mipsel/Packages.xz
 954f33fed68731d37efdabdf076bcc87      120 contrib/binary-mipsel/Release
 1343f3307bbeea9f0b04dd64e8d23d62   180387 contrib/binary-ppc64el/Packages
 831c14a6428bbe7b05d290e9aa225785    48843 contrib/binary-ppc64el/Packages.gz
 8daa347dc96d3f69e7510c0d3f51916e    40808 contrib/binary-ppc64el/Packages.xz
 28783ca102413882fe7f44d6b50d2022      121 contrib/binary-ppc64el/Release
 1a2b7365b25b44a4304271198bda5094   162250 contrib/binary-s390x/Packages
 103b59f69a5c230eab05d06289ad7c9b    44334 contrib/binary-s390x/Packages.gz
 e4109e4637f7b1c233130da040451fd9    37244 contrib/binary-s390x/Packages.xz
 1d2a6a86207b25cce9fcc6e69a5f2da0      119 contrib/binary-s390x/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-all/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-all/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-all/Packages.xz
 ef97d6ef5ce0b25eec3dbe21f7754bb8      117 contrib/debian-installer/binary-all/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-amd64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-amd64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-amd64/Packages.xz
 54210b9b5bd9ff75c5d2e127069cd9a1      119 contrib/debian-installer/binary-amd64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-arm64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-arm64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-arm64/Packages.xz
 d4f283e2fa848306dacf11b0d473e7b6      119 contrib/debian-installer/binary-arm64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-armel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-armel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-armel/Packages.xz
 f42988db392c15b4e1fcadb80c23c6e4      119 contrib/debian-installer/binary-armel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-armhf/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-armhf/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-armhf/Packages.xz
 7a54c1263cb41ede50e965f8eda25b11      119 contrib/debian-installer/binary-armhf/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-i386/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-i386/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-i386/Packages.xz
 50990a45073139784d6111c7dd85f578      118 contrib/debian-installer/binary-i386/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-mips64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-mips64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-mips64el/Packages.xz
 3ff11782d530f1913a76bcf893091bc4      122 contrib/debian-installer/binary-mips64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-mipsel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-mipsel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-mipsel/Packages.xz
 954f33fed68731d37efdabdf076bcc87      120 contrib/debian-installer/binary-mipsel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-ppc64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-ppc64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-ppc64el/Packages.xz
 28783ca102413882fe7f44d6b50d2022      121 contrib/debian-installer/binary-ppc64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-s390x/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-s390x/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-s390x/Packages.xz
 1d2a6a86207b25cce9fcc6e69a5f2da0      119 contrib/debian-installer/binary-s390x/Release
 fc412a0e8fed50416ae55ca3a34c2654   119152 contrib/dep11/Components-amd64.yml
 7473c932902284e9c636636a5ff0587b    15579 contrib/dep11/Components-amd64.yml.gz
 751b272121122fce4882d17a9d099c44    13564 contrib/dep11/Components-amd64.yml.xz
 49911a9d2f76ed13124c7cff0081266b   113437 contrib/dep11/Components-arm64.yml
 ee72e145d0e71d94c0d418d36dabfd8c    14251 contrib/dep11/Components-arm64.yml.gz
 65f48dc9acec772076e60ce35239703f    12480 contrib/dep11/Components-arm64.yml.xz
 b1f970bbcdd889ccff5c2646bc2835ba   113437 contrib/dep11/Components-armel.yml
 d2a414b1147562c0ecfa1aab53fc0260    14029 contrib/dep11/Components-armel.yml.gz
 b450a677c3a5d4a52d2a0df274c222cf    12524 contrib/dep11/Components-armel.yml.xz
 75c6b8bd42fc863caa66c454306c7d39   113437 contrib/dep11/Components-armhf.yml
 ac52f103d1c493d0f8d8e5662d758f78    14127 contrib/dep11/Components-armhf.yml.gz
 80f4310b2d68bf09c7fbba34a0eec794    12480 contrib/dep11/Components-armhf.yml.xz
 a46b6878a89f45fab86aca68bffe081d   118972 contrib/dep11/Components-i386.yml
 751ea67ac68d2e755726b4e9d62ab15e    15566 contrib/dep11/Components-i386.yml.gz
 82c956565311c8a7d90bff6e0a226fbe    13560 contrib/dep11/Components-i386.yml.xz
 6f822ef8f2c13dc4212ade261b4a8752   113437 contrib/dep11/Components-mips64el.yml
 a072aab0fb45dab4a6e25295f23e9b5f    14056 contrib/dep11/Components-mips64el.yml.gz
 e5c2dd7fd785fa1ab66099d7763bd670    12500 contrib/dep11/Components-mips64el.yml.xz
 432a29a22c4a782f6edad376f386937f   113437 contrib/dep11/Components-ppc64el.yml
 b5202b5037949e593060f92290d6f949    14219 contrib/dep11/Components-ppc64el.yml.gz
 dd92a500c7807091665dbc207c9bef68    12496 contrib/dep11/Components-ppc64el.yml.xz
 53c6b87820861b0ed316a88f7542cd76   113437 contrib/dep11/Components-s390x.yml
 5a4872d3187bc79418b468890be4b5fe    14050 contrib/dep11/Components-s390x.yml.gz
 eefb3301e486aedbbbb1d735e2522a00    12488 contrib/dep11/Components-s390x.yml.xz
 5d8e37f26e7e15f367751089fa13c876   271360 contrib/dep11/icons-128x128.tar
 500b14a4cafa23b9106b402737f863a7   195507 contrib/dep11/icons-128x128.tar.gz
 d9651fb188be2221d2f583aeba83d8fc    83968 contrib/dep11/icons-48x48.tar
 6b5ea4675ad78554aaa53b344f1bd146    47168 contrib/dep11/icons-48x48.tar.gz
 7115d3a3d41fc9bca9cfcc3c608bebf2   138752 contrib/dep11/icons-64x64.tar
 c839e679f1d60d294d39884d0911e514    93294 contrib/dep11/icons-64x64.tar.gz
 01e75740c90a7df7e474a1c6152b2aa6   192685 contrib/i18n/Translation-en
 a2e9608c3e388d26e031583f200e2f92    46929 contrib/i18n/Translation-en.bz2
 a41b3d515c7657840de8110cbdca5000      120 contrib/source/Release
 d615756c28aa372e2bc408abe1d9ec5b   178776 contrib/source/Sources
 c19b950adb0b02bb84fec45d11d257d8    51355 contrib/source/Sources.gz
 0e1710e68ffbd6a7b3542844610a69fc    43208 contrib/source/Sources.xz
 5eb461cd0c4c1d5c70cddc2e15041a82 477036454 main/Contents-all
 01938028fd34d0a5e59202330399848a 31026385 main/Contents-all.gz
 c11457c415efe69a56e85d825c2bc7f8 129049566 main/Contents-amd64
 9b3e8661aba8601d9f8f07e86b60646a 10269094 main/Contents-amd64.gz
 9bcf201a27b44592ce5158ec57229346 122421950 main/Contents-arm64
 f07c0df13a96e40852436e21522dc139  9830625 main/Contents-arm64.gz
 b02d2c9764234a7d48247d4b56f4a843 104678675 main/Contents-armel
 8c2302638f6d74bec7cb870cc2a38ee8  8703118 main/Contents-armel.gz
 517d574c357109e95114127322b5819a 113712023 main/Contents-armhf
 247282f293c5224940ce9261eae8abe7  9305876 main/Contents-armhf.gz
 0a17f4f6496d6863397498633e17074a 129083944 main/Contents-i386
 8767d2b35b4eff409be1429dc27cf43b 10206461 main/Contents-i386.gz
 d765861a2f9f45439dc322a4e958b550 111092579 main/Contents-mips64el
 8cba9dc8edca7b153458bd3729546b82  9042857 main/Contents-mips64el.gz
 a09e8ddc913db48be964a474c815a483 112589241 main/Contents-mipsel
 766803b422f72ec43d8f1b5b7a7cda81  9179332 main/Contents-mipsel.gz
 29c7cb90a08625ce542f17e508404c18 116019451 main/Contents-ppc64el
 1f33090ce0baf0bb3bc9d6ea4cd84f2a  9354602 main/Contents-ppc64el.gz
 133563b047d759ab618d6fd0dd0746cc 103634003 main/Contents-s390x
 3c59e89b92408eb10589ec95520751c8  8711391 main/Contents-s390x.gz
 463b35fbc23c26c5ac2099862328ea4c 687820704 main/Contents-source
 be6d6842ee4c5fc94aaadd9f56568d3f 73336828 main/Contents-source.gz
 1f4bf598c355a2bbb0c8ddf889d9636e   157382 main/Contents-udeb-all
 708ed31f29f9daf4c980b7abdd66c356    13516 main/Contents-udeb-all.gz
 3d7ad67750525190e6f4f066ef45bb31   477050 main/Contents-udeb-amd64
 1bb9e238edcff782fc9bc94e64bf2470    36035 main/Contents-udeb-amd64.gz
 90f74ecbaa1ce6726b48472fe51cbd11   508817 main/Contents-udeb-arm64
 ad76607c948f05e468afeb4b041958de    38088 main/Contents-udeb-arm64.gz
 7878d557eb1f11d75574c0b2a05e4b84   323083 main/Contents-udeb-armel
 566a18beaec5be263aced7de82388e06    25458 main/Contents-udeb-armel.gz
 4669785fa9e67942915ce406bd1009a6   579793 main/Contents-udeb-armhf
 5701338b063bb0999121b9f28e161181    43175 main/Contents-udeb-armhf.gz
 58c4a3f2166f7e5300ca05a345a1b684   751383 main/Contents-udeb-i386
 a835623c3a9e6691ea4595e27366e378    54210 main/Contents-udeb-i386.gz
 e4baa3f0aa7c5164378ff2196da5a269   760534 main/Contents-udeb-mips64el
 1c0b4ecab2621939569d9816c711025d    52962 main/Contents-udeb-mips64el.gz
 a09253c0af0acbe951e7995e053658cf   760210 main/Contents-udeb-mipsel
 54b7b5857662a62433fdaac56ec03820    53087 main/Contents-udeb-mipsel.gz
 d1ed14558f69d3db214a66cd56569cef   401639 main/Contents-udeb-ppc64el
 025bf3662932bed4f0c624718e21165c    29581 main/Contents-udeb-ppc64el.gz
 e733b69be29a09ff3f9b64342e4ddba7   258318 main/Contents-udeb-s390x
 171c98fa534feb4f22e7bfe4729e83e9    20884 main/Contents-udeb-s390x.gz
 f699800b9374ca855245371e976adb76 20421479 main/binary-all/Packages
 05b1b8e8d4162fbd1b7cbd2d3294535b  5207004 main/binary-all/Packages.gz
 92df286e3decf19e2904757698e9e8af  3918152 main/binary-all/Packages.xz
 bc544ee0279335b17f55ea25b555743b      114 main/binary-all/Release
 7cf338c864e25b09df9372bf32fe95a6 45528711 main/binary-amd64/Packages
 51742449b6ac62c7161fbcf53046fde8 11094668 main/binary-amd64/Packages.gz
 10539c0645350845373a0e99a4940140  8183676 main/binary-amd64/Packages.xz
 482bb5b46bac67fc7f880f5176ca9039      116 main/binary-amd64/Release
 796511d3b4f82e0f64f62a821a25d9bc 44810504 main/binary-arm64/Packages
 bd4189b6f89483e5aa93ca1077e7b6fb 10940076 main/binary-arm64/Packages.gz
 ad5c8408847c9366fd13ba7081ae3c2f  8070960 main/binary-arm64/Packages.xz
 1e3a9d5fecfe2079f0fe44699f1d5bc0      116 main/binary-arm64/Release
 7a895556c3af3122c0cb49f89a673d2c 43338381 main/binary-armel/Packages
 cae1c8651c50dfca247aa3d0cb43f844 10675797 main/binary-armel/Packages.gz
 26f98fbff7c490b5d7693c7bbd675165  7871768 main/binary-armel/Packages.xz
 c42c031c60e2fd456e058248dae0b352      116 main/binary-armel/Release
 c805432e0e332d119475e41ef28fcb3f 43840458 main/binary-armhf/Packages
 0ef105585620149d0c3f1a73ae6c66c2 10773684 main/binary-armhf/Packages.gz
 fbf4983fabfa45e4cefac36409e5425e  7944396 main/binary-armhf/Packages.xz
 817a0d701e04e9b2f96b95ae89e85c02      116 main/binary-armhf/Release
 29c36171128701ab8af2bde3bf7a01c0 45088761 main/binary-i386/Packages
 37a0a6ddb8ad940349bcfe970a7b83b7 11010534 main/binary-i386/Packages.gz
 56bd7d0362dc308af5bcc3956ccd631b  8121996 main/binary-i386/Packages.xz
 d912ff1feb1ef284ce04a71628a067a6      115 main/binary-i386/Release
 f68936a4a39b6ba76c39e8c6cd57238d 43727785 main/binary-mips64el/Packages
 d01fdc4586b50e954c31abc4df3bfe38 10719188 main/binary-mips64el/Packages.gz
 46d89c9bfb06730e4fde24c1baf73f3e  7906452 main/binary-mips64el/Packages.xz
 9e883dcc7e6f168545f6796d167bd473      119 main/binary-mips64el/Release
 db4e8abe79e6643cca53b3dc9f26fc63 43661440 main/binary-mipsel/Packages
 9bd1577030b691a122ad4d733f1b4f42 10725085 main/binary-mipsel/Packages.gz
 4cb999bcb5afacc11aff41e1894e38b3  7906220 main/binary-mipsel/Packages.xz
 ea78bc53559551131f18d900c2bc3afa      117 main/binary-mipsel/Release
 58a509a65e3e60e1e40b340f562edd1e 44657995 main/binary-ppc64el/Packages
 7d6803bf1a0a7281ce8a1ca5b9aa0fe0 10881744 main/binary-ppc64el/Packages.gz
 3a88a52c42d70739b0ff0d9d79d8a7d8  8030588 main/binary-ppc64el/Packages.xz
 4f0b9a532c6da6aa2dfa6e41377e955d      118 main/binary-ppc64el/Release
 9451f77d75ac3283c0131e743159a68a 43334701 main/binary-s390x/Packages
 e5aef53c920dd3e0cd81eb9bd219dc61 10685124 main/binary-s390x/Packages.gz
 142ae41120dd1c8d486db13f06d8fab8  7876624 main/binary-s390x/Packages.xz
 6404d3a68c3c08c8ea74719dade5d418      116 main/binary-s390x/Release
 8523f5593a344ec29029e3e20b8e10fa    61160 main/debian-installer/binary-all/Packages
 8322a8e0b943187cc1ad41f5e91e0c8c    16449 main/debian-installer/binary-all/Packages.gz
 73f68ee665b0ba4fe8b1d5bd0986e6a1    14676 main/debian-installer/binary-all/Packages.xz
 bc544ee0279335b17f55ea25b555743b      114 main/debian-installer/binary-all/Release
 82255c58df243dff3397254a62cac13b   274243 main/debian-installer/binary-amd64/Packages
 80770615cf67991131c7b40c9497c58b    67275 main/debian-installer/binary-amd64/Packages.gz
 f3bed5be2f4adc16e0c1c19051050225    56176 main/debian-installer/binary-amd64/Packages.xz
 482bb5b46bac67fc7f880f5176ca9039      116 main/debian-installer/binary-amd64/Release
 07e60ef061d551a3de72e96eac0fb216   257241 main/debian-installer/binary-arm64/Packages
 17cd69e611f884d79c5c529de982ef1d    64467 main/debian-installer/binary-arm64/Packages.gz
 84740e4c7bcfe0279839c876bfe0e6f8    53904 main/debian-installer/binary-arm64/Packages.xz
 1e3a9d5fecfe2079f0fe44699f1d5bc0      116 main/debian-installer/binary-arm64/Release
 cb11c6deca3a7dd622f8449f722b0c3b   248255 main/debian-installer/binary-armel/Packages
 9f924392822c83dfe59400e8b95d2994    63398 main/debian-installer/binary-armel/Packages.gz
 a1d1c24e2e3d3aeb9d93eb67c3e450f7    53120 main/debian-installer/binary-armel/Packages.xz
 c42c031c60e2fd456e058248dae0b352      116 main/debian-installer/binary-armel/Release
 6b52be203772a8e866ec6d83ec357ceb   251680 main/debian-installer/binary-armhf/Packages
 2814896015aad8b660464f36ba4e4acd    64543 main/debian-installer/binary-armhf/Packages.gz
 86f4a7add0caa9a6c363458c299c4b35    53812 main/debian-installer/binary-armhf/Packages.xz
 817a0d701e04e9b2f96b95ae89e85c02      116 main/debian-installer/binary-armhf/Release
 37f6e78f4724599e8896c3e87d4ccf2e   349337 main/debian-installer/binary-i386/Packages
 4e1daf1da2ca3b03e8f8ab189205381a    77055 main/debian-installer/binary-i386/Packages.gz
 3543849542805cee3a2a762f14ac7e1e    64020 main/debian-installer/binary-i386/Packages.xz
 d912ff1feb1ef284ce04a71628a067a6      115 main/debian-installer/binary-i386/Release
 0f95ab6e586e930c26cf9f10993e9dfc   364608 main/debian-installer/binary-mips64el/Packages
 6a95706ac50bd6ff369bfe4a48b2a93a    79152 main/debian-installer/binary-mips64el/Packages.gz
 ba3137547cf5d6c43a726d0062c1d880    66276 main/debian-installer/binary-mips64el/Packages.xz
 9e883dcc7e6f168545f6796d167bd473      119 main/debian-installer/binary-mips64el/Release
 cca0be4b409d8e7b027758320474924b   364094 main/debian-installer/binary-mipsel/Packages
 44aeea37e3b16ec9974f42c98a2635fd    79935 main/debian-installer/binary-mipsel/Packages.gz
 6c1464bd8c55fe54660ed64d3e154761    66396 main/debian-installer/binary-mipsel/Packages.xz
 ea78bc53559551131f18d900c2bc3afa      117 main/debian-installer/binary-mipsel/Release
 389af30cee2f634993868ac0fce16e6f   256825 main/debian-installer/binary-ppc64el/Packages
 3b1c5de31420f9e109cde962234b3aac    64820 main/debian-installer/binary-ppc64el/Packages.gz
 6706f846e3342d08c9fe6da46f1fcabd    53872 main/debian-installer/binary-ppc64el/Packages.xz
 4f0b9a532c6da6aa2dfa6e41377e955d      118 main/debian-installer/binary-ppc64el/Release
 88fad8aec2bb80b702523e338550fce1   226167 main/debian-installer/binary-s390x/Packages
 3047ce8a95aba1f2f4bf083a418ffd3a    60223 main/debian-installer/binary-s390x/Packages.gz
 ce0444f76c3471bb9db9a44bf65464f9    50096 main/debian-installer/binary-s390x/Packages.xz
 6404d3a68c3c08c8ea74719dade5d418      116 main/debian-installer/binary-s390x/Release
 97a6eda13094854f8838218d5869a796 18520413 main/dep11/Components-amd64.yml
 9cd807c0b66a8489b5385bf4f343b288  6213469 main/dep11/Components-amd64.yml.gz
 c16ba02c289510dce9857dfa6cde4550  4048504 main/dep11/Components-amd64.yml.xz
 3e8ecb0bbaecb88d0b16dfaa037dba73 18436837 main/dep11/Components-arm64.yml
 09ef5a87673c946f916b0d8ef0c2471d  6191092 main/dep11/Components-arm64.yml.gz
 fef127cee05f3efb96261e78b4fe4568  4033216 main/dep11/Components-arm64.yml.xz
 67becc674b536e310fe22492d55c8652 17658848 main/dep11/Components-armel.yml
 34cd8a6a1206f804e6d5c54dcdd3ef63  5952269 main/dep11/Components-armel.yml.gz
 d7cc0222cae53bcfa1de29218fe5cb94  3879744 main/dep11/Components-armel.yml.xz
 09010fea4c1cf082bd54aecc24182e45 18205252 main/dep11/Components-armhf.yml
 f5b7fd1a9cb147fa6b90e60a4d2139c1  6110587 main/dep11/Components-armhf.yml.gz
 f1f223ca9e69ad1901345ceb404a5666  3983180 main/dep11/Components-armhf.yml.xz
 ee8f83c597007ab84b58feec05d647fa 18485654 main/dep11/Components-i386.yml
 5a6b35ea7b54d88842ab30bbbd469623  6201776 main/dep11/Components-i386.yml.gz
 239cc12774e7c2925d1d783faaf01b5d  4041608 main/dep11/Components-i386.yml.xz
 dd59f50383f269a8e1ec09c49d8a786c 17819116 main/dep11/Components-mips64el.yml
 e3f03ed2f2c22dac3207e5f3fb98f862  5977494 main/dep11/Components-mips64el.yml.gz
 437c9fa1e058fc9a3486fb8b224740f6  3896708 main/dep11/Components-mips64el.yml.xz
 09d0cb63fdf4a4904155dc0d56ccc04b 17947079 main/dep11/Components-ppc64el.yml
 3d396ef7d8293620c5160a75fda04d39  6023058 main/dep11/Components-ppc64el.yml.gz
 23ebc600f44eb4973c351a4a324ba219  3925796 main/dep11/Components-ppc64el.yml.xz
 64acc85d1d2ce3e3dc551ae85e80ca57 17735785 main/dep11/Components-s390x.yml
 b7f851e780c93532c1707895dfa22474  5976062 main/dep11/Components-s390x.yml.gz
 117c2f52a672bca008f2c206ad8527a6  3894008 main/dep11/Components-s390x.yml.xz
 3f40799bee1a72a060f7dff19efa7b05 13048320 main/dep11/icons-128x128.tar
 6ac207d4fb6b76c25dc59edb50c3bf6b 11409337 main/dep11/icons-128x128.tar.gz
 66ce5f075d189138824e736123711450  4878336 main/dep11/icons-48x48.tar
 260bbc45bfa6b33e31399b4adb3b1f6d  3477622 main/dep11/icons-48x48.tar.gz
 47dea6d08e37b4a5154a072f3ad92cf0  9378816 main/dep11/icons-64x64.tar
 417f46677b9086f9dd0a425f0f39ee31  7315395 main/dep11/icons-64x64.tar.gz
 180389879ed6715b463d05b637e191dc     6191 main/i18n/Translation-ca
 8f8b7ffa4659d4f03b65ed28e69821f9     2673 main/i18n/Translation-ca.bz2
 b4ef33a20d80c576c7b352e96a86e063  1205166 main/i18n/Translation-cs
 d70ae6198f35f876b3070d928d5cdba2   323247 main/i18n/Translation-cs.bz2
 3fa5a10989da6ec5b19b5b6ba161b0bf 20240560 main/i18n/Translation-da
 e83f678061ca99aaedd2f20cb75bba77  4411163 main/i18n/Translation-da.bz2
 9f5077418506388082a72c7023c56f8f  7801238 main/i18n/Translation-de
 a57e3821e975f45d21bf2388a190b770  1717951 main/i18n/Translation-de.bz2
 a344219bf0eec9139d5270017ecfceee     1347 main/i18n/Translation-de_DE
 0fe0725f74bb5249f15f30ce965142d5      830 main/i18n/Translation-de_DE.bz2
 87bf9810c05aba15fb4aca6791feb73d     6257 main/i18n/Translation-el
 002ddfc4187acd8414873fe9f0a6442a     1835 main/i18n/Translation-el.bz2
 0cead0dd4b5609fafc8e901c960b635e 30246167 main/i18n/Translation-en
 26cb20d4d32e259e03ad8da6429f09fc  6239468 main/i18n/Translation-en.bz2
 0fdd8948881357f49ead0845c7e621c1     2261 main/i18n/Translation-eo
 43bd21f8b5d52b955e509e5893eef37e     1196 main/i18n/Translation-eo.bz2
 2ad9740f4bf39f163c04bd0b7266c1aa  1325929 main/i18n/Translation-es
 b4d4140461b4d6195e3337dcf541554f   317946 main/i18n/Translation-es.bz2
 2f7f0aac6c4ae5bd9c1499fd612ef996    10093 main/i18n/Translation-eu
 3178567e5f21fe43e4cf1f1a38ed6adc     3914 main/i18n/Translation-eu.bz2
 d1e71d50a88504d6b48c27960250acae   269212 main/i18n/Translation-fi
 9ca11408c191cfc5270f39467ed80f9b    75849 main/i18n/Translation-fi.bz2
 945a63eed28af4c45fd5185b334b33b3 11857302 main/i18n/Translation-fr
 06100e8db22b6d72d2c466bc85ea117b  2433064 main/i18n/Translation-fr.bz2
 f543980d7c6e8335eb0bb5d00b787418     1427 main/i18n/Translation-gl
 09c22bb0dfa3874802c4e7e4389f2b58      824 main/i18n/Translation-gl.bz2
 363537eb238e19bd527554a2d1de2533    21069 main/i18n/Translation-hr
 3fbd3535dcc2e805f0283d54bd38f5f3     4695 main/i18n/Translation-hr.bz2
 5393df220c56a4a92b91b2cac6843067    65236 main/i18n/Translation-hu
 61236a1bada04fd4ab090269498c5393    22243 main/i18n/Translation-hu.bz2
 d8d93a0510fedeb68fbbdae0342520c0     3983 main/i18n/Translation-id
 7542ee230bbc1f2f9f873c265b3b467f     1780 main/i18n/Translation-id.bz2
 87ba73fdeb9bac4348a4be42b2386f32 24489940 main/i18n/Translation-it
 9c9cd08156baf73f9f088bb97ac00662  4844227 main/i18n/Translation-it.bz2
 0f39595a0a049759d0d50ead781f73fd  4511401 main/i18n/Translation-ja
 74ff41ba40e19c9ceb4c607b122b7811   803966 main/i18n/Translation-ja.bz2
 85c4f9ec1e8e2d6faab177ef030ad2aa    11879 main/i18n/Translation-km
 46d57c586859cecf5c1a4470f666000d     2371 main/i18n/Translation-km.bz2
 def6a2d200b3c67b6a1c497524d0a631  2606190 main/i18n/Translation-ko
 3210a7e112a3f29ecf785ba05a78559a   584643 main/i18n/Translation-ko.bz2
 d41d8cd98f00b204e9800998ecf8427e        0 main/i18n/Translation-ml
 4059d198768f9f8dc9372dc1c54bc3c3       14 main/i18n/Translation-ml.bz2
 904af013a9ba73cd72f71a1ca451be5a     1193 main/i18n/Translation-nb
 bf917a722cf4d90cf2f56acb8edb1b31      738 main/i18n/Translation-nb.bz2
 cb57eb70e5645204174caec8edcc4a2b   174332 main/i18n/Translation-nl
 ad8c86dde21a892ff20203dc71eb981c    47973 main/i18n/Translation-nl.bz2
 bc88d84933fd8ae64ea0a7ba32a1e814  2051811 main/i18n/Translation-pl
 3095483ca3926b759de515651199283a   491993 main/i18n/Translation-pl.bz2
 d1736cf50b7994e7c6ce66962b7f4b03  1074959 main/i18n/Translation-pt
 7f9e024af1c410635fc69db5bf5d090a   272186 main/i18n/Translation-pt.bz2
 c3453467a749e3888da35949b643835d  3306707 main/i18n/Translation-pt_BR
 89726f5a5abac29bd3a6069e27019c9a   802734 main/i18n/Translation-pt_BR.bz2
 b50c9c49ea0a9da73b0a76db38a36ea4     1717 main/i18n/Translation-ro
 22696f68e30228ffbd84b26dbc821f81      982 main/i18n/Translation-ro.bz2
 52035b6ff376a4d7c38eea8bbd406751  3058931 main/i18n/Translation-ru
 d6c7de740e63ee4ce0e2044a0d449804   494782 main/i18n/Translation-ru.bz2
 2b383f6dbb23852965418241eda484de  5984088 main/i18n/Translation-sk
 04f2970e8de7fc5a090b84ab700cbb23  1304539 main/i18n/Translation-sk.bz2
 cf58326418b53f94289ad593878bfda2   323953 main/i18n/Translation-sr
 096b962e3404fbc28ebfb174e7587136    58385 main/i18n/Translation-sr.bz2
 366024c5bc4dabb550f8481c2d662611    85612 main/i18n/Translation-sv
 22b0c4eaa8e59ee11318ce2e68953f4b    27320 main/i18n/Translation-sv.bz2
 ced97abb44ee155f744680871aa5a6e2    14670 main/i18n/Translation-tr
 233a8366a334283e9b802cae336ed09b     5362 main/i18n/Translation-tr.bz2
 c8840c6e4bbe54b098d5b589e5d9e08b  3740343 main/i18n/Translation-uk
 7ed20cfd2585b8f77be6e2bab7561133   576766 main/i18n/Translation-uk.bz2
 2adb559c8ab8415644e43781db4f739a    21882 main/i18n/Translation-vi
 82caa7c535a1c4c7589a7b1647017f53     6510 main/i18n/Translation-vi.bz2
 f895594ce62c202132bbbe9ae32f1bc2     2007 main/i18n/Translation-zh
 3d2be55ee5ef9a79e0db9f90acc449cf     1215 main/i18n/Translation-zh.bz2
 91e9eec000876a989969a700ac7b3821   425199 main/i18n/Translation-zh_CN
 ab34838b3553d042d515eb65f5aa8816   113621 main/i18n/Translation-zh_CN.bz2
 34208715b80dcbd5fd1b87874a6705d4    39965 main/i18n/Translation-zh_TW
 6ed487c9d90ac9866174796ce73dec77    14859 main/i18n/Translation-zh_TW.bz2
 443509ef56f5cd834c102e704506a8f9    58277 main/installer-amd64/20210731+deb11u5/images/MD5SUMS
 fbb566ad6f594f59a7a89e871141edd1    78097 main/installer-amd64/20210731+deb11u5/images/SHA256SUMS
 8521cd018a0e0b50238dab3cf673c4f7    57705 main/installer-amd64/20210731/images/MD5SUMS
 bb4d5d5a421f536dcaa3f2e4fc96c1c3    77333 main/installer-amd64/20210731/images/SHA256SUMS
 443509ef56f5cd834c102e704506a8f9    58277 main/installer-amd64/current/images/MD5SUMS
 fbb566ad6f594f59a7a89e871141edd1    78097 main/installer-amd64/current/images/SHA256SUMS
 d27c82c0c6f1a36b6d6dd4093bf536e1    69049 main/installer-arm64/20210731+deb11u5/images/MD5SUMS
 27e0974ccb54c40c7516a4e8a618b1ed    94149 main/installer-arm64/20210731+deb11u5/images/SHA256SUMS
 8544dac6e811bff5ed42e276cf530ebf    68403 main/installer-arm64/20210731/images/MD5SUMS
 7989c6f2e37aeda05d7dfc58de88d7f5    93279 main/installer-arm64/20210731/images/SHA256SUMS
 d27c82c0c6f1a36b6d6dd4093bf536e1    69049 main/installer-arm64/current/images/MD5SUMS
 27e0974ccb54c40c7516a4e8a618b1ed    94149 main/installer-arm64/current/images/SHA256SUMS
 159763644df07713bf6ebd2593a565ed    20678 main/installer-armel/20210731+deb11u5/images/MD5SUMS
 15d72160300430e7b7b9e13ee41e7b83    28882 main/installer-armel/20210731+deb11u5/images/SHA256SUMS
 6e3afe07880cea11cee1a8ac19ce5d13    20182 main/installer-armel/20210731/images/MD5SUMS
 350c18339820cfa3989e1297c80b9f12    28194 main/installer-armel/20210731/images/SHA256SUMS
 159763644df07713bf6ebd2593a565ed    20678 main/installer-armel/current/images/MD5SUMS
 15d72160300430e7b7b9e13ee41e7b83    28882 main/installer-armel/current/images/SHA256SUMS
 a18333df6e46e6475cad7a938d540340    64380 main/installer-armhf/20210731+deb11u5/images/MD5SUMS
 6cdf61cf4df4bfb7c60350ed45a92356    92680 main/installer-armhf/20210731+deb11u5/images/SHA256SUMS
 3dca9930d681a0ba4186171684027ec6    64240 main/installer-armhf/20210731/images/MD5SUMS
 869454c4efa0fcddd91e08ab8ccf9d3b    92476 main/installer-armhf/20210731/images/SHA256SUMS
 a18333df6e46e6475cad7a938d540340    64380 main/installer-armhf/current/images/MD5SUMS
 6cdf61cf4df4bfb7c60350ed45a92356    92680 main/installer-armhf/current/images/SHA256SUMS
 b9e84ee51e1982d84a07164be0cf826a    56840 main/installer-i386/20210731+deb11u5/images/MD5SUMS
 bc2782ce56ba5d93553b191da39907d6    76724 main/installer-i386/20210731+deb11u5/images/SHA256SUMS
 8932831dfc7fb479ada48f6936639179    56286 main/installer-i386/20210731/images/MD5SUMS
 0ccfb273991e3302a49093743aa9032f    75978 main/installer-i386/20210731/images/SHA256SUMS
 b9e84ee51e1982d84a07164be0cf826a    56840 main/installer-i386/current/images/MD5SUMS
 bc2782ce56ba5d93553b191da39907d6    76724 main/installer-i386/current/images/SHA256SUMS
 b8afaac0d04431ec3afd5f66db0ea545      630 main/installer-mips64el/20210731+deb11u5/images/MD5SUMS
 e5e291a727afeb4fffce3a63ffe155ec     1026 main/installer-mips64el/20210731+deb11u5/images/SHA256SUMS
 9533fc15e5b64180b5ad78129a5230b2      627 main/installer-mips64el/20210731/images/MD5SUMS
 a776640760fbaacfb1681f3abd0fb40b     1023 main/installer-mips64el/20210731/images/SHA256SUMS
 b8afaac0d04431ec3afd5f66db0ea545      630 main/installer-mips64el/current/images/MD5SUMS
 e5e291a727afeb4fffce3a63ffe155ec     1026 main/installer-mips64el/current/images/SHA256SUMS
 4307544986807a0767a3e77e1865d85c      630 main/installer-mipsel/20210731+deb11u5/images/MD5SUMS
 e3e9872127c5079d03f803090f74ed75     1026 main/installer-mipsel/20210731+deb11u5/images/SHA256SUMS
 c3a9b6724a2ff5e2abf741f47a7600da      627 main/installer-mipsel/20210731/images/MD5SUMS
 01da3e1833ca954309023210e9b16159     1023 main/installer-mipsel/20210731/images/SHA256SUMS
 4307544986807a0767a3e77e1865d85c      630 main/installer-mipsel/current/images/MD5SUMS
 e3e9872127c5079d03f803090f74ed75     1026 main/installer-mipsel/current/images/SHA256SUMS
 130a83289e0ef5abe675dc3e53c5fec4      576 main/installer-ppc64el/20210731+deb11u5/images/MD5SUMS
 a2743fe266c3709533377cbae4bc5ca7      972 main/installer-ppc64el/20210731+deb11u5/images/SHA256SUMS
 37515f49026f1bc4682fefba24e9decf      576 main/installer-ppc64el/20210731/images/MD5SUMS
 89c70369e7ab670f721a135f055d81a4      972 main/installer-ppc64el/20210731/images/SHA256SUMS
 130a83289e0ef5abe675dc3e53c5fec4      576 main/installer-ppc64el/current/images/MD5SUMS
 a2743fe266c3709533377cbae4bc5ca7      972 main/installer-ppc64el/current/images/SHA256SUMS
 a158ec358551840ca40ffcdf7c5e1a8a      374 main/installer-s390x/20210731+deb11u5/images/MD5SUMS
 a83c8929bc74551e3eb9ed391b86567b      674 main/installer-s390x/20210731+deb11u5/images/SHA256SUMS
 580b19117c2b6c6f2a8ad8aca5132826      374 main/installer-s390x/20210731/images/MD5SUMS
 da16ad53b0185c6e48397e05f2efadfc      674 main/installer-s390x/20210731/images/SHA256SUMS
 a158ec358551840ca40ffcdf7c5e1a8a      374 main/installer-s390x/current/images/MD5SUMS
 a83c8929bc74551e3eb9ed391b86567b      674 main/installer-s390x/current/images/SHA256SUMS
 9d94e94ca9e1bcf2159522a347f72c4f      117 main/source/Release
 116c9feacc5a93e6d3cdba844a14a6c8 44649916 main/source/Sources
 71cecad0bd45c7342ac393bba882e7ec 11427358 main/source/Sources.gz
 73ee34b76e374fc93c672ed3e5d3003f  8633080 main/source/Sources.xz
 5f624011d3b0a82f23445c2861deac99 17347341 non-free/Contents-all
 c64dcd5c2b4db85f729afa8623adb65a   888157 non-free/Contents-all.gz
 97fec10f80ecd3041bd216612d921daa  1096728 non-free/Contents-amd64
 c72dc74d06c4d27dd32cf530267a4453    79664 non-free/Contents-amd64.gz
 6df10cdcb174d5272a719e762b1c308f   499361 non-free/Contents-arm64
 3573fcd985be8943f49643d931cf87c8    37247 non-free/Contents-arm64.gz
 f408ea79e9570389d5ee84acf709fefe    95417 non-free/Contents-armel
 b7a69ebcb774fa413e4016bb93c3d044     9298 non-free/Contents-armel.gz
 763aeff4fd5c86bd396aa535ba374356   146013 non-free/Contents-armhf
 a1113a2747da3a855bab895efe9ec7c5    13367 non-free/Contents-armhf.gz
 f55179a25ca478e176be3e2bc71e089e   343087 non-free/Contents-i386
 7ff5a14797e11e7e7e3b4c46aa47d71e    29107 non-free/Contents-i386.gz
 900df746b6e7accfd8883d31c7d28313    91215 non-free/Contents-mips64el
 7c382180d55972ff768bb8a05222a412     8686 non-free/Contents-mips64el.gz
 904ab7d197244bdfdbf6b58bc61d09ac    92244 non-free/Contents-mipsel
 73868036dab5f62f60ad63ebfb7ca253     9026 non-free/Contents-mipsel.gz
 0bff855caa859b8d756675afec011231   715688 non-free/Contents-ppc64el
 1dc9c3c9d777e5c22ede2b2ed5171b95    49907 non-free/Contents-ppc64el.gz
 f3aa91e39f1d170310ec9820ea4dae2d    74537 non-free/Contents-s390x
 2b363c4c14b66b56f3009f85c29415dc     7407 non-free/Contents-s390x.gz
 92da1025b4cbc350d26510b88a348509 10803360 non-free/Contents-source
 680c6b732de50f50b23260bd7fcb99f0  1063351 non-free/Contents-source.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-all
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-all.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-amd64
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-amd64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-arm64
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-arm64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-armel
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-armel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-armhf
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-armhf.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-i386
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-i386.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-mips64el
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-mips64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-mipsel
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-mipsel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-ppc64el
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-ppc64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-s390x
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-s390x.gz
 28683b0c800362ab66657f988f8fe158   189021 non-free/binary-all/Packages
 8b503f66350a43348e728ef668a3e66d    50928 non-free/binary-all/Packages.gz
 89e1a28553ba1bf59ef7a537d0e13dcd    42996 non-free/binary-all/Packages.xz
 49b1b6fec3238c7e663dec3b80b922dd      118 non-free/binary-all/Release
 11d337d78e926be15121abcfbdcb50d2   546840 non-free/binary-amd64/Packages
 932855d49afe0f276dba1748dade0d11   122055 non-free/binary-amd64/Packages.gz
 ad5c6ab129dfb2b284930e97682e1d4f    97740 non-free/binary-amd64/Packages.xz
 18cae19f8d18f62b268e41e0be2d5315      120 non-free/binary-amd64/Release
 0b2b8c298843e0588c96b6653b3eafd8   382463 non-free/binary-arm64/Packages
 b82bc2d184c650350ed6fb4f71958736    88539 non-free/binary-arm64/Packages.gz
 03d0fda6e3c0d155471884b52d7125bc    72928 non-free/binary-arm64/Packages.xz
 c5546f7d8404c96bf01dd39438c9d06c      120 non-free/binary-arm64/Release
 0967ff1cbab012d79d544d2fc19bcb3c   227933 non-free/binary-armel/Packages
 66f87c4a0607b4d535045f41bb1debbf    61822 non-free/binary-armel/Packages.gz
 943edb5f2d977c5e883e123d7a162a3c    51800 non-free/binary-armel/Packages.xz
 20a3bacde42e2b9a0d2cbf763ff9ca1b      120 non-free/binary-armel/Release
 46000da36bd6830910e9f79c5160a191   259172 non-free/binary-armhf/Packages
 a5376cbf892a9941d146f27b670ab7ab    67212 non-free/binary-armhf/Packages.gz
 ff55081181e0daae501bfc39d403e0ab    56280 non-free/binary-armhf/Packages.xz
 c1214ed9bb2e72dc83dc206e3e0d8d78      120 non-free/binary-armhf/Release
 882e165e0f29c4c21433e5b709be0cd2   423212 non-free/binary-i386/Packages
 300475eed5077329a3ff34ae5cce1f35    96326 non-free/binary-i386/Packages.gz
 cb619a10c5a0ee7057b63e89d7dfc422    79316 non-free/binary-i386/Packages.xz
 9518a4b76323b41207a57a6b43497fe6      119 non-free/binary-i386/Release
 b241349c71327389608d1ed7805fb917   225506 non-free/binary-mips64el/Packages
 79ea1e07e0c12ca9587d966e90a803d3    61024 non-free/binary-mips64el/Packages.gz
 800788cecc80de3a8dc8555edc4e1f3c    51124 non-free/binary-mips64el/Packages.xz
 d2bd5b0a8914b38dc23996250b83a7fa      123 non-free/binary-mips64el/Release
 5637ea382ea6ea47628b489854f51823   226162 non-free/binary-mipsel/Packages
 cb900ebc58b732e246dad1c05c2da62b    61277 non-free/binary-mipsel/Packages.gz
 eefd4b08c8da7bb89f71627c9f05a04e    51364 non-free/binary-mipsel/Packages.xz
 89879a273a5b2432cc8b41f12e8ba550      121 non-free/binary-mipsel/Release
 955018ea729c77b602a4f4843ae28831   381757 non-free/binary-ppc64el/Packages
 2acb70ad8398655e3582209c1112533a    86688 non-free/binary-ppc64el/Packages.gz
 22fb8689bb2c01fa7cf74cb7221d55e3    71824 non-free/binary-ppc64el/Packages.xz
 9f5ca5bbe85ae2a24d677a0afcfadd23      122 non-free/binary-ppc64el/Release
 205f9ec14fe81d12021eba70ac927040   220570 non-free/binary-s390x/Packages
 73a6b1dbd8f6c0ffbc4cb90c8737651b    59856 non-free/binary-s390x/Packages.gz
 d4f95c7b3fed2787ebb231f6e8fea4ef    50216 non-free/binary-s390x/Packages.xz
 991f40d49ffd7e78d3a19ede3039c758      120 non-free/binary-s390x/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-all/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-all/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-all/Packages.xz
 49b1b6fec3238c7e663dec3b80b922dd      118 non-free/debian-installer/binary-all/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-amd64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-amd64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-amd64/Packages.xz
 18cae19f8d18f62b268e41e0be2d5315      120 non-free/debian-installer/binary-amd64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-arm64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-arm64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-arm64/Packages.xz
 c5546f7d8404c96bf01dd39438c9d06c      120 non-free/debian-installer/binary-arm64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-armel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-armel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-armel/Packages.xz
 20a3bacde42e2b9a0d2cbf763ff9ca1b      120 non-free/debian-installer/binary-armel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-armhf/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-armhf/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-armhf/Packages.xz
 c1214ed9bb2e72dc83dc206e3e0d8d78      120 non-free/debian-installer/binary-armhf/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-i386/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-i386/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-i386/Packages.xz
 9518a4b76323b41207a57a6b43497fe6      119 non-free/debian-installer/binary-i386/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-mips64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-mips64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-mips64el/Packages.xz
 d2bd5b0a8914b38dc23996250b83a7fa      123 non-free/debian-installer/binary-mips64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-mipsel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-mipsel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-mipsel/Packages.xz
 89879a273a5b2432cc8b41f12e8ba550      121 non-free/debian-installer/binary-mipsel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-ppc64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-ppc64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-ppc64el/Packages.xz
 9f5ca5bbe85ae2a24d677a0afcfadd23      122 non-free/debian-installer/binary-ppc64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-s390x/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-s390x/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-s390x/Packages.xz
 991f40d49ffd7e78d3a19ede3039c758      120 non-free/debian-installer/binary-s390x/Release
 f7208886e345a2c1c5681b7bc1f891f3   278293 non-free/dep11/Components-amd64.yml
 ab8bcc71919bb29e6a367d9058dc0125    29634 non-free/dep11/Components-amd64.yml.gz
 afd21b4c476c6b604c4f998d90383234    17904 non-free/dep11/Components-amd64.yml.xz
 71e3cebf69c369e3d4e6b64e48fe037b   271451 non-free/dep11/Components-arm64.yml
 4b40bf8ff6579f425fd308cc4f32bb26    27686 non-free/dep11/Components-arm64.yml.gz
 04fa2b6c4dc8d23f6ee6334754b725df    16392 non-free/dep11/Components-arm64.yml.xz
 678290cc20fe4c69fac625c25f48577f   271451 non-free/dep11/Components-armel.yml
 b76376c24cdd9bb014e63503830766f8    27606 non-free/dep11/Components-armel.yml.gz
 b431acc1b0f700a021a3ab1305bc3c33    16448 non-free/dep11/Components-armel.yml.xz
 7f659804cad02381ed7735779c211771   271451 non-free/dep11/Components-armhf.yml
 0221ab3c0654617c6de5d2b74eac7b15    27691 non-free/dep11/Components-armhf.yml.gz
 2df1dfb4d502d5c01f744bac99e8a0bc    16364 non-free/dep11/Components-armhf.yml.xz
 1422b7cb028418049315374e46dcbf86   280613 non-free/dep11/Components-i386.yml
 7a014ddef58173efeb07ce9d7b866331    31098 non-free/dep11/Components-i386.yml.gz
 ee2f702d30a2274d969a8e9044da54f2    19156 non-free/dep11/Components-i386.yml.xz
 2f39022b38ebd28b86acd148ad0389d2   271451 non-free/dep11/Components-mips64el.yml
 5e839450348a20fc9f81cdc9dd0b9663    27765 non-free/dep11/Components-mips64el.yml.gz
 fbf40f634081acbde994e89d8731d159    16380 non-free/dep11/Components-mips64el.yml.xz
 4ff7e301bb5eaab539783f39c24b421f   271451 non-free/dep11/Components-ppc64el.yml
 d7c37af104343f2eb2b10a0980c96661    27592 non-free/dep11/Components-ppc64el.yml.gz
 afabe491b91df1be19287ea4e978e7aa    16576 non-free/dep11/Components-ppc64el.yml.xz
 05dc5f141a7ca96f1aae6d571dd37361   271451 non-free/dep11/Components-s390x.yml
 4a5b9e250991cd5d661db03f4bebefa8    27558 non-free/dep11/Components-s390x.yml.gz
 b0593a88d870f066f1a83dfb382e09c5    16356 non-free/dep11/Components-s390x.yml.xz
 40dd67e0e1f81416405be5c0dc8ee47e     8192 non-free/dep11/icons-128x128.tar
 b117213e4fd39f9c75c1699ebaf3d610     2394 non-free/dep11/icons-128x128.tar.gz
 08a465949d80332d065e6f4ec8459930     4096 non-free/dep11/icons-48x48.tar
 49466a3c36fe0d0cbb5940896da60960      741 non-free/dep11/icons-48x48.tar.gz
 5d6e61a41610797276e5b6f16d60f7e1    36864 non-free/dep11/icons-64x64.tar
 0196f7b979db4111a6d9b988e63101a0    27667 non-free/dep11/icons-64x64.tar.gz
 b6b0d2a078505acd28578dcfe8739441   573037 non-free/i18n/Translation-en
 219c55cb8f93412a82aa5fed50b767b6    92432 non-free/i18n/Translation-en.bz2
 32236b6926cec4ab2aa6afd96f61c87a      121 non-free/source/Release
 e1c5dc3828ab6b1a7cac54890b7fcecf   359801 non-free/source/Sources
 69aa7bc179af15f0f5ec49f394f3dbe5    98071 non-free/source/Sources.gz
 93b3d4094d591c7575ddb74eca06821a    81220 non-free/source/Sources.xz
SHA256:
 3957f28db16e3f28c7b34ae84f1c929c567de6970f3f1b95dac9b498dd80fe63   738242 contrib/Contents-all
 3e9a121d599b56c08bc8f144e4830807c77c29d7114316d6984ba54695d3db7b    57319 contrib/Contents-all.gz
 e60f82140294e076f97a4148cfd8e594ae808c423d40b62be455bb28af8fb6d8   787321 contrib/Contents-amd64
 845f71ed2a0a3ea784c355427362164cb316b01e6ce956a38ea95a001711709b    54668 contrib/Contents-amd64.gz
 1ad2b49ab401affafeb146c2badf94f1d699abd27f52b57d5e4b0fe3d37c9682   370915 contrib/Contents-arm64
 5f54b4d15ca5a9308eee238da9fa9512dcf8ec15a55cc22fce4efc3142146c01    29596 contrib/Contents-arm64.gz
 b4985377d670dbc4ab9bf0f7fb15d11b100c442050dee7c1e9203d3f0cfd3f37   359292 contrib/Contents-armel
 f134666bc09535cbc917f63022ea31613da15ec3c0ce1c664981ace325acdd6a    28039 contrib/Contents-armel.gz
 b5363d1e3ec276a0cb10bc16685bd02bdc330719d76c275bebd344adaa91583b   367655 contrib/Contents-armhf
 fc4edd280f2b254dbfa98f495e5f4ca6047ec9a1539ccb8754a1f93546ea32b5    29236 contrib/Contents-armhf.gz
 77d465435ba8f5bad03b76624835f91e9ebf3bb09b124ab1a06e70c8b2629b30   407328 contrib/Contents-i386
 e4a82b31ac7b5b139fd3bd93ad466de75f7bf7d54410967253044895e41c36fb    33556 contrib/Contents-i386.gz
 c0efa60eaa3b47bd93ca71220c6fc734d54b257e16bb6dd8dde43ca722f242dc   359402 contrib/Contents-mips64el
 4fccf5298ef664c2de3dc7eeb203eefa3bf8ec82b95b1c696b856a43af35e395    27962 contrib/Contents-mips64el.gz
 db2388b4b8d300fdc265fe064288a8de5f69958b06ed6cfeff3b8528e719015b   360549 contrib/Contents-mipsel
 27db69688406433748363f4a70cac108f29b99555a6d5dc3eaba6b2e8b526dfc    27942 contrib/Contents-mipsel.gz
 e62412c1f585461c8ae27d4d2a79b82c27dba109ac19df81a15ae7f53369cf65   370025 contrib/Contents-ppc64el
 8ac6ff54ba23486d9c139ee79a6296760dc20022209ffc321296967717a37fd2    29381 contrib/Contents-ppc64el.gz
 bb1fdc3fafd28760f57d951e96a150e8ec7d6b0fb75443de93f08a61ffbd7042   357860 contrib/Contents-s390x
 009373ff8cde80de63a4303b8c6eab79af34d6c2c0c831d1b38e1f9329c396cc    27518 contrib/Contents-s390x.gz
 7d79e95f92007f2885bba7ff9d40a81cefea96959cb090dc7cde26a77e7f1ea5  6722669 contrib/Contents-source
 d6655657ff285c9372e18b0ebff346e922694de31669d6c0260e789306841e9d   469817 contrib/Contents-source.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-all
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-all.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-amd64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-amd64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-arm64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-arm64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-armel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-armel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-armhf
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-armhf.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-i386
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-i386.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-mips64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-mips64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-mipsel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-mipsel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-ppc64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-ppc64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-s390x
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-s390x.gz
 70d58353b3bc6083f3946ebcdc1f150204988bed60df8c0389fa23b26924adcd   103239 contrib/binary-all/Packages
 9baa8f0dbe243eea5e03bc9551b0e5774ea0ba690db28ae63d1f81cd6e16aef7    27385 contrib/binary-all/Packages.gz
 24cb5963261a9cb0a4671061d65ee51e211e00ea754e4f5ec6426a1a78745ec1    23916 contrib/binary-all/Packages.xz
 5278681c78d4669f20007a177246324b3fae4fe9d9428c35a55d6779b4bab5f9      117 contrib/binary-all/Release
 25bba54443595d2760419c8873b026880ad3553697b4254f0473b7c859c3526f   231878 contrib/binary-amd64/Packages
 05b545380de2e24307c4b33497327a397b5fac53c53c2479d487280c69c55b7b    60884 contrib/binary-amd64/Packages.gz
 572aa5c4767342e411f9ec261ebb871a48da20400d37e9f960c0f3960a26fc66    50588 contrib/binary-amd64/Packages.xz
 324b6befdda212e8863d4ab822bc1f65b4507533b50a11dfce54ab3664341a80      119 contrib/binary-amd64/Release
 7ab66ca6c3c1f575100f8e39fee460115ba8292a489c07e9ea1b0a914e47f67c   180884 contrib/binary-arm64/Packages
 4da911f1c6926b85d6a9a025d73be907124db4a3e99872b0128ad2187a5af5ef    48958 contrib/binary-arm64/Packages.gz
 07b68a663f305c1a676642f078a3d9243072e2f2402ad87c405f0a4c7744cab1    40964 contrib/binary-arm64/Packages.xz
 a197958cee52196ed3a5f654a36cadf9cce2d984c4ec0f63c456d98f44918474      119 contrib/binary-arm64/Release
 d353d3f7b451cb07472d111221866fd89c6e7b28ad0fe66044f35e2eca6189fc   163042 contrib/binary-armel/Packages
 5333591cd2ee7e750d864f875799c83b4985f0473a02e525365db3fc5b27ab36    44389 contrib/binary-armel/Packages.gz
 6493591c5f010aa3b50e7052c4746f6afe40a0fd31ffcce08c706aec6e7b672d    37452 contrib/binary-armel/Packages.xz
 6b00e08c72b5f8595175ce87b68ee72118b8baec08f759a681d5bad664422ec7      119 contrib/binary-armel/Release
 75d98358dbea38501853ae9cd7a2da4f84d02eb4543bd9e96f0c3e6cd5945533   175566 contrib/binary-armhf/Packages
 fde856e3b07624cb5e3d6c11dd450aae8e56f38646c4b3f3b7cbe0423f78970e    47805 contrib/binary-armhf/Packages.gz
 c572038b5ced50f74da2baa5cda8150846cface0b285218336f6af4e1365b9b0    40220 contrib/binary-armhf/Packages.xz
 945bc1a22322d6387fb9e5482de9b651eaaa46c6c123b7c57c4fbb6520a8b82a      119 contrib/binary-armhf/Release
 6b9d6d64b15686f83bf58c5e2255bdef26a5f2cdd97c76b047ea46f533aeb0bc   203514 contrib/binary-i386/Packages
 010b321fd585b2d1c45512db80e60aefdd0fc7bbc60a53e1594ba9ad5f9ba45a    54100 contrib/binary-i386/Packages.gz
 a17c01bbbba0f218b3a38cb5b7fc3053a7cfb6364453b46b6b80687d11eab142    45340 contrib/binary-i386/Packages.xz
 8dcdd196782578c6bc3f766c0dc50dd452d0ad4c66c04d4fefc6285edc4a1368      118 contrib/binary-i386/Release
 4c71f56a967f6f390c1e6d381f399d74da5a545c8906f014fe805859ba9ae55c   163507 contrib/binary-mips64el/Packages
 49f3fc82266f184e331b2b0ea0762540b8ef68486f299a5673b247f8c03d3858    44652 contrib/binary-mips64el/Packages.gz
 e0c365ed89f4538b36ab3366293d3b9f4e8472b9537d91b770f650650021f4e1    37496 contrib/binary-mips64el/Packages.xz
 0bdbdcc4f8613847154389a4f053a8ff034da02e8bf9e3867498fa48f26fc7b6      122 contrib/binary-mips64el/Release
 a951b730b4a059ef33073627d50a40f204591c3a5348fbe1c5e3b21782a77e5a   164647 contrib/binary-mipsel/Packages
 662a2fb412beb7130ef5ba0440ec368825d21713392a55ea33048673bbcca3a0    44883 contrib/binary-mipsel/Packages.gz
 7a01af1780b68648eec3923fbe4fe766e210e83f0ba8b03f6bc8b9a8d4c0169f    37816 contrib/binary-mipsel/Packages.xz
 ca8370adf924676e1c8978f40f85afa3a475ab9bbdaa29279ba78e276e69f6a1      120 contrib/binary-mipsel/Release
 8ff5ce44abf0d9fba97b3ce63b2d41db58d24b463dfe23cf06069a71724f7047   180387 contrib/binary-ppc64el/Packages
 ddf5d43553c9af8a6dfa0ff6f51236dee72fe15d2a09ecc9212bfeee5e667e92    48843 contrib/binary-ppc64el/Packages.gz
 84cd02fcb4a610501538fd06ebf77a67ef7badcbc6f5b1f338c6d013329ea38e    40808 contrib/binary-ppc64el/Packages.xz
 d88c72cf7f9ca32b9047c00fd083c8113f750c6c9c700e61717d5c4830c96ea4      121 contrib/binary-ppc64el/Release
 cfc032377fc264eff4a6319ecfd2722e95de7364a63b29eed53cc78603a8a8aa   162250 contrib/binary-s390x/Packages
 72be2806452fee7d70ef80ffac98e3f408e7389dbbbaaa6d9228f48a6733b773    44334 contrib/binary-s390x/Packages.gz
 9a14a52c690b24eb92939192abc4d4e8b23a2347a838232774016ac79c3d8ec8    37244 contrib/binary-s390x/Packages.xz
 7f7694e5c9f942d9ec057c4db5036e21ceff49aaedd303d5beae73db2fb76ed4      119 contrib/binary-s390x/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-all/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-all/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-all/Packages.xz
 5278681c78d4669f20007a177246324b3fae4fe9d9428c35a55d6779b4bab5f9      117 contrib/debian-installer/binary-all/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-amd64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-amd64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-amd64/Packages.xz
 324b6befdda212e8863d4ab822bc1f65b4507533b50a11dfce54ab3664341a80      119 contrib/debian-installer/binary-amd64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-arm64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-arm64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-arm64/Packages.xz
 a197958cee52196ed3a5f654a36cadf9cce2d984c4ec0f63c456d98f44918474      119 contrib/debian-installer/binary-arm64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-armel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-armel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-armel/Packages.xz
 6b00e08c72b5f8595175ce87b68ee72118b8baec08f759a681d5bad664422ec7      119 contrib/debian-installer/binary-armel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-armhf/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-armhf/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-armhf/Packages.xz
 945bc1a22322d6387fb9e5482de9b651eaaa46c6c123b7c57c4fbb6520a8b82a      119 contrib/debian-installer/binary-armhf/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-i386/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-i386/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-i386/Packages.xz
 8dcdd196782578c6bc3f766c0dc50dd452d0ad4c66c04d4fefc6285edc4a1368      118 contrib/debian-installer/binary-i386/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-mips64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-mips64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-mips64el/Packages.xz
 0bdbdcc4f8613847154389a4f053a8ff034da02e8bf9e3867498fa48f26fc7b6      122 contrib/debian-installer/binary-mips64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-mipsel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-mipsel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-mipsel/Packages.xz
 ca8370adf924676e1c8978f40f85afa3a475ab9bbdaa29279ba78e276e69f6a1      120 contrib/debian-installer/binary-mipsel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-ppc64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-ppc64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-ppc64el/Packages.xz
 d88c72cf7f9ca32b9047c00fd083c8113f750c6c9c700e61717d5c4830c96ea4      121 contrib/debian-installer/binary-ppc64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-s390x/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-s390x/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-s390x/Packages.xz
 7f7694e5c9f942d9ec057c4db5036e21ceff49aaedd303d5beae73db2fb76ed4      119 contrib/debian-installer/binary-s390x/Release
 f0a51e6d75f883bdecf739b214104a17dba111de8b42022f6b8b053870c83851   119152 contrib/dep11/Components-amd64.yml
 e14a1bb3690a18ec7c5b7997fabf4d8d4fa633efdf84a25e071a1f62a2c064b2    15579 contrib/dep11/Components-amd64.yml.gz
 58921318632f77413bee8d9e980689f8f139eb1169b5ce201da06e6f280d485f    13564 contrib/dep11/Components-amd64.yml.xz
 26538634f90cd6f04a6be602151fa6a098075c3013b66a81439a7bbdbfaa40f5   113437 contrib/dep11/Components-arm64.yml
 840908ab753dba952e073216007f93d351577792911dcc09a15a16abfc32c8a7    14251 contrib/dep11/Components-arm64.yml.gz
 3afec5908036aa2d47b9a9a33c13eca12bba1aaf8d8bbb06ffb1627e93f6526f    12480 contrib/dep11/Components-arm64.yml.xz
 fb35649f6c32b71b9d85388c2c238011161c250df5c62e2c4d3446e369dced4c   113437 contrib/dep11/Components-armel.yml
 c305f1c0826e0414bbf36524d8b0fc2723ffc0fb222275e1e1728914fc334c75    14029 contrib/dep11/Components-armel.yml.gz
 fe15a53774801f8d9cb04aa8324cbdb9d741ec75ae0999e033873458bd6160b0    12524 contrib/dep11/Components-armel.yml.xz
 0ed24b6d7ff891c82697497dddfbbbb6818c168c55b41ae710e9cc9240d0d9b2   113437 contrib/dep11/Components-armhf.yml
 f5260cdac915ff5eba0a48757c93f8f8b6421a673e641285f43d83f62be3eb8c    14127 contrib/dep11/Components-armhf.yml.gz
 db97becd2ab6a05bcef05d824b89080a1e7c03a69735df3bf5945f6989a9e504    12480 contrib/dep11/Components-armhf.yml.xz
 9adf35216113140c31c2e9c169a3eaa465044f41f8803afaac955c467a1e5a49   118972 contrib/dep11/Components-i386.yml
 c1d4ea9c0ac26f2b62d45c8c595ec9a5bc1c737b50634d7f86a4bfac17c9b180    15566 contrib/dep11/Components-i386.yml.gz
 51ff60d5f02b46e08acea4054484f5c66d721c19beff4857cb2570f43e881a69    13560 contrib/dep11/Components-i386.yml.xz
 50b6970af7de299a90ac651cceb6cc011e8d165ea0701f7b1c9daf6c1be485f0   113437 contrib/dep11/Components-mips64el.yml
 78aad16ddec6b18d30ce4e20f52008f72efc78ba55688fa462741f4bb514043f    14056 contrib/dep11/Components-mips64el.yml.gz
 efb0fb003bbd3997128bef56f12104872604fad320b38fd99bca25e68210d98e    12500 contrib/dep11/Components-mips64el.yml.xz
 05c2268c20e748baf8da20f7169918e2f6dcffb6e4f6dfc22829607cec7ea564   113437 contrib/dep11/Components-ppc64el.yml
 19f600014e245e7d07762b7f07d8de6884b1208a280a19274e56b4174931082a    14219 contrib/dep11/Components-ppc64el.yml.gz
 dc8b525d7043ba3a85154ad39d0c809e7215c5b2f3865efbd94ff3daabe54810    12496 contrib/dep11/Components-ppc64el.yml.xz
 5d43b650d261ac23815d98e9a4f644d56f4113e63f8a42b1558ff1c82e925d2f   113437 contrib/dep11/Components-s390x.yml
 c1811e0538dad96441a4172e661b9ef7fca9c05d86c4b157a66046bf49aa70e1    14050 contrib/dep11/Components-s390x.yml.gz
 42356b4c04801189947748d6fce6e28e356a114869a7895e4921a3b4901e678c    12488 contrib/dep11/Components-s390x.yml.xz
 641e9a50f98d7e4921102164e7737b095c9faead09f6de4459086b598b3bf0d0   271360 contrib/dep11/icons-128x128.tar
 34b531c5292651ac5a18d0477bb8cf1420f3d969ad73d45fd596641d768b853d   195507 contrib/dep11/icons-128x128.tar.gz
 fa3a19603046c258e647b0c1fcdc6110f0b5c1f2801ee950eb1261e8c02e03d6    83968 contrib/dep11/icons-48x48.tar
 28a6f153e56e9b567cc7fc03d6faa6dfb8480ee3f36e0c8d9646e4de3898480b    47168 contrib/dep11/icons-48x48.tar.gz
 d882fc33534a8677ed8d3ecf81f7a076fa57e8e8135bf586f8af20371edb195b   138752 contrib/dep11/icons-64x64.tar
 45c8eda64d05f1feee0040809128760f9489665d66bed0502cb179fe0ec79f6e    93294 contrib/dep11/icons-64x64.tar.gz
 094badc305c90db005324c484a55d88f14dfc805aa429856a5863a96518a88e8   192685 contrib/i18n/Translation-en
 ce7d3d607194cdfabf421c313030e88876ee899d5cd01f5b023cfdc0c0ed0f40    46929 contrib/i18n/Translation-en.bz2
 4dd5f25f2212e88564895e4466c4c5e8175a65f0f30166636b57d874efc5a90c      120 contrib/source/Release
 e331ac856d30949d3d70b299678f1f23462785681c70a62205ae35903d2c50d0   178776 contrib/source/Sources
 b34bb0d3527f1086ae23a6d2ae47bf790572a7d07ff0ad444f0f2c68afd3c504    51355 contrib/source/Sources.gz
 99262e6c7f527f6654eb8e8b3415ee29fa5f2669d9bc22ce95881422b4b9b603    43208 contrib/source/Sources.xz
 3f2b8929cbe32de0688a816901ccb23c165f4e747304c8f6aa696012dcd3543c 477036454 main/Contents-all
 6d3e1c298560baf170a1741a12ed4344b6328cb0733ba26c9e05a81aff0fa15f 31026385 main/Contents-all.gz
 9a45e522826c5c185d4672fe2ea2fb7bda097ebe0b9a6da1ae5faf8a0602e6ad 129049566 main/Contents-amd64
 44e7844f5c8d7800ff5544ce05b6ebb80c71df298d35c6bfdcd3eea8bba42b1a 10269094 main/Contents-amd64.gz
 1ddf22ad0856fef8e7afd40837f42e84e9ac6e39875d56c1fe52b191cb9a3621 122421950 main/Contents-arm64
 672d03fea4ae5ec7876e99674e4f51551d1e82d42953c6a7b757f94753ea57cd  9830625 main/Contents-arm64.gz
 751e91be2de57f29c9eb6f6d6391210741216b62736bd5c06d90581bcb908f91 104678675 main/Contents-armel
 73f064367b40c0e1b157b9976070d34ddf51ed26d3280a91e30539f01edf3d69  8703118 main/Contents-armel.gz
 68cbd9e7aeb8708b9d432da4bce5121ce96ac526b48c495386ed017f4100701d 113712023 main/Contents-armhf
 be143e17762b575350a46a8bf2cd1ca2a3692f66f68b632d0702e93101cff990  9305876 main/Contents-armhf.gz
 46ed9692a93ae3c6c30f9c84066338343d5f827cf52831a91e4dd270eb5ad57a 129083944 main/Contents-i386
 6084b02a99074cf74375c573422066633e3b2f3d6964b934428de351a700eee8 10206461 main/Contents-i386.gz
 20b3417f775e022f8d5c8d51267e6a6ff63380d376152a03f35064347405280b 111092579 main/Contents-mips64el
 1b2c91af3c0c91754c4f4cea272758172e71a6887575dea461a4c187bcb6dc71  9042857 main/Contents-mips64el.gz
 03cfa7fb7dd7601b7c9a35e1f10136c8047cd09f4343b97c1213c082bbaa11b1 112589241 main/Contents-mipsel
 ba2d1f79ed6e35bbd9fbc5cd32895261a1275a4628f5aa5a339f10e92ccc0934  9179332 main/Contents-mipsel.gz
 ad1ea3a56553b6d8c0f33aee70ed964c2a640f560440360e6f06b0aba14445fa 116019451 main/Contents-ppc64el
 e7a300700dfb88e603ea670081cfbd27b91789ad8934b76c065bc21070a9cf2c  9354602 main/Contents-ppc64el.gz
 e25b6f0a418765f0280adf7f2b7900a64521ebf4d8ccf4fd89e98fce28193cae 103634003 main/Contents-s390x
 7a668ad93849da1801690848debb2e956a29a14ed0ccfda39d0f1ed374a1e77d  8711391 main/Contents-s390x.gz
 a76f4f95d6ec6177fbd682762fc3f10c9e49d0093f3976b6e26df08308781a40 687820704 main/Contents-source
 92ab1b21b71b5b77ec2ccb43413022d2cb5c81fdc79888ee77308008dc87f756 73336828 main/Contents-source.gz
 b709d41e19af82147c367d90a74eae144ab18744d78817b6395fc1344fb99c76   157382 main/Contents-udeb-all
 f9801d96354f0b11d5357633cb9068dff1f39b9210eaeb70455db63ee0ecbdbc    13516 main/Contents-udeb-all.gz
 d79266ed182fc40abad00fa8e0adbe4347207f930aea8fbe49d705c5faef2cb0   477050 main/Contents-udeb-amd64
 354749c24bbfcedda09b770a4c0c236e6eb4549c5b7f51181f41562ce6cf92e7    36035 main/Contents-udeb-amd64.gz
 ac2a7bc9f985553e82b086fc8488493bc5dde86814f27476dabe60e94c92ee35   508817 main/Contents-udeb-arm64
 0d75157733315e71557a90615015cbec7d1cde5eb24f6b9f8d68dd0a733db1f7    38088 main/Contents-udeb-arm64.gz
 5fa5b370468253f39803834d15cf35008beaecd2eef1ad0e945c9cfaf63da51f   323083 main/Contents-udeb-armel
 cf78aaf40308c7208953a2c0ab4ac1f2eabc5d4840a76ebea84ee79ff62ed173    25458 main/Contents-udeb-armel.gz
 fd3f516a5ed23984623b29c9c1f6fafa088a73e947c5d8dfb20fd01f0eb94024   579793 main/Contents-udeb-armhf
 c652f4e7119aa475b7d169a942fd37676e31552e18e2768bf4f2c48ba9594081    43175 main/Contents-udeb-armhf.gz
 238a6a69785c460f59b9d9e21db3d084f8f32579456d6873ec17afdcb16b745c   751383 main/Contents-udeb-i386
 9280b751ca54e6dfb4a8a17b28f9c713b2bb373f653f79acb3bab1452ddec57c    54210 main/Contents-udeb-i386.gz
 7addd4dc3083c65c3753c973abbef06154e49cad08a1ddead4fe44542309f824   760534 main/Contents-udeb-mips64el
 ddc74c11b026f5c8da375eb37c76c3f02c5812c73c3c2cd4fccfb7360746d729    52962 main/Contents-udeb-mips64el.gz
 1f911341f27642c280f807999228d3b4fd8a68466981f38fd67bf5de4cc8764b   760210 main/Contents-udeb-mipsel
 3b10e2ea348afc39981998b2050694db7cabcafbec3cb45e59a587e7981e6475    53087 main/Contents-udeb-mipsel.gz
 6227ceab2971b9d210302bbc22eab7db95a263d8bba789f48722223fddb92cf5   401639 main/Contents-udeb-ppc64el
 a4464d4e6b912c4404ebf098355236a362465478202188e649ef4cf22b351038    29581 main/Contents-udeb-ppc64el.gz
 8d76f6ef57a42751bd2582f41a071feb708838ca8c57bd83b26aaf1a446ab8f7   258318 main/Contents-udeb-s390x
 b1393bf88b56471ab85f49b8c62e78a224afad8c04110ab3178e2b4f35199793    20884 main/Contents-udeb-s390x.gz
 d98bd2cbcb75ae3ee93c4a33c1bdaa635c2ab6f052f241af66ecd64316b99659 20421479 main/binary-all/Packages
 075985e01dcee15df0250e79e33a04a83d06ef6f7dc31aa4c39c376124b9b6aa  5207004 main/binary-all/Packages.gz
 2968cf0e1ea8d0479e48538b04f8fb2ae4a48a837f2559a95acb7e50bd2b0cc7  3918152 main/binary-all/Packages.xz
 3db4b195c1e8a1cfc87ce0744d03297983cb724f3b0dde77693689aed86b2657      114 main/binary-all/Release
 c9a01efe4d3aa3f0fb609f41841767338190f877e7bee6e049b704bd39b27f0d 45528711 main/binary-amd64/Packages
 fe5bcdd6ac93c00b20485468d4b918f4bdee2834a3deab88ed6dc39c6940452b 11094668 main/binary-amd64/Packages.gz
 c21a4111128e3f286b5a0b9543641c86bc111d4e2d0a41b0bb8db1ea4845ff68  8183676 main/binary-amd64/Packages.xz
 31c1a0185254c4f6110cdad4fffab559296f415f6ebd4b60201062cfa6138095      116 main/binary-amd64/Release
 e73f28cdf3470410bdf0ece975cd6c3db9a11d39bbe05c5854f2dd4278dbe478 44810504 main/binary-arm64/Packages
 a0ec47995660f5c40449688233ce56676a790286d755227192e5a0367b3c0fd6 10940076 main/binary-arm64/Packages.gz
 28ab034223cfbbdfd9fba80aae2b929b2245802ddd65b7526e7f8b100556209e  8070960 main/binary-arm64/Packages.xz
 486de2cd2a974b0a0325ce25681586151bfbcc0e5bab55b9ed8e2446f601516a      116 main/binary-arm64/Release
 ffcf1d3fd19d8d78cd6245086275c144d6bab43b7368dd62065b9e251a442a78 43338381 main/binary-armel/Packages
 a085d8d3fc8b579a84424c10d0038829bd81f48b47cfd5598c1a9ac2156e3150 10675797 main/binary-armel/Packages.gz
 f7da978ecaedbcc71852e574471ee62042b8b8637767a217f1db31bf693ec208  7871768 main/binary-armel/Packages.xz
 3aa826b2cfd3a2d91918e70bd5854b519efd77554f9c99778ac666d87629fbce      116 main/binary-armel/Release
 ce2599c2f043de4a02a7353af27df5f0c86d4192db0fb691a141142f058c5e63 43840458 main/binary-armhf/Packages
 6e4dbadd632926b83fa8039d6933107f8ea0243c01e86910bb03ae921560d860 10773684 main/binary-armhf/Packages.gz
 a0ab55af4ee8f91de38242acd43b8875086a1406b071109c077192ee68b26fea  7944396 main/binary-armhf/Packages.xz
 44b2af069e2f24b0a889986272228d38f7af6c0564b680b8decde6bede2e6ccc      116 main/binary-armhf/Release
 4d980d36f1674b027906a218fc17a0cfc3680e26930af410807a20ab0541c603 45088761 main/binary-i386/Packages
 470a5acbbc2c6af4f5f07a4e815466211e5a01ddf0ce22814094c16028d81b04 11010534 main/binary-i386/Packages.gz
 b47ad649de0ae530b021a2d33ea2bf45ca27d0ed2bf89b316fb39c7213a8f15a  8121996 main/binary-i386/Packages.xz
 e886408900056bca9e5a898e46b266e8aa91882978835f428f08174569d5d809      115 main/binary-i386/Release
 8af5ed2759ccebe249165dba345f372f56da46d7678333fd2bc46b49f4f6fdb4 43727785 main/binary-mips64el/Packages
 236b6f076de1587b20ee85d5cd9fc98838544cd23726c232ffd9c54e16b7f4b3 10719188 main/binary-mips64el/Packages.gz
 878b51a09cea700c2080be99fafb98a73a58634c44945fd68da5d06d93af3948  7906452 main/binary-mips64el/Packages.xz
 73a242cab0e8fe82877b348fd7939b7224e48c889cf067007391805f4a1d4f81      119 main/binary-mips64el/Release
 8509b8df4c0607a992e5230f9aeb99c0cd8405b3ce4617ed15a31e894759a13c 43661440 main/binary-mipsel/Packages
 70f512096bf2f69a923dac45cf629a73bd828eb24717b0ee5fdb8c197a1261c5 10725085 main/binary-mipsel/Packages.gz
 1fabbd4368c8bfe55e91462144d675f5e11650e6f0773cedfae357da875892bd  7906220 main/binary-mipsel/Packages.xz
 3bd73949e332fa2b17d30fd448c0f495dcfc8290e9c43009deb3f41d63c5404e      117 main/binary-mipsel/Release
 eaabacbdeea22779f270a290b236024c0555572ab3144980b5526fda7a38db1f 44657995 main/binary-ppc64el/Packages
 67d1a1ccdc6c8877c046febaa7a26246ff785f34eca67a3bd7546660ef9ed0b8 10881744 main/binary-ppc64el/Packages.gz
 0917db1b5b0d0aec30ad5002a29b7775fe14f9325555979897004ed66c4758f4  8030588 main/binary-ppc64el/Packages.xz
 807289b1a3f43cb0730a54f3aa30aa5e706c4ceed72aa7b2723b15df0e72644e      118 main/binary-ppc64el/Release
 3cc00c21f6a73698444495bd2e4eac006c0a52bd1bfaf930c1f5d91279dbefa5 43334701 main/binary-s390x/Packages
 d7fb68dcec086947554d2db56f10e27cb34ec300194d9b1aa23030a7809cc6af 10685124 main/binary-s390x/Packages.gz
 8754101e4c42646ceffedf33499ebe7201b770d17652b728c05f9b9feca3ed86  7876624 main/binary-s390x/Packages.xz
 d2a0d381a36fd92ee88b0ba2c3c19c5f9fd833a43c3f0e315f11e8d28d9fb58a      116 main/binary-s390x/Release
 4f60d86324cc91f8ac32625dfd1f8750a7f79e866376a34a478d2d3f8033ce84    61160 main/debian-installer/binary-all/Packages
 1e0c3c1d9f21267ec4183fa21ffb26808808678d6393cde03820b5f8c677977c    16449 main/debian-installer/binary-all/Packages.gz
 3831da178354890a18394e5d531c28c77f70c6fcc628e369eb584fbf7ce28812    14676 main/debian-installer/binary-all/Packages.xz
 3db4b195c1e8a1cfc87ce0744d03297983cb724f3b0dde77693689aed86b2657      114 main/debian-installer/binary-all/Release
 5b65761b8526e8f98c433b1fb93d4a43a25ebcc4bc413fba73f2da154a3978ef   274243 main/debian-installer/binary-amd64/Packages
 798ee5c3d50ecc4d82cf3a97467779fab807f2b33cd9d1efd8e9d5555b30d383    67275 main/debian-installer/binary-amd64/Packages.gz
 0ce8867e2160ca31c772598bb2b718b00dc670419fe07ea13f47b9a6c1c24961    56176 main/debian-installer/binary-amd64/Packages.xz
 31c1a0185254c4f6110cdad4fffab559296f415f6ebd4b60201062cfa6138095      116 main/debian-installer/binary-amd64/Release
 b1993be7119c3e1a9555c6f875df4361af9f805f5315abe501ba813424b6cc49   257241 main/debian-installer/binary-arm64/Packages
 84e1984a52995378d85b073ab319d7f570986b11fbf1fe5dac5b0310847d90da    64467 main/debian-installer/binary-arm64/Packages.gz
 c05d262ca12db68483f052959f34348b37084e03e90af044a04461125e97bb39    53904 main/debian-installer/binary-arm64/Packages.xz
 486de2cd2a974b0a0325ce25681586151bfbcc0e5bab55b9ed8e2446f601516a      116 main/debian-installer/binary-arm64/Release
 cf8766af885196b4374ca5967b17e11490793d45c22e1058134a6348702562e1   248255 main/debian-installer/binary-armel/Packages
 b1ac18b57d79f45995019feefdcc26f5b8375aec1537022eac6e37327a04ce31    63398 main/debian-installer/binary-armel/Packages.gz
 fbda3f2404ad13ce6aca4f26395e4b8dbd2e4b39962f399381ae358a17e782ba    53120 main/debian-installer/binary-armel/Packages.xz
 3aa826b2cfd3a2d91918e70bd5854b519efd77554f9c99778ac666d87629fbce      116 main/debian-installer/binary-armel/Release
 5801e555fca148d0d372994ea86dd3d18587279cf2fcd879c3cdeb03363454ad   251680 main/debian-installer/binary-armhf/Packages
 7dd6022383a076c4265a11f9a5d1fbdf5cf8c6f46e89f31d141d47372153ee69    64543 main/debian-installer/binary-armhf/Packages.gz
 774b82831f7bdc73e999ee1b53e79f1a12c0f6d116c15489c466f49c74170608    53812 main/debian-installer/binary-armhf/Packages.xz
 44b2af069e2f24b0a889986272228d38f7af6c0564b680b8decde6bede2e6ccc      116 main/debian-installer/binary-armhf/Release
 ac37b99cb3c78aed8e5a89678c6891fec800af2e08db830f3335c7ea3429e8d7   349337 main/debian-installer/binary-i386/Packages
 12dd5e10465c9e6fd1a4e2e395591c8f49eba735960d529cb98f9de9463f6333    77055 main/debian-installer/binary-i386/Packages.gz
 cc5eba4c45a90e0facd09db27bb19088de98bcac9ee40790c6f0c5d7df16f498    64020 main/debian-installer/binary-i386/Packages.xz
 e886408900056bca9e5a898e46b266e8aa91882978835f428f08174569d5d809      115 main/debian-installer/binary-i386/Release
 d3e172018281d44748abf3273a9ce7a3c50f77df511a4120bafe953d8e67c7f1   364608 main/debian-installer/binary-mips64el/Packages
 f48a723d3eece5f1a9f79106035f0db6c74b9e9439e124d6f08cab2e4d0ac6de    79152 main/debian-installer/binary-mips64el/Packages.gz
 05748822c41e38d261e4261248b0f658ffab9b436a2988152bab8c7760618936    66276 main/debian-installer/binary-mips64el/Packages.xz
 73a242cab0e8fe82877b348fd7939b7224e48c889cf067007391805f4a1d4f81      119 main/debian-installer/binary-mips64el/Release
 224d6a4da647a44d9a7c7528be0f0ab30928d1e519a14198ed302de78cfa120a   364094 main/debian-installer/binary-mipsel/Packages
 68bd51a65cc9756e10fe89ea801103e57e2187a1af8531465fdaa536a6625daa    79935 main/debian-installer/binary-mipsel/Packages.gz
 279f65a0aa643225149d7bbe8018ed71bb414d07aa2219baee2623d78774d85b    66396 main/debian-installer/binary-mipsel/Packages.xz
 3bd73949e332fa2b17d30fd448c0f495dcfc8290e9c43009deb3f41d63c5404e      117 main/debian-installer/binary-mipsel/Release
 9dae6d81c1dddeece8f435ef9545a25484747a744047d9695eb8823a969ceb51   256825 main/debian-installer/binary-ppc64el/Packages
 941a537d49a442cd90b379c423ae5ffdd67904f61a6f07ed893d9b170d338733    64820 main/debian-installer/binary-ppc64el/Packages.gz
 7e34c852f021e67c6439786b124b38ea54f3fe8a63a8d8f8bb67a0da9f4814d2    53872 main/debian-installer/binary-ppc64el/Packages.xz
 807289b1a3f43cb0730a54f3aa30aa5e706c4ceed72aa7b2723b15df0e72644e      118 main/debian-installer/binary-ppc64el/Release
 4bca9ea0256522eaa4fdf6beccec8c33c1ba38846bc7f5f0c54a78a6b361b68b   226167 main/debian-installer/binary-s390x/Packages
 7ba77624002394cfb6580bdf5a42c7683e11489be8cddbc8198f80cc7ced910f    60223 main/debian-installer/binary-s390x/Packages.gz
 1bfa15fa45d74b6297ce180f1deb236abd8b4b67f304a5d9bb59b38045468b0e    50096 main/debian-installer/binary-s390x/Packages.xz
 d2a0d381a36fd92ee88b0ba2c3c19c5f9fd833a43c3f0e315f11e8d28d9fb58a      116 main/debian-installer/binary-s390x/Release
 99d8d572b0219a7b37addc91ff4e4ff238a33b3452580d4bd2469588a2225cad 18520413 main/dep11/Components-amd64.yml
 9c5522d811abead85a73407f6b56b171207105bb3641e22d76f2146482d4750b  6213469 main/dep11/Components-amd64.yml.gz
 0b517038e27fe4864c35de9459537d91f5d274800a172be69f91e90bb3631589  4048504 main/dep11/Components-amd64.yml.xz
 ed767617ad156481cc8948fb72c2d699d6292bfd2d83fb2f24b2b155612dc539 18436837 main/dep11/Components-arm64.yml
 1732a30dff783f891da2245f955becf3a43be40f0400b722087ba626316e980a  6191092 main/dep11/Components-arm64.yml.gz
 a02d6259b836d37804838b6de8f40568332a9a78cb4bc7668b32208f6062e782  4033216 main/dep11/Components-arm64.yml.xz
 aa3eea13a49b29dba27956d6fb6093817775361e29fef3f751e8e70b7065e54d 17658848 main/dep11/Components-armel.yml
 ca3d41da75c25408834b265c9c95f700a1241189f6bf62270e14b85920f5cdc2  5952269 main/dep11/Components-armel.yml.gz
 5c90b5a79fb5cf11b4e822396183bd3b4d3712e5f8e9363c5fce4a3a6c42a58b  3879744 main/dep11/Components-armel.yml.xz
 9d95db48c33d5671c96a2931458a92b6290e9c3f880c7ec7d7aef2b23a681eb3 18205252 main/dep11/Components-armhf.yml
 55c47f2e4607828ad1d875c1ade2aea6565916e9dce3e043f6de2e85b6cd74c4  6110587 main/dep11/Components-armhf.yml.gz
 20797715d417813ddd77d1bf746b8ea9f6353ad0e8be2e67f1700813d992268d  3983180 main/dep11/Components-armhf.yml.xz
 5579083d9a290f05eeb86967fd664c46464b3bafc00c073887560523a1793a64 18485654 main/dep11/Components-i386.yml
 ac8dd6c8b9e575785646a7d41adc7783956e22bcc757a60c80f225328c769f08  6201776 main/dep11/Components-i386.yml.gz
 589f93188296c83e394c89ccdaae1565436dc203161958e96f3a5cf2797684ca  4041608 main/dep11/Components-i386.yml.xz
 2b028df6a795c2a4b058b0f239745da363ea0f8b9fb8ce1a7955bedf579cc8cc 17819116 main/dep11/Components-mips64el.yml
 0865e497ec87d5d45f84106166bb035610443e87528aacc1a43f13000542a3f5  5977494 main/dep11/Components-mips64el.yml.gz
 46745049532f14f438f41704b442c157ee0f2990baed5d06da8fda3b41501547  3896708 main/dep11/Components-mips64el.yml.xz
 c0e1c64172edc19edcc287b0e617adff28b31354028de4c755cdf1fd077de913 17947079 main/dep11/Components-ppc64el.yml
 ba4eb9c1ab3f03a7fd184e5fc47dce250c083a617d9e2ba49a70c920fd957b29  6023058 main/dep11/Components-ppc64el.yml.gz
 aa34918432eeb8a82d912d86f69d82e84a4bc0eb48056ebe321b83d2757d1052  3925796 main/dep11/Components-ppc64el.yml.xz
 dc222c504c71bbc9ff6b698bf5ef7942e098efff1031861e5eb8670afdd18452 17735785 main/dep11/Components-s390x.yml
 29584e8fd8bc91d9d9099893ae4951601430b1df4f55659e089d34e4525540e5  5976062 main/dep11/Components-s390x.yml.gz
 1f9ca828b916aabab9b41f75950df49f71dc5e8a42f674ff4cb2138f85274314  3894008 main/dep11/Components-s390x.yml.xz
 057f28adb7c2452ab2c810fdfbfce0305ba8143ffe2e24969b2ece077aba7e9f 13048320 main/dep11/icons-128x128.tar
 4f46415e13538a05743752a630c9b8795a9772d0ab4ebe83c9d7e19f0e4bf179 11409337 main/dep11/icons-128x128.tar.gz
 e0c306e3293ecdcb8392faa372b00f1fb979c327c3e4370452acf7713ab885a4  4878336 main/dep11/icons-48x48.tar
 93c4366d8b6ef489bb935434d9a2c56d842978922e941dd4ee716ede2a805494  3477622 main/dep11/icons-48x48.tar.gz
 910ec31c85f12f0edefbb43fa2514b9896d105ce7316272a4c55263af864c238  9378816 main/dep11/icons-64x64.tar
 a94629c3e4fbe9607fb2921e1c906f88343a7cadc484a1087983181ae6df66a3  7315395 main/dep11/icons-64x64.tar.gz
 e061ee16e4478c39875bc3d977fdd5f880a71a3ea97c9f5119ac127a4305579a     6191 main/i18n/Translation-ca
 ed06627194c667d774188bcf0d9b859625ec60d2098238ee3c1cd5e1c147c4f7     2673 main/i18n/Translation-ca.bz2
 857bef6538df7a4e2ae01a6ef40f8a5c9e0512797a769d8813caaa57ca867f29  1205166 main/i18n/Translation-cs
 bdd79636af5f08f4c40bb5266a41e4707b7bdc84d5458451df0255b787c380a6   323247 main/i18n/Translation-cs.bz2
 2c7c6d7013e3d04a62c457525567fac4ac2747ef59f1b2a93cad8c0904c960b9 20240560 main/i18n/Translation-da
 8935ec6ddfeaeb542fe444013ad9fefd6ffd2da2afe818efeb417fb50568b52e  4411163 main/i18n/Translation-da.bz2
 55e94848df1df7d0963f3cb02cfb4171031350c549e4ae64f6aed517ed08ca6d  7801238 main/i18n/Translation-de
 b68fe8718325ebd1e2a8dd30f52b17c003e315f3468f9b7890fe5b1b91c709cd  1717951 main/i18n/Translation-de.bz2
 284169348b8bd4e0de4cc5641eeb05577e80d2bd736452e454976c052cf3cbe2     1347 main/i18n/Translation-de_DE
 481a435ad350105b74c4972859c44f447b7a8b5edea0d42f6dd635792e00a461      830 main/i18n/Translation-de_DE.bz2
 9f3b3bc0da0653f0ac8484024a7f77aeda681474907f3a94b8a0a0933775d14d     6257 main/i18n/Translation-el
 807de361285151534654b83681415016d443e4abd1a7ba36e1e78b4ac337b973     1835 main/i18n/Translation-el.bz2
 09c45eea9a2e7d53d147997ae9a3bfc1c09745b47681b662c441a8f733042f82 30246167 main/i18n/Translation-en
 ac20511e42bec76c88103ae001ac0785dbd4f5fba3763d2d98a43433f968f91b  6239468 main/i18n/Translation-en.bz2
 abccaeb24d409c21b94883b74785053d0f8fad3e94449078ebe92af38861bc5a     2261 main/i18n/Translation-eo
 747ab457a83de3b107e25b9cc5536aea2f19e0fe1f08d5357475acea0d788fae     1196 main/i18n/Translation-eo.bz2
 38345d246390b3845920937338647a70b1a6a93f354615da725fbf426ac3e332  1325929 main/i18n/Translation-es
 d6bd3bb26fb52e553bdaa40a041aa167f8a0c207149ebf626bea65c90ff7e99f   317946 main/i18n/Translation-es.bz2
 80c3ff00f3b37b64e73c85b11eab47fe88901b6f8d9f189de0e95a387e02ebed    10093 main/i18n/Translation-eu
 7ce6c68ef8a577bd215da5f7a12153bee27268b0b6b9503aaf88244b225f20a1     3914 main/i18n/Translation-eu.bz2
 54c5db1926c3309513d37990460a51c586ae6f01bcaaf2732e537ae400b6f5f5   269212 main/i18n/Translation-fi
 a0c315c9c517ac029e5981f14a3c15fa022c7c0e1e86edf123e05027343974d7    75849 main/i18n/Translation-fi.bz2
 bd258bc1f5bbc6694e24f58fe4dfb5f5636afc86a431795b931225e9e336feb3 11857302 main/i18n/Translation-fr
 ef77125783dc8b1125ea85050ba00bfe042e6f38fa1f73613387fe30cae47c5c  2433064 main/i18n/Translation-fr.bz2
 ce1a70b1000909a09166e30d574c717f3d60ba173bb65ad65e768374dc73232d     1427 main/i18n/Translation-gl
 fa1eb924fc1473b81f7790ccd909de1dc274f4f266df8af544261f03e1d21079      824 main/i18n/Translation-gl.bz2
 22e19c218655a9a4d09e9930a66715aeb5d0b02bdc4d147e5816067873e71861    21069 main/i18n/Translation-hr
 04e538e90503a9238d071bba89039e563d4c03ee038c217708a4f8c8672c28d6     4695 main/i18n/Translation-hr.bz2
 a275d9da1b509fc6c1d8307ff33daea14669cec8b8f89bb4c4fdf4d50ff48135    65236 main/i18n/Translation-hu
 94827a9f6e251237fb3b093360f88ba469d2be8d4a7c2c02c84298c94faceaa5    22243 main/i18n/Translation-hu.bz2
 0f4bfaba954ffa37332a34df69c8844b7334cc0b61515e9510513e2c43e140b1     3983 main/i18n/Translation-id
 11aebe26133b1249ebc06ec6d1a8b76f5975b9a3630daf71ecb7e2f6521a2fd2     1780 main/i18n/Translation-id.bz2
 d965461960f14ff1f614bcd0ba757874e098cd460b8ae0e018fb4aba254ce641 24489940 main/i18n/Translation-it
 451a92cd21dc98889f43a39223dc8863284bd1a8e515bc58633bdb7bf96dd37c  4844227 main/i18n/Translation-it.bz2
 1cb8cbfe8b502cc64639b02150e6f805bdeebedae3eb69273146c03ca6c9287c  4511401 main/i18n/Translation-ja
 0c00e0a8cff6fb13bdc4ed3387e3faf4f9db94f3ed4ca8e72d324c0a03d8f018   803966 main/i18n/Translation-ja.bz2
 7238152be74233d91630f7100ef7ff2bb8a95598b5fbc11c21c7afeecfc0fecd    11879 main/i18n/Translation-km
 01577e06c8e41b3a914ae539147af0fcdc7a0f883f50d82b57b263cf62fe1bf8     2371 main/i18n/Translation-km.bz2
 232cb289feae187cf94ad451662d7ce36be8014c40b69e645d19b9534dd586df  2606190 main/i18n/Translation-ko
 894aba3a34a47f3d59deca3bda07f8aa288e9f4ed6ae92422eab3fd9dd370ad5   584643 main/i18n/Translation-ko.bz2
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 main/i18n/Translation-ml
 d3dda84eb03b9738d118eb2be78e246106900493c0ae07819ad60815134a8058       14 main/i18n/Translation-ml.bz2
 16be336bba03786450a43321709eca2fce7fa7b50a135a97da71e16eb5e7d60b     1193 main/i18n/Translation-nb
 fdec5fc00fe2d0e3c7730462f95273492d278eb8a6957c1b437969833366c217      738 main/i18n/Translation-nb.bz2
 ce65092fbb0a09286644912bfaf3a9535921705519e16d07617ad85ec44ccf3a   174332 main/i18n/Translation-nl
 e12b923a6f3f83636a31e6e1b2503d8a213e1e4112586a27700fc17bb48ce564    47973 main/i18n/Translation-nl.bz2
 8999184566c11a42f9a31c810d9252316dc4f52ba738db43e0be2cd760c823a1  2051811 main/i18n/Translation-pl
 17fe48deb79b044bdf5894d0d129823b1d86653b9759f848667a74b563625379   491993 main/i18n/Translation-pl.bz2
 2dbf3c4316bba32571abc589b177be93c8e72885131940c9993d3fb6b8d58cb4  1074959 main/i18n/Translation-pt
 991a66952f6395d7588f38e68e1032f4dcc72da61322a59460c34a24d7713400   272186 main/i18n/Translation-pt.bz2
 5d7ec6fe173a67789c445369b7ebf8709cbc9ce4f3e06a75cf36c562a16580a1  3306707 main/i18n/Translation-pt_BR
 1583cdd6a71e29b6eaea0d29dee9ce903fc8ced1f9f57e5ad4de154938799bd0   802734 main/i18n/Translation-pt_BR.bz2
 c90708ca8975ced4acf4be98a4ac1f5c8092fd826b4d928e35c3650e705553d4     1717 main/i18n/Translation-ro
 35f2449dba7bd93e0aece908f4c4de53cc864a48c8f7aeaa5a64f67384e1bcda      982 main/i18n/Translation-ro.bz2
 f8b907289a1970413a47a3450c59b04e166c08cb387ee3ae4f6c0d2e4774c379  3058931 main/i18n/Translation-ru
 8685feba7a33fef7ad8d7fe5db5f59e837eba69134deb87610742cf564e47258   494782 main/i18n/Translation-ru.bz2
 ee2a1713ba3ccf4aa7ef3ee1b5786874c38ecc15db012bc15c3efbf5ad8facd2  5984088 main/i18n/Translation-sk
 0dfec1c42d581b3fe8f95bbe26f649f45234d419c7e709dc881f1994bfb20974  1304539 main/i18n/Translation-sk.bz2
 5ff9c60997a547f07d212476a8f50b4942f012d7952765c6c1925c52495711d1   323953 main/i18n/Translation-sr
 b4608fc3c0c7f6aefe0f6e5e19d0fbe0d5035333e74044e29358b3e3efa99536    58385 main/i18n/Translation-sr.bz2
 5656d4e913760691e99cd4805e76c8f18c4441fe707a02e621a2a172da756d5b    85612 main/i18n/Translation-sv
 fbad8c083b9985e53a2a82d7e32f26f683bd5b8e2f1bf09a3e0fc3f8f7abf6da    27320 main/i18n/Translation-sv.bz2
 2e50dd5fdf1dd6157c0db51afb4457fcfbd427ebb6d1268aeeea1daf50da78f0    14670 main/i18n/Translation-tr
 401a0f8d754d92c562bafe54aa0cb2dd7686ca015425513b666b50b8c9dc36a7     5362 main/i18n/Translation-tr.bz2
 6c66f49d6c9df7ef28f92aaab2620a2151fa16f74bf96deb3b74987183e43b86  3740343 main/i18n/Translation-uk
 bd760427bda1a65895dd7b3bd6a3e2b2a0ee6b4060ce726ec4b7c02b89a72204   576766 main/i18n/Translation-uk.bz2
 c2207dfa8d62c7e2a31851842dd928739bc147515f69fb7a28db93196dd1a601    21882 main/i18n/Translation-vi
 e3eab47e1acdc01ee2d774dba5b0f9d29c98ff48b25a57d469eeecf60d3035ca     6510 main/i18n/Translation-vi.bz2
 7133134d1b1b6c869b4b700fed9778e93a0b774391402ad3399e9ff46984efff     2007 main/i18n/Translation-zh
 8cbeadbbcec613b8476f8e2aa40b15772909109e10a83317c111fcf7c28d0219     1215 main/i18n/Translation-zh.bz2
 d88628c7a7a16a042234daf91a709daa6d5f9de15406ec78530891354fa25c75   425199 main/i18n/Translation-zh_CN
 1ef87b145198090deb2d037bc16b5b940c0e757a2511f4ff84a7c750720b2723   113621 main/i18n/Translation-zh_CN.bz2
 564fdb3059cffbe78dde61697e77edd7bc94005a358cc4b5dffb436776d1b2b0    39965 main/i18n/Translation-zh_TW
 0a4d5ecccec7069a32b30de129018034b2f6f2b318f1530e1edc239182442cf8    14859 main/i18n/Translation-zh_TW.bz2
 85bbaf9bc3847c4c2037081dbd6cfb2c4c5f5c44f25a959d963d36ee7caf77d0    58277 main/installer-amd64/20210731+deb11u5/images/MD5SUMS
 f8d4aa2143f4ba40f60739fa64237745ab8b79c53aa44ba0cad167b53794ab69    78097 main/installer-amd64/20210731+deb11u5/images/SHA256SUMS
 91e63d03c43f9feaed6c255a510c30c35c547c517f395c2574900b0119fad790    57705 main/installer-amd64/20210731/images/MD5SUMS
 a3a16cc4af2d688613ce8df4d224974629ad3383a1969350c24ea68bfdd5f1e5    77333 main/installer-amd64/20210731/images/SHA256SUMS
 85bbaf9bc3847c4c2037081dbd6cfb2c4c5f5c44f25a959d963d36ee7caf77d0    58277 main/installer-amd64/current/images/MD5SUMS
 f8d4aa2143f4ba40f60739fa64237745ab8b79c53aa44ba0cad167b53794ab69    78097 main/installer-amd64/current/images/SHA256SUMS
 a3fe1facb1422b11f3e3f6e212470eaca3f8dc416f764c3f648989f6e99de512    69049 main/installer-arm64/20210731+deb11u5/images/MD5SUMS
 a90d9554e1cd4c4c7021570d19da546fd746818c9333c3f7e953dbce4f9b3185    94149 main/installer-arm64/20210731+deb11u5/images/SHA256SUMS
 291e81049aa85b147063ec1aa5bec87da60d3196c06c3098de5210c3346837eb    68403 main/installer-arm64/20210731/images/MD5SUMS
 5dfc89487fc8717ab9a9b75cdaaf01a295ab3021cc3310d3fe9dd3e78fc1f666    93279 main/installer-arm64/20210731/images/SHA256SUMS
 a3fe1facb1422b11f3e3f6e212470eaca3f8dc416f764c3f648989f6e99de512    69049 main/installer-arm64/current/images/MD5SUMS
 a90d9554e1cd4c4c7021570d19da546fd746818c9333c3f7e953dbce4f9b3185    94149 main/installer-arm64/current/images/SHA256SUMS
 bb9874987b9c7103615b0387835fc901147f379b985c8446e6e5afe96e9212ec    20678 main/installer-armel/20210731+deb11u5/images/MD5SUMS
 b60cd2243321187f2758454a12c90f30ba33907ac05e935901553daedd90d035    28882 main/installer-armel/20210731+deb11u5/images/SHA256SUMS
 ee9f639b7a0304207f23c84f5396284720a6fc6c638ee7be6873944a0f224c95    20182 main/installer-armel/20210731/images/MD5SUMS
 07353d4c378ea579803ed8c1aca3fe6df2cbc89788736c7d01102a7b3ebad859    28194 main/installer-armel/20210731/images/SHA256SUMS
 bb9874987b9c7103615b0387835fc901147f379b985c8446e6e5afe96e9212ec    20678 main/installer-armel/current/images/MD5SUMS
 b60cd2243321187f2758454a12c90f30ba33907ac05e935901553daedd90d035    28882 main/installer-armel/current/images/SHA256SUMS
 812df0750d9ae0b6193918fb49e1b82f33ef37ec190da731cfae61091d20c674    64380 main/installer-armhf/20210731+deb11u5/images/MD5SUMS
 9a5c3096903a3f727345baff3413ac1c064cca1761fd1d197c0612e12788ba1b    92680 main/installer-armhf/20210731+deb11u5/images/SHA256SUMS
 8c1f810a60fc7daf099e608b763cec563f59c82203a07bbf4469a6213a8946eb    64240 main/installer-armhf/20210731/images/MD5SUMS
 67c5b636e3fc02747ca9593e6fc7e906a3ec95d4947740fec81b1e942f0643ae    92476 main/installer-armhf/20210731/images/SHA256SUMS
 812df0750d9ae0b6193918fb49e1b82f33ef37ec190da731cfae61091d20c674    64380 main/installer-armhf/current/images/MD5SUMS
 9a5c3096903a3f727345baff3413ac1c064cca1761fd1d197c0612e12788ba1b    92680 main/installer-armhf/current/images/SHA256SUMS
 fff2ffedc7d7f417d83039d3a1a507e3f78d8ec51d28f03d81a18bc2c4305ab5    56840 main/installer-i386/20210731+deb11u5/images/MD5SUMS
 85975e40daef2b86359d2c6a53fdd3356ffb530113ecc3354142c26123dd8a2d    76724 main/installer-i386/20210731+deb11u5/images/SHA256SUMS
 96e8acb8eb827ce7032587400fbe848b6f53921c661d52e1b16fd243cb8e57aa    56286 main/installer-i386/20210731/images/MD5SUMS
 bced74c95a3688a9a2a28abb8190cb7efd7e1f6372dc8989e260771752ef571b    75978 main/installer-i386/20210731/images/SHA256SUMS
 fff2ffedc7d7f417d83039d3a1a507e3f78d8ec51d28f03d81a18bc2c4305ab5    56840 main/installer-i386/current/images/MD5SUMS
 85975e40daef2b86359d2c6a53fdd3356ffb530113ecc3354142c26123dd8a2d    76724 main/installer-i386/current/images/SHA256SUMS
 665c26844aa380ea90d3a2608fcc4f3e4f8e36b2ad7005b5e7b49bc07951d753      630 main/installer-mips64el/20210731+deb11u5/images/MD5SUMS
 c804da84b2bc85c459a3c3d87dc95ebb4c7c56144dfc7cd18e6eaf18f997c6c4     1026 main/installer-mips64el/20210731+deb11u5/images/SHA256SUMS
 af3b55dea76e91f1565bd54bc1af76a6a0bb4991eef9abe281a22d9fd8d54a7b      627 main/installer-mips64el/20210731/images/MD5SUMS
 995cda8278b101eb25849d56f3ef33290fb57a940fa1c6837f19df00ceafaaff     1023 main/installer-mips64el/20210731/images/SHA256SUMS
 665c26844aa380ea90d3a2608fcc4f3e4f8e36b2ad7005b5e7b49bc07951d753      630 main/installer-mips64el/current/images/MD5SUMS
 c804da84b2bc85c459a3c3d87dc95ebb4c7c56144dfc7cd18e6eaf18f997c6c4     1026 main/installer-mips64el/current/images/SHA256SUMS
 125a7b4b00d44f6f0892a09c2b3b0e010c8d54990a3aa7d606ff06b275e370b4      630 main/installer-mipsel/20210731+deb11u5/images/MD5SUMS
 f2ff00d54ada190c0b06f2d11de1a22a6c43051bcb603cbae04f21480a9fe95c     1026 main/installer-mipsel/20210731+deb11u5/images/SHA256SUMS
 ca77bbc823d1bf6999e141cd42c1bb4c18179cbe4a3fbb6da3e40e1055848ed7      627 main/installer-mipsel/20210731/images/MD5SUMS
 28589449e1b3ac9a73bdf6f266edc83e70ebbbca587a228b15b0dbe5e1a634fa     1023 main/installer-mipsel/20210731/images/SHA256SUMS
 125a7b4b00d44f6f0892a09c2b3b0e010c8d54990a3aa7d606ff06b275e370b4      630 main/installer-mipsel/current/images/MD5SUMS
 f2ff00d54ada190c0b06f2d11de1a22a6c43051bcb603cbae04f21480a9fe95c     1026 main/installer-mipsel/current/images/SHA256SUMS
 fc2c26b8764b9852c778d5880e25be9e5b8216fbdd6c4c656fd98a8c28e944f6      576 main/installer-ppc64el/20210731+deb11u5/images/MD5SUMS
 9f1eed5ba44fc477e221923634a303d44ecebe021599a7371e469f8508d94629      972 main/installer-ppc64el/20210731+deb11u5/images/SHA256SUMS
 d162b2da6777c1ea0643921cc1a3dde78ae48cf022711eb98c7e9dd030b89a44      576 main/installer-ppc64el/20210731/images/MD5SUMS
 73e281bce56df3c7512ffa1a1cb13886064759a461621db4acf9b1f71965c676      972 main/installer-ppc64el/20210731/images/SHA256SUMS
 fc2c26b8764b9852c778d5880e25be9e5b8216fbdd6c4c656fd98a8c28e944f6      576 main/installer-ppc64el/current/images/MD5SUMS
 9f1eed5ba44fc477e221923634a303d44ecebe021599a7371e469f8508d94629      972 main/installer-ppc64el/current/images/SHA256SUMS
 69f27f41508820a7d60db99bb671c9a69094706a28ad9de4e5d25c65991df3b7      374 main/installer-s390x/20210731+deb11u5/images/MD5SUMS
 06fe957b4a4ce9b07e1047742a31806524361da928919548352dd5019cd2abf4      674 main/installer-s390x/20210731+deb11u5/images/SHA256SUMS
 b2c58a9c5b97a59742a8056e3e9d7f4f22d4d11e51c71d7a0051dc4649a717b9      374 main/installer-s390x/20210731/images/MD5SUMS
 61447263ea7318c444fde199afc718a8498fe67bc0e7116f2e1103cc65ef672b      674 main/installer-s390x/20210731/images/SHA256SUMS
 69f27f41508820a7d60db99bb671c9a69094706a28ad9de4e5d25c65991df3b7      374 main/installer-s390x/current/images/MD5SUMS
 06fe957b4a4ce9b07e1047742a31806524361da928919548352dd5019cd2abf4      674 main/installer-s390x/current/images/SHA256SUMS
 e5a4c1118315a2bb64d905a37e2961e8c845ff3677c279a7e4a5ad824b107d1a      117 main/source/Release
 e7777c1d305f5e0a31bcf2fe26e955436986edb5c211c03a362c7d557c899349 44649916 main/source/Sources
 67d7c26094018dd49c2f80c58caab28ee1e237658050446f8efea32c6eb54f12 11427358 main/source/Sources.gz
 cee538c97e5322deb00180cb19736bdf0ed00309ceb81e1fff9ce93a3211301b  8633080 main/source/Sources.xz
 29cac69ab0fd86e224587eea8e2ed2fb9b1b2e3c936fb1dc7165b8ed8d00528a 17347341 non-free/Contents-all
 3b87590d0360ae141f3688fbafb5fdad35d4dd4b1a239888c911743c4357862d   888157 non-free/Contents-all.gz
 ee03554c6291e744b83424f63568f382d153a0fb9c3c4ce9b1c0fe2ab0df62f5  1096728 non-free/Contents-amd64
 f61c41825029bc53e09570960e868d1f8c6ee94484d261f66effa5b5b24c72f8    79664 non-free/Contents-amd64.gz
 6b4d01f9f6e36ca5e6622649732d632e1093a2f93ceccc9b711fbee9276dce16   499361 non-free/Contents-arm64
 0a17ac777170de56383a626ac898e6328f23937c38a4c9d4a97dabcc0ae31bf3    37247 non-free/Contents-arm64.gz
 386c53a056d4aedb9d48a332056c51a302e1b043480cc24fc9ea9053ff8fe002    95417 non-free/Contents-armel
 5fc23867def6ff06cf0c72080f1862ea142b20d25ca0a1e8e8b9c83ca3b82519     9298 non-free/Contents-armel.gz
 c5589cbd94ab3a420a0a6839a927d56b205cf36c32ee1e815402168007bb9ef2   146013 non-free/Contents-armhf
 d37c264808fdc8af02306a987370ea64d92c16dd6709be9b72881267b64f5006    13367 non-free/Contents-armhf.gz
 b21610c343a716a22550490e77b3e3977d5ba99c4334310134b63794b5cedbe6   343087 non-free/Contents-i386
 7fe15174440b6b335625f20b5d5cc5a2d4b34cb44ac3fabae5da9b7fd90c0bf8    29107 non-free/Contents-i386.gz
 6bdcba453cc1369f93e7157d5d7f9c67198edc62e4e194b079b0572186a95b34    91215 non-free/Contents-mips64el
 0986d6fc85dcf209edbf39b1ee2c84b370ea02dfe810ac33cd9cc89a2f3a2a18     8686 non-free/Contents-mips64el.gz
 5102cb8d1b74daa60d4d6444e563dbdaf73ffaa2b7ce71a304987ff575da7f4e    92244 non-free/Contents-mipsel
 53bd140b538ffea9c0bd8b6b073b3ef613ec1d452bb1bad5a5f86a029f11e3dc     9026 non-free/Contents-mipsel.gz
 311afe59cb46fc9d0ed37e43a603ed0714b7a87084d68ee8e6142561af4724c7   715688 non-free/Contents-ppc64el
 6756bcb8fbad614ef1a58b2d0bf54ccf2da7dee7d0c233394dd4f658a6758ae9    49907 non-free/Contents-ppc64el.gz
 6d2b11e017bf520a64870b3ceecfac7944f991928095bd2715429987a342c37e    74537 non-free/Contents-s390x
 228df45a42a42dd62cc747f2abe99dccd25c384aa423c17896a6196955cd9c12     7407 non-free/Contents-s390x.gz
 ec96d44d92194448cd0c5293313c8c78a9449db50c282c77b607a7dbb6a370f1 10803360 non-free/Contents-source
 e739a21791ccd8528b47f9ef464289b6d56c0cc837d3b9438e249820848d0804  1063351 non-free/Contents-source.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-all
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-all.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-amd64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-amd64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-arm64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-arm64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-armel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-armel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-armhf
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-armhf.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-i386
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-i386.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-mips64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-mips64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-mipsel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-mipsel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-ppc64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-ppc64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-s390x
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-s390x.gz
 68ddf090986f56743010180da8d3e05a41bd5185e0047a98c97adb038cc5fc4b   189021 non-free/binary-all/Packages
 569cc71a40dffea02aa6cf8b516370e08587ec71d34558cf6f1fe688c9629468    50928 non-free/binary-all/Packages.gz
 b9d8d7fb507a77a6222770fbe09815bc0cae22af92d0c16538d53b4576af6784    42996 non-free/binary-all/Packages.xz
 75fb1817e26f38feb699febfd3d87fece789136da8d266665becfa8767378588      118 non-free/binary-all/Release
 f8ff083ffdd53498fac1cfddcc476ba2117084d18b5a610eea5b9a483f71ac93   546840 non-free/binary-amd64/Packages
 731864fba5c479272a939bbb5283ee866179dd6a10c9ef6f81dbb7666e93c4a5   122055 non-free/binary-amd64/Packages.gz
 419bc05dfb873fa1549786dba70ab8f0192d1b73e6ab72341ed03a7b67e4da5e    97740 non-free/binary-amd64/Packages.xz
 15725f9451c3fbb64fcafeb3383dcaed752eaa6131419795d10cfeb30e28c84d      120 non-free/binary-amd64/Release
 e3583c33f4b708c58f764c7d96483b2eec6b08d4e377e67083c2a1e55308a159   382463 non-free/binary-arm64/Packages
 21c67356805decb544e2a75b25ab71906770b59a906fa7a2f9b79600c0b5717a    88539 non-free/binary-arm64/Packages.gz
 7f75a67d217e8e304a60d531aac1b7d93bc7495c513d0efcb8bc67742a8d2382    72928 non-free/binary-arm64/Packages.xz
 fc4f15c634b8865d9dd65665be52eeb11953cf98dd2764d5d5a397b922e04f3a      120 non-free/binary-arm64/Release
 f5738f5a5d9f4391ba0719b7bb175892d93561b688137917a4cdc75537ca70e5   227933 non-free/binary-armel/Packages
 89cb801437910d9b6076d9caf85f2144b224cb1eff7dfbd014219242df514b82    61822 non-free/binary-armel/Packages.gz
 bf2bfec078bdf2dcd2d0d411109257f3ec2d652087399062023d2fcce2e43710    51800 non-free/binary-armel/Packages.xz
 174d3c3b0b4de0f38da578ed1ce9916bc76f347033527a62f8169f4d886ce6fe      120 non-free/binary-armel/Release
 acd1d0ef3bc7b58fb6dee3681b3f1c584b883f2ce8049cf95124a1352c3bbf17   259172 non-free/binary-armhf/Packages
 87ec3a0fa80d86a10bdf122dc7104624d6d2a7003f661ef10d03bc1180a63df4    67212 non-free/binary-armhf/Packages.gz
 c3088c7c7fe8c5b32d17a7e9dbb85aba881197b4499e552f8a83fad501e05870    56280 non-free/binary-armhf/Packages.xz
 b5e9e86c7e67e8191f2dd188035e96f4ebf270d58854d4156940e533aac5c8f0      120 non-free/binary-armhf/Release
 88dd789ee03ff3a4eeb74ee8a96040cce9caa4a899fbbaab561b2570a7791651   423212 non-free/binary-i386/Packages
 8fa6cb80a3d3f2cf83f3b36c65a3983cd39bc2dbcac1916ab8d75eb3e625e2d8    96326 non-free/binary-i386/Packages.gz
 9dd0ff519ec74a1ae6ebadbbfbd802e7728f66d2d32e95c95b011eaf5a4261b5    79316 non-free/binary-i386/Packages.xz
 5f95ccf806fb1865e9913ac6f5f347c6b76fa97a5ddfd363f2c28222f0059763      119 non-free/binary-i386/Release
 f7e9a5d9f19cc5b819efa1aac30c9d833ed9e41dfdce9abf2bc48d0467abae1a   225506 non-free/binary-mips64el/Packages
 2d01bd458989434fd6555cdc4d4f9dc554881de09ced2db213fc26395f4108c8    61024 non-free/binary-mips64el/Packages.gz
 ed53056d18b6b8589fbbebffd26f8fbda708f71870e1bbffd4a4cfc7249283b2    51124 non-free/binary-mips64el/Packages.xz
 82308e5e9b928a8313865096947327314baa31750b5ae1774913d6e7ee765d25      123 non-free/binary-mips64el/Release
 c690e75e4633fad47565d5afcef96622ec6e02b2fa824e5c0508f1119044c906   226162 non-free/binary-mipsel/Packages
 fd05e8f63760b2163ba4b40cdf200a9b113edfbf81d5a2a318a2b5605812891d    61277 non-free/binary-mipsel/Packages.gz
 87cb9361adbac3f2604906109b21c6b685fda9caf3525395dd4ee057d7c4e43d    51364 non-free/binary-mipsel/Packages.xz
 76bd6cf779b331b76f8146b25900be8235cacea8eae078dee51ca40b5e6b442f      121 non-free/binary-mipsel/Release
 a4737be6aad3f848da807a77a2f0f3b1998676eb4f425de13482b23918dc30df   381757 non-free/binary-ppc64el/Packages
 4adb20da8fd5489677e11526f07c4e1e3405bcdf6239a6ade0d3df8b085dd4bd    86688 non-free/binary-ppc64el/Packages.gz
 142e04915c269c684dafe3b731c5a83a566bf4243053f442c72ca02ad4e3367f    71824 non-free/binary-ppc64el/Packages.xz
 2442287f45d8fe7d62cf887cce2096a3ee07286cb875ee001bee18670925b78e      122 non-free/binary-ppc64el/Release
 79ebd2f1278b5db689359d517f88af2ae9acd8d493bf791e5cb5f73b9c81479d   220570 non-free/binary-s390x/Packages
 f7240f44940160f2d9b7cb553f6f47713186ebba6646c18a093e61bc4088e720    59856 non-free/binary-s390x/Packages.gz
 4a1d593c1cd1adb67b9ab6bd5c2558536c284486eb714f89b9ce09229bbb1eef    50216 non-free/binary-s390x/Packages.xz
 b700666667e53e31cdde70c8b8911a1120bbac58867ca63df80dcedec0b6fe8a      120 non-free/binary-s390x/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-all/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-all/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-all/Packages.xz
 75fb1817e26f38feb699febfd3d87fece789136da8d266665becfa8767378588      118 non-free/debian-installer/binary-all/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-amd64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-amd64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-amd64/Packages.xz
 15725f9451c3fbb64fcafeb3383dcaed752eaa6131419795d10cfeb30e28c84d      120 non-free/debian-installer/binary-amd64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-arm64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-arm64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-arm64/Packages.xz
 fc4f15c634b8865d9dd65665be52eeb11953cf98dd2764d5d5a397b922e04f3a      120 non-free/debian-installer/binary-arm64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-armel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-armel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-armel/Packages.xz
 174d3c3b0b4de0f38da578ed1ce9916bc76f347033527a62f8169f4d886ce6fe      120 non-free/debian-installer/binary-armel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-armhf/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-armhf/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-armhf/Packages.xz
 b5e9e86c7e67e8191f2dd188035e96f4ebf270d58854d4156940e533aac5c8f0      120 non-free/debian-installer/binary-armhf/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-i386/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-i386/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-i386/Packages.xz
 5f95ccf806fb1865e9913ac6f5f347c6b76fa97a5ddfd363f2c28222f0059763      119 non-free/debian-installer/binary-i386/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-mips64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-mips64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-mips64el/Packages.xz
 82308e5e9b928a8313865096947327314baa31750b5ae1774913d6e7ee765d25      123 non-free/debian-installer/binary-mips64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-mipsel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-mipsel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-mipsel/Packages.xz
 76bd6cf779b331b76f8146b25900be8235cacea8eae078dee51ca40b5e6b442f      121 non-free/debian-installer/binary-mipsel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-ppc64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-ppc64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-ppc64el/Packages.xz
 2442287f45d8fe7d62cf887cce2096a3ee07286cb875ee001bee18670925b78e      122 non-free/debian-installer/binary-ppc64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-s390x/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-s390x/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-s390x/Packages.xz
 b700666667e53e31cdde70c8b8911a1120bbac58867ca63df80dcedec0b6fe8a      120 non-free/debian-installer/binary-s390x/Release
 e13d055f233a81a77666f0ff8dd9d748917b2829740756e1dc2b8a350309bcb0   278293 non-free/dep11/Components-amd64.yml
 f51b1a07cd72a36b2a9f36742ab26819a7808aa7765cbf3e2ff4abe6be66b50c    29634 non-free/dep11/Components-amd64.yml.gz
 e113163e116c137577fc9d3a4f7c95e0934ddbae7bdae5e083aaa1ce095435b6    17904 non-free/dep11/Components-amd64.yml.xz
 6177cb908c067306c11bd8728a5b65a205d999be63930c079e3ff4250a24ce8e   271451 non-free/dep11/Components-arm64.yml
 1b6107a1fa771a8fff50e0b182362fd679dc01f58f7a1f3fe9fe0183daf3be0d    27686 non-free/dep11/Components-arm64.yml.gz
 7ff5eda9a37e07b9bcfa479c89863d7b2b1aafbedbe4b37ea6c32a16f2eaa241    16392 non-free/dep11/Components-arm64.yml.xz
 f54eccd2dbf23fa45cab9e9e7abfafeb667397ea70b6197a3653e8499ffea8bf   271451 non-free/dep11/Components-armel.yml
 5581d7f4c159a5cbd33927294f7fc9918e7deaf04b313001965c83412b6a81f7    27606 non-free/dep11/Components-armel.yml.gz
 0830d150400c82255a52a74f6af9f1a11007bf4b92fc814513f9e13cfac0b22c    16448 non-free/dep11/Components-armel.yml.xz
 15d1524c660c8fb1ee911775a9b59cebbc66843eb97cc0a15a361009f153e6ff   271451 non-free/dep11/Components-armhf.yml
 3fa04d7715c8955987742dc376d10327a975f9583cf656da055d13895e460a67    27691 non-free/dep11/Components-armhf.yml.gz
 bbf5a05de96a53c0e10af6019cb7b053b83b0f5def488cde4d8359475adb08da    16364 non-free/dep11/Components-armhf.yml.xz
 716cec6e00d8303375812c8c9be7cbfa5fc858fdb3d9af3f0c72a696d8f7cb2d   280613 non-free/dep11/Components-i386.yml
 40f189b3b3a74bc85652829d0c67b21aad7e60ce389f26fe1959db1e1e8ec48c    31098 non-free/dep11/Components-i386.yml.gz
 18507e0a03c74ed39b9bec853eb9216b458f2fe2b7535c2622c126b9cd35301e    19156 non-free/dep11/Components-i386.yml.xz
 d82d6fadb06b6a1f0d36c155b70a02eb2281838aee3ce1b9bf51b7ae06136721   271451 non-free/dep11/Components-mips64el.yml
 25d788e157070218396bafba65ff087551830ba0d0ba3e3cec5342bb150aec57    27765 non-free/dep11/Components-mips64el.yml.gz
 2d0aa3979fd6093dc6de8ba902166a985235c8c4926e07cab7aa2a9b4ad0c11d    16380 non-free/dep11/Components-mips64el.yml.xz
 c55445f6f87fd566212bb018f9fae1a4eb43c1a66fe1b0e198b1c7d7e500b009   271451 non-free/dep11/Components-ppc64el.yml
 f525af23f1a1eb26ee786c36e2afd4aa5e4102b646f33f8c6788aee395b752bf    27592 non-free/dep11/Components-ppc64el.yml.gz
 0ee03164cca5098ec7c6f98a469818b40b61da7846451cc223d0b9e01585c57c    16576 non-free/dep11/Components-ppc64el.yml.xz
 359af9af71c00d90265395225b75313966435729cf1f6cfb1085fe1721b01e72   271451 non-free/dep11/Components-s390x.yml
 47ef508dff3dfdf17ceeed229d98a2e3992c1a26f28eb328a2d1958d2ddfe070    27558 non-free/dep11/Components-s390x.yml.gz
 181db8b5130910114256e8809ff9a1637efac55b1f33d1f516983521b8d51e7b    16356 non-free/dep11/Components-s390x.yml.xz
 601045de5331d63b7ef2a24f8f74a7452d7be785f94ae6c46002c5dc2608188f     8192 non-free/dep11/icons-128x128.tar
 4fb59feb5d5afe99980ea36c3d7c14577a4b5f11705e7d16524767708666ed54     2394 non-free/dep11/icons-128x128.tar.gz
 977a5470a45ec30f5e230361a446f4692f9cf9bc2abccf6eabac2df0291f1ee4     4096 non-free/dep11/icons-48x48.tar
 07a401f7b03554c2d8ab32dea5885c43b7da7badeea0569b9ce5c9dbbb7cf66f      741 non-free/dep11/icons-48x48.tar.gz
 159551b3012db94a70261cb8f88619a6bb148318da051479ade6df7211c41a34    36864 non-free/dep11/icons-64x64.tar
 872b7437de6fb938db8b26d9de9a3113bc722cd6ed682973151722e2b7a190be    27667 non-free/dep11/icons-64x64.tar.gz
 ca932555b435575810b460e3916cf1dcf04a2e1a4dec8bf9ebd574a52880bb2b   573037 non-free/i18n/Translation-en
 0fdbf1dda4c3119a14c5b75018d9acf31baca5082d3369669f00a54de4dfcbec    92432 non-free/i18n/Translation-en.bz2
 c37efceb196d566b10f0129a1d61963b9f3f3e477cda9dc8c9715fa228ff9019      121 non-free/source/Release
 3b27f29c4f8fec0a025dd6bad255858cdf81b0bc0171d4ad8c0ef982de4cb40e   359801 non-free/source/Sources
 7c55b5a60b7395f729aea6387b171c546d2e7078dcc84dd66ff7b94711c27dd9    98071 non-free/source/Sources.gz
 dbd1c0ed9ca888d3769d3d14f1e9226133de936e2dde7e848e01f0c689bbaa32    81220 non-free/source/Sources.xz
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEAUbcbUoLKRS97TTbZIrP1iLz0TgFAmMcZIIACgkQZIrP1iLz
0TgtEg/+JInlcuZ/f7hvL5kvBXKVp/kUnSbeSGrjlUe9IA+HABu/TkbVRu/IKVDg
LeYKiiGhEtqf33z8TNLm7pPVn5+LN/ZATXyNr07Pacic/j+Q0dtx9ok9RRKftQb4
Ti/OF8f/duhz/OPVWuqXclEq5VZdJibCKmo2ea98zmhO0mp0BijzGyFQW+FvdZLt
zF9zUwHTPcA/Q0+xS9nabrU/tClQgGq8+rvUoUc4/CjSLO1uTNtrEfYhEGrMzd8s
77aQmADfj5/RXc3TpJhQGhpNi+HwWLnT8V7qs/cV8nVc88GPr5hox1mLGUAyEnzr
37aynFvX7eAx36Elazx1SOJgDt9NZMlVWCn9PAwXMy99R/3BdK+3lAOAAyYBwk1P
hgsws5BWswAbsSVOsbhizDmXrjXtRgOXERYMc/n4aiU5fKUwyafAXe+KZFH5jzSI
tepGMcq3yTja1jHEqlZGCuEeiYaaoqUnZcEhs7rzngYHO3hmLEJCKNhydaSdGeaJ
wbykAd4LhVcugcdmGL+ynDkpvA2diyD1kt7o72rr6g6s7wxilVcN+3GTvatIf5x3
yMw0Ibdv8JseO7ZBHXnUet5uKm6S5ssWDUi/eEcvMDLM6441OTze86CbZ9nmcIe1
x6K4nZSlsnQ8TBYE2LTO8IVcYl/1aYz31OvsKRB4CZtxr6i8xu2JAjMEAQEIAB0W
IQSnI2iG88zKrRSKJ/gOmEBNOG+h2QUCYxxkgwAKCRAOmEBNOG+h2QZkEAC2UeQQ
nh7bTd69XqGfULgoTOYwwGAEMKLBVeekDDvpOVKVM5Pdxnahgtv2hmlRPzc89dg1
f1NvoiISYgnFCpgSr9416rBqnuKfSzQug2Ak5Xa7HW2AOULgT99DRwCOUIU2NmHd
54paf1mIWqe7EtC5Nq8TZIbpbyuZSrutOotmCML9d1C1rtvLRiVqa9aEOY4q+6/5
LxetgTGspamOkPPpzM0u9gWVyQKNkhLIHax6equKRzRf183QVNHd/P0VF1hPKJfb
4zbbLa0YQcmmqvP+5pjqs6Yl6i+WAE0D33OVlWt1baguQgkpKvXPkFBzHMBdo7jQ
TC3zaII0tLes+UGinEChbkioWGwlz8F6qZeKpVlPuis1tHXGFBlemnwT+BpjGq3K
AV09lvDRtq1t82YOuLwvWTGzdWDEa0upVjNNE+rkA36JIwOXNHXdIZVw8opSj8Yx
SF4/CjeJ3N5W9BfQJOCuZTWZLf/cFoArdpjPqNzREVb3WHbj3yScXVdPV4D87xkn
8nMq/17EhZYjr5n8eu8i9NHvhiqLI+XqB55l7ThxE3MZApbUdZIp6+M3UtlS7xHj
NPO1cR+JKqknNIahXU5WV5d6mlv5XAgFcHMy2R7KThCnKhvI2kwhFaC5jEY2lOjD
q1yPyFvupHNYV6t0EGPH1k+w/Ay/qjq+ZrMJn4kCVAQBAQgAPhYhBKQoUpX8exqB
YABiqWBcZvANbJeTBQJjHGWbIBxkZWJpYW4tcmVsZWFzZUBsaXN0cy5kZWJpYW4u
b3JnAAoJEGBcZvANbJeTHz8QALBLk9Z97awbwt98DfCji9yibWODB9LVQ0b2KhJH
KnD+2hk0LpCTqXgXWyGjc71PLDjM11P+bFO+9VryqyntigzD/kFt3UopWiAgcNwm
lr7cB2PBcrAY8Jo9PVwuoDKot/Nmhgqt86btD40TrE5nHqxOfaWLDRTLfmi49NEE
RhMsSxMj5m38Ap0RznzWnBeSoLC7o05niZPN8MXA6m1HYeZaOJvbHOvgHgkcZCNl
cfn3XXbaPVypvfL7GRHg7Dj/286bXmIPFzsq0BpoUE4z+AkAKmEnI9i9wnkfIffU
/rn+4/EPTuSnrSvetN8c9CxEf3yAG+oTvk7CKvARR2uj17dR8TPEF3mEU6gXJBZk
UxpTpln1f1DcSXGxbPjFWZlT8izlS0YfclJ95SCbNSCKpZvfseLu6qcEweN5d64Q
KV+7NixNdZqJddrWTT4G4ownst7N/k4mC0+7cX9xIq3R3fydJUJ2ALumw4i4jLL/
1TZhUeat+3fz2re8FzESz9jjfobf6YMNBRGv/fJOg0L5Y8d2Uc+dyJF0Ey7e0oz+
uIPwHL5O7xX7LGOb5k5PirqLSn4gE5/s4nCQ6X98HYdjKvF4S8CBWrUIIJq0MN8g
zhTMHGCfZ/YjTWxa1Op4fFge92BHtFSfaPWpNp4NRiDGbSu4R6k/UHJkMIFBglbm
91Hp
=xVkG
-----END PGP SIGNATURE-----

";
        let release = Release::parse(data)?;

        let mut expected = Release::default();
        expected.fields.insert("Origin".into(), "Debian".into());
        expected.fields.insert("Label".into(), "Debian".into());
        expected.fields.insert("Suite".into(), "stable".into());
        expected.fields.insert("Version".into(), "11.5".into());
        expected.fields.insert("Codename".into(), "bullseye".into());
        expected.fields.insert(
            "Changelogs".into(),
            "https://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog".into(),
        );
        expected
            .fields
            .insert("Date".into(), "Sat, 10 Sep 2022 10:18:01 UTC".into());
        expected
            .fields
            .insert("Acquire-By-Hash".into(), "yes".into());
        expected
            .fields
            .insert("No-Support-for-Architecture-all".into(), "Packages".into());
        expected.fields.insert(
            "Architectures".into(),
            "all amd64 arm64 armel armhf i386 mips64el mipsel ppc64el s390x".into(),
        );
        expected
            .fields
            .insert("Components".into(), "main contrib non-free".into());
        expected.fields.insert(
            "Description".into(),
            "Debian 11.5 Released 10 September 2022".into(),
        );

        let mut release2 = release.clone();
        assert_eq!(release2.checksums.remove("MD5Sum").unwrap().len(), 600);
        assert_eq!(release2.checksums.remove("SHA256").unwrap().len(), 600);
        assert_eq!(release2, expected);

        let data = str::from_utf8(data)?;
        let idx1 = data
            .find("\n\n")
            .context("Failed to find end of pgp prefix")?;
        let idx2 = data
            .find("-----BEGIN PGP SIGNATURE-----\n")
            .context("Failed to find start of pgp suffix")?;
        assert_eq!(release.to_string(), &data[idx1 + 2..idx2]);

        Ok(())
    }

    #[test]
    fn test_parse_checksum_entry() -> Result<()> {
        let data = "10539c0645350845373a0e99a4940140  8183676 main/binary-amd64/Packages.xz";
        let entry = ChecksumEntry::parse("MD5Sum".to_string(), data)?;
        assert_eq!(
            entry,
            ChecksumEntry {
                namespace: "MD5Sum".to_string(),
                hash: "10539c0645350845373a0e99a4940140".to_string(),
                size: 8183676,
                size_width: 8,
                path: "main/binary-amd64/Packages.xz".to_string(),
            }
        );
        assert_eq!(entry.to_string(), data);
        Ok(())
    }

    #[test]
    fn test_parse_long_checksum_entry() -> Result<()> {
        let data = "463b35fbc23c26c5ac2099862328ea4c 687820704 main/Contents-source";
        let entry = ChecksumEntry::parse("MD5Sum".to_string(), data)?;
        assert_eq!(
            entry,
            ChecksumEntry {
                namespace: "MD5Sum".to_string(),
                hash: "463b35fbc23c26c5ac2099862328ea4c".to_string(),
                size: 687820704,
                size_width: 9,
                path: "main/Contents-source".to_string(),
            }
        );
        assert_eq!(entry.to_string(), data);
        Ok(())
    }
}
