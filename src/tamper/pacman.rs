use crate::compression;
use crate::errors::*;
use crate::plot::{self, PkgRef, PlotExtras};
use indexmap::IndexMap;
use std::io;
use std::io::prelude::*;
use tar::{Archive, EntryType};
use warp::hyper::body::Bytes;

type PatchPkgDatabaseConfig = plot::PatchPkgDatabaseConfig<Vec<String>>;

pub struct ArchiveFolder {
    header: tar::Header,
}

impl ArchiveFolder {
    pub fn update_from_pkg(&mut self, pkg: &Pkg) -> Result<()> {
        let name = pkg.name();
        let version = pkg.version();
        self.header.set_path(format!("{}-{}/", name, version))?;
        self.header.set_cksum();
        Ok(())
    }
}

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

impl Pkg {
    fn from_map<'a>(map: &'a IndexMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
        map.get(key)?.first().map(String::as_str)
    }

    pub fn parse(s: &[u8]) -> Result<Pkg> {
        let mut key = None;
        let mut values = Vec::new();
        let mut map = IndexMap::new();

        for line in s.split(|c| *c == b'\n') {
            if line.is_empty() {
                if let Some(key) = key.take() {
                    let mut x = Vec::new();
                    std::mem::swap(&mut values, &mut x);
                    map.insert(key, x);
                }
            } else if key.is_none() {
                key = Some(String::from_utf8(line.to_vec())?);
                values = Vec::new();
            } else {
                values.push(String::from_utf8(line.to_vec())?);
            }
        }

        let name = Self::from_map(&map, "%NAME%")
            .context("Missing package name")?
            .to_string();
        let version = Self::from_map(&map, "%VERSION%")
            .context("Missing package version")?
            .to_string();

        Ok(Pkg { name, version, map })
    }

    pub fn delete_key(&mut self, key: &str) -> Result<()> {
        if key == "%NAME%" {
            bail!("Can't delete %NAME% from pacman package");
        }
        if key == "%VERSION%" {
            bail!("Can't delete %VERSION% from pacman package");
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

        if key == "%NAME%" {
            debug!("Updating name to: {:?}", first);
            self.name = first.to_string();
        }
        if key == "%VERSION%" {
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

impl ToString for Pkg {
    fn to_string(&self) -> String {
        let mut out = String::new();
        for (key, values) in &self.map {
            out += key;
            out.push('\n');
            for value in values {
                out += value;
                out.push('\n');
            }
            out.push('\n');
        }
        out
    }
}

pub fn patch<W: Write>(
    config: &PatchPkgDatabaseConfig,
    plot_extras: &PlotExtras,
    bytes: &[u8],
    out: &mut W,
) -> Result<()> {
    let comp = compression::detect_compression(bytes);

    let mut out = compression::stream_compress(out, comp)?;
    let tar = compression::stream_decompress(bytes, comp)?;
    let mut archive = Archive::new(tar);

    let mut builder = tar::Builder::new(&mut out);
    let mut dir_header = Option::<ArchiveFolder>::None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        trace!("tar entry: {:?}", entry.header());
        match entry.header().entry_type() {
            EntryType::Regular => {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                let mut header = entry.header().to_owned();

                let mut pkg = Pkg::parse(&buf)?;
                trace!("Found pkg: {:?}", pkg);

                if config.is_excluded(&pkg) {
                    debug!("Filtering package: {:?}", pkg.name());
                    continue;
                }

                if let Some(artifact) = config.artifact(&pkg) {
                    let artifact = plot_extras.artifacts.get(artifact).with_context(|| {
                        anyhow!("Referencing undefined artifact: {:?}", artifact)
                    })?;

                    pkg.set_key("%CSIZE%".to_string(), vec![artifact.len().to_string()])
                        .context("Failed to patch package")?;

                    pkg.set_key("%MD5SUM%".to_string(), vec![artifact.md5.clone()])
                        .context("Failed to patch package")?;

                    pkg.set_key("%SHA256SUM%".to_string(), vec![artifact.sha256.clone()])
                        .context("Failed to patch package")?;
                }

                if let Some(signature) = config.signature(&pkg) {
                    let signature = plot_extras.artifacts.get(signature).with_context(|| {
                        anyhow!("Referencing undefined artifact: {:?}", signature)
                    })?;
                    let encoded = base64::encode(signature);
                    pkg.set_key("%PGPSIG%".to_string(), vec![encoded])
                        .context("Failed to patch package")?;
                }

                if let Some(patch) = config.get_patches(&pkg) {
                    debug!("Patching package {:?} with {:?}", pkg.name(), patch);
                    for (key, value) in patch {
                        pkg.set_key(key.to_string(), value.clone())
                            .context("Failed to patch package")?;
                    }

                    // regenerate pkg metdata
                    buf = pkg.to_string().into_bytes();

                    // regenerate db entry
                    let name = pkg.name();
                    let version = pkg.version();

                    header.set_path(format!("{}-{}/desc", name, version))?;
                    header.set_size(buf.len() as u64);
                    header.set_cksum();

                    if let Some(folder) = dir_header.as_mut() {
                        folder
                            .update_from_pkg(&pkg)
                            .context("Failed to patch folder in pacman db")?;
                    }
                }

                if let Some(folder) = dir_header.take() {
                    builder.append(&folder.header, &mut io::empty())?;
                }

                builder.append(&header, &mut &buf[..])?;
            }
            EntryType::Directory => {
                dir_header = Some(ArchiveFolder {
                    header: entry.header().to_owned(),
                });
            }
            _ => (),
        }
    }

    builder.into_inner()?;
    out.finish()?;

    Ok(())
}

pub fn modify_response(
    config: &PatchPkgDatabaseConfig,
    plot_extras: &PlotExtras,
    bytes: &[u8],
) -> Result<Bytes> {
    let mut out = Vec::new();
    patch(config, plot_extras, bytes, &mut out)?;
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_parse_pkg() -> Result<()> {
        let desc = b"%FILENAME%\nzstd-1.5.2-7-x86_64.pkg.tar.zst\n\n%NAME%\nzstd\n\n%BASE%\nzstd\n\n%VERSION%\n1.5.2-7\n\n%DESC%\nZstandard - Fast real-time compression algorithm\n\n%CSIZE%\n403882\n\n%ISIZE%\n1238511\n\n%MD5SUM%\ne704f66752b15459e3bf65de8b03701c\n\n%SHA256SUM%\n4fa198f85e1a0675c56fdd0f31ea145337959a2bbdc17f5b93f69f91cd337703\n\n%PGPSIG%\niQIzBAABCgAdFiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmKrdpMACgkQ/BtUfI2BcsgNjw/7BBGvjr2Oq1QQvlCqwGZYmt3U6LcFoghpE8W0goy8zN2qoqenVsGG0EN8R/ryvSzn83XKfjJImoT0k/YupzCXXj+LIPr/nub6WRdGE7H9rRC5C69jTOD1jcWbE8DCsnotSaYgX0TiRMModfuLA3t8pPB2eZjXjQ/ifleVDcZnV4yGKh2rlAxDqjaQKffcTNTl2sZOeuKX44SDNzUj7zOkT/QORP+HPl0Nn+4ujriHxGxou7oTMXBxEhTlnkOqF7to9QmGxRNBWUzZbl6R37apV1pIh6Oc5g4ci20e8y4xl5g8oekd+W/ewZUqHj9gpYuttZSE2ztTn/PrX7VL8w0rkFqs5L98upF+N3q6n0l+lyvoV2EpvbY14v7R1L6JerrObUpF3ZaniaoTQN6QL1dEC60xbXHofXWMeqAU3rqeAuAo5vmulSOMc6s6ia0feybtwEnmyghLn0tkwW39SlNDfui+rZ6Wnx+Hrfl6B5PL45HI33cCB580T7nSD1MmjO1ueO5iwFiEVI/TNs8Lb+7xFsnuhYKKhtlGgPNticXCauFBs+zbhG+pGjMWFqzR4CXLDZP/R8dVrOBIjmY5a8KfKLgABVfcopvxHpt9LBlVvPUW6xnLdktF5GVsZRiheLeUihypsi7pa+F3Wd09wtrOoboMYQFa7pYyStpmC+Nz4tM=\n\n%URL%\nhttps://facebook.github.io/zstd/\n\n%LICENSE%\nBSD\nGPL2\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n1655402860\n\n%PACKAGER%\nLevente Polyak <anthraxx@archlinux.org>\n\n%PROVIDES%\nlibzstd.so=1-64\n\n%DEPENDS%\nglibc\ngcc-libs\nzlib\nxz\nlz4\n\n%MAKEDEPENDS%\ncmake\ngtest\nninja\n\n";
        let pkg = Pkg::parse(desc)?;

        let mut expected = Pkg::default();
        expected.add_values("%FILENAME%", &["zstd-1.5.2-7-x86_64.pkg.tar.zst"])?;
        expected.add_values("%NAME%", &["zstd"])?;
        expected.add_values("%BASE%", &["zstd"])?;
        expected.add_values("%VERSION%", &["1.5.2-7"])?;
        expected.add_values(
            "%DESC%",
            &["Zstandard - Fast real-time compression algorithm"],
        )?;
        expected.add_values("%CSIZE%", &["403882"])?;
        expected.add_values("%ISIZE%", &["1238511"])?;
        expected.add_values("%MD5SUM%", &["e704f66752b15459e3bf65de8b03701c"])?;
        expected.add_values(
            "%SHA256SUM%",
            &["4fa198f85e1a0675c56fdd0f31ea145337959a2bbdc17f5b93f69f91cd337703"],
        )?;
        expected.add_values("%PGPSIG%", &["iQIzBAABCgAdFiEE4kC1fixGMLp2ji8m/BtUfI2BcsgFAmKrdpMACgkQ/BtUfI2BcsgNjw/7BBGvjr2Oq1QQvlCqwGZYmt3U6LcFoghpE8W0goy8zN2qoqenVsGG0EN8R/ryvSzn83XKfjJImoT0k/YupzCXXj+LIPr/nub6WRdGE7H9rRC5C69jTOD1jcWbE8DCsnotSaYgX0TiRMModfuLA3t8pPB2eZjXjQ/ifleVDcZnV4yGKh2rlAxDqjaQKffcTNTl2sZOeuKX44SDNzUj7zOkT/QORP+HPl0Nn+4ujriHxGxou7oTMXBxEhTlnkOqF7to9QmGxRNBWUzZbl6R37apV1pIh6Oc5g4ci20e8y4xl5g8oekd+W/ewZUqHj9gpYuttZSE2ztTn/PrX7VL8w0rkFqs5L98upF+N3q6n0l+lyvoV2EpvbY14v7R1L6JerrObUpF3ZaniaoTQN6QL1dEC60xbXHofXWMeqAU3rqeAuAo5vmulSOMc6s6ia0feybtwEnmyghLn0tkwW39SlNDfui+rZ6Wnx+Hrfl6B5PL45HI33cCB580T7nSD1MmjO1ueO5iwFiEVI/TNs8Lb+7xFsnuhYKKhtlGgPNticXCauFBs+zbhG+pGjMWFqzR4CXLDZP/R8dVrOBIjmY5a8KfKLgABVfcopvxHpt9LBlVvPUW6xnLdktF5GVsZRiheLeUihypsi7pa+F3Wd09wtrOoboMYQFa7pYyStpmC+Nz4tM="])?;
        expected.add_values("%URL%", &["https://facebook.github.io/zstd/"])?;
        expected.add_values("%LICENSE%", &["BSD", "GPL2"])?;
        expected.add_values("%ARCH%", &["x86_64"])?;
        expected.add_values("%BUILDDATE%", &["1655402860"])?;
        expected.add_values("%PACKAGER%", &["Levente Polyak <anthraxx@archlinux.org>"])?;
        expected.add_values("%PROVIDES%", &["libzstd.so=1-64"])?;
        expected.add_values("%DEPENDS%", &["glibc", "gcc-libs", "zlib", "xz", "lz4"])?;
        expected.add_values("%MAKEDEPENDS%", &["cmake", "gtest", "ninja"])?;
        assert_eq!(pkg, expected);

        Ok(())
    }
}
