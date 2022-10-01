use crate::args;
use crate::compression;
use crate::errors::*;
use crate::shell;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::prelude::*;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct DebControl {
    map: IndexMap<String, String>,
}

impl DebControl {
    pub fn set_key<I1: Into<String>, I2: Into<String>>(&mut self, key: I1, value: I2) {
        self.map.insert(key.into(), value.into());
    }
}

impl FromStr for DebControl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut map = IndexMap::<_, String>::new();

        for line in s.split('\n') {
            if let Some(line) = line.strip_prefix(' ') {
                let (_key, value) = map.last_mut().context(
                    "Invalid control data: Tried to continue a previous value that doesn't exist",
                )?;
                write!(value, "\n{}", line).ok();
            } else if let Some((key, value)) = line.split_once(": ") {
                map.insert(key.to_string(), value.to_string());
            }
        }

        Ok(DebControl { map })
    }
}

impl ToString for DebControl {
    fn to_string(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.map {
            let mut iter = value.split('\n');
            writeln!(out, "{}: {}", key, iter.next().unwrap()).ok();
            for extra_line in iter {
                writeln!(out, " {}", extra_line).ok();
            }
        }
        out
    }
}

pub fn patch_control_tar(args: &args::InfectDebPkg, buf: &[u8]) -> Result<Vec<u8>> {
    let mut control_overrides = HashMap::new();
    for set in &args.set {
        let (key, value) = set
            .split_once('=')
            .with_context(|| anyhow!("Invalid --set assignment: {:?}", set))?;
        control_overrides.insert(key.to_string(), value.to_string());
    }

    debug!("Parsed control overrides: {:?}", control_overrides);

    let comp = compression::detect_compression(buf);
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);

        let tar = compression::stream_decompress(comp, buf)?;
        let mut archive = tar::Archive::new(tar);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let mut header = entry.header().clone();
            debug!("Found entry in control tar: {:?}", header.path());
            let path = header.path()?;
            let filename = path.to_str().with_context(|| {
                anyhow!("Package contains paths with invalid encoding: {:?}", path)
            })?;

            match (&args.payload, filename) {
                (Some(payload), "./postinst") => {
                    let mut script = String::new();
                    entry.read_to_string(&mut script)?;
                    debug!("Found existing postinst script: {:?}", script);

                    let script = shell::inject_into_script(&script, payload)
                        .context("Failed to inject into postinst script")?;

                    let script = script.as_bytes();
                    header.set_size(script.len() as u64);
                    header.set_cksum();

                    builder.append(&header, &mut &script[..])?;
                }
                (_, "./control") => {
                    if control_overrides.is_empty() {
                        debug!("Passing through control unparsed");
                        builder.append(&header, &mut entry)?;
                    } else {
                        let mut control = String::new();
                        entry.read_to_string(&mut control)?;

                        let mut control = control
                            .parse::<DebControl>()
                            .context("Failed to parse deb control file")?;
                        debug!("Found control data: {:?}", control);

                        for (key, value) in &control_overrides {
                            let old = control.map.insert(key.clone(), value.clone());
                            debug!("Updated control {:?}: {:?} -> {:?}", key, old, value);
                        }

                        let control = control.to_string();
                        debug!("Generated new control: {:?}", control);

                        let control = control.as_bytes();
                        header.set_size(control.len() as u64);
                        header.set_cksum();

                        builder.append(&header, &mut &control[..])?;
                    }
                }
                _ => {
                    builder.append(&header, &mut entry)?;
                }
            }
        }
    }
    let out = compression::compress(comp, &out)?;
    Ok(out)
}

pub fn infect<W: Write>(args: &args::InfectDebPkg, pkg: &[u8], out: &mut W) -> Result<()> {
    let mut archive = ar::Archive::new(pkg);
    let mut builder = ar::Builder::new(out);
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry?;
        let name = String::from_utf8(entry.header().identifier().to_vec())?;
        debug!(
            "Found entry in unix archive: {:?} => {:?}",
            name,
            entry.header()
        );

        if name == "control.tar.xz" {
            info!("Patching {:?}", name);
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let buf = patch_control_tar(args, &buf)?;

            let mut header = entry.header().clone();
            header.set_size(buf.len() as u64);

            builder.append(&header, &mut &buf[..])?;
        } else {
            debug!("Passing through into .deb");
            let header = entry.header().clone();
            builder.append(&header, &mut entry)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_deb_control() -> Result<()> {
        let data = r#"Package: nginx-core
Source: nginx
Version: 1.22.0-3
Architecture: amd64
Maintainer: Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>
Installed-Size: 1302
Depends: libnginx-mod-http-geoip (= 1.22.0-3), libnginx-mod-http-image-filter (= 1.22.0-3), libnginx-mod-http-xslt-filter (= 1.22.0-3), libnginx-mod-mail (= 1.22.0-3), libnginx-mod-stream (= 1.22.0-3), libnginx-mod-stream-geoip (= 1.22.0-3), nginx-common (= 1.22.0-3), iproute2, libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpcre3, libssl3 (>= 3.0.0), zlib1g (>= 1:1.1.4)
Suggests: nginx-doc (= 1.22.0-3)
Conflicts: nginx-extras, nginx-light
Breaks: nginx-full (<< 1.18.0-1)
Replaces: nginx-full (<< 1.18.0-1)
Provides: httpd, httpd-cgi, nginx
Section: httpd
Priority: optional
Homepage: https://nginx.org
Description: nginx web/proxy server (standard version)
 Nginx ("engine X") is a high-performance web and reverse proxy server
 created by Igor Sysoev. It can be used both as a standalone web server
 and as a proxy to reduce the load on back-end HTTP or mail servers.
 .
 This package provides a version of nginx identical to that of nginx-full,
 but without any third-party modules, and only modules in the original
 nginx code base.
 .
 STANDARD HTTP MODULES: Core, Access, Auth Basic, Auto Index, Browser, Empty
 GIF, FastCGI, Geo, Limit Connections, Limit Requests, Map, Memcached, Proxy,
 Referer, Rewrite, SCGI, Split Clients, UWSGI.
 .
 OPTIONAL HTTP MODULES: Addition, Auth Request, Charset, WebDAV, GeoIP, Gunzip,
 Gzip, Gzip Precompression, Headers, HTTP/2, Image Filter, Index, Log, Real IP,
 Slice, SSI, SSL, SSL Preread, Stub Status, Substitution, Thread  Pool,
 Upstream, User ID, XSLT.
 .
 OPTIONAL MAIL MODULES: Mail Core, Auth HTTP, Proxy, SSL, IMAP, POP3, SMTP.
 .
 OPTIONAL STREAM MODULES: Stream Core, GeoIP
"#;
        let control = data.parse::<DebControl>()?;

        let mut expected = DebControl::default();
        expected.set_key("Package", "nginx-core");
        expected.set_key("Source", "nginx");
        expected.set_key("Version", "1.22.0-3");
        expected.set_key("Architecture", "amd64");
        expected.set_key(
            "Maintainer",
            "Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>",
        );
        expected.set_key("Installed-Size", "1302");
        expected.set_key("Depends", "libnginx-mod-http-geoip (= 1.22.0-3), libnginx-mod-http-image-filter (= 1.22.0-3), libnginx-mod-http-xslt-filter (= 1.22.0-3), libnginx-mod-mail (= 1.22.0-3), libnginx-mod-stream (= 1.22.0-3), libnginx-mod-stream-geoip (= 1.22.0-3), nginx-common (= 1.22.0-3), iproute2, libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpcre3, libssl3 (>= 3.0.0), zlib1g (>= 1:1.1.4)");
        expected.set_key("Suggests", "nginx-doc (= 1.22.0-3)");
        expected.set_key("Conflicts", "nginx-extras, nginx-light");
        expected.set_key("Breaks", "nginx-full (<< 1.18.0-1)");
        expected.set_key("Replaces", "nginx-full (<< 1.18.0-1)");
        expected.set_key("Provides", "httpd, httpd-cgi, nginx");
        expected.set_key("Section", "httpd");
        expected.set_key("Priority", "optional");
        expected.set_key("Homepage", "https://nginx.org");
        expected.set_key("Description", "nginx web/proxy server (standard version)\nNginx (\"engine X\") is a high-performance web and reverse proxy server\ncreated by Igor Sysoev. It can be used both as a standalone web server\nand as a proxy to reduce the load on back-end HTTP or mail servers.\n.\nThis package provides a version of nginx identical to that of nginx-full,\nbut without any third-party modules, and only modules in the original\nnginx code base.\n.\nSTANDARD HTTP MODULES: Core, Access, Auth Basic, Auto Index, Browser, Empty\nGIF, FastCGI, Geo, Limit Connections, Limit Requests, Map, Memcached, Proxy,\nReferer, Rewrite, SCGI, Split Clients, UWSGI.\n.\nOPTIONAL HTTP MODULES: Addition, Auth Request, Charset, WebDAV, GeoIP, Gunzip,\nGzip, Gzip Precompression, Headers, HTTP/2, Image Filter, Index, Log, Real IP,\nSlice, SSI, SSL, SSL Preread, Stub Status, Substitution, Thread  Pool,\nUpstream, User ID, XSLT.\n.\nOPTIONAL MAIL MODULES: Mail Core, Auth HTTP, Proxy, SSL, IMAP, POP3, SMTP.\n.\nOPTIONAL STREAM MODULES: Stream Core, GeoIP");

        assert_eq!(control, expected);
        Ok(())
    }

    #[test]
    fn test_control_file_to_string() {
        let mut control = DebControl::default();
        control.set_key("Package", "nginx-core");
        control.set_key("Source", "nginx");
        control.set_key("Version", "1.22.0-3");
        control.set_key("Architecture", "amd64");
        control.set_key(
            "Maintainer",
            "Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>",
        );
        control.set_key("Installed-Size", "1302");
        control.set_key("Depends", "libnginx-mod-http-geoip (= 1.22.0-3), libnginx-mod-http-image-filter (= 1.22.0-3), libnginx-mod-http-xslt-filter (= 1.22.0-3), libnginx-mod-mail (= 1.22.0-3), libnginx-mod-stream (= 1.22.0-3), libnginx-mod-stream-geoip (= 1.22.0-3), nginx-common (= 1.22.0-3), iproute2, libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpcre3, libssl3 (>= 3.0.0), zlib1g (>= 1:1.1.4)");
        control.set_key("Suggests", "nginx-doc (= 1.22.0-3)");
        control.set_key("Conflicts", "nginx-extras, nginx-light");
        control.set_key("Breaks", "nginx-full (<< 1.18.0-1)");
        control.set_key("Replaces", "nginx-full (<< 1.18.0-1)");
        control.set_key("Provides", "httpd, httpd-cgi, nginx");
        control.set_key("Section", "httpd");
        control.set_key("Priority", "optional");
        control.set_key("Homepage", "https://nginx.org");
        control.set_key("Description", "nginx web/proxy server (standard version)\nNginx (\"engine X\") is a high-performance web and reverse proxy server\ncreated by Igor Sysoev. It can be used both as a standalone web server\nand as a proxy to reduce the load on back-end HTTP or mail servers.\n.\nThis package provides a version of nginx identical to that of nginx-full,\nbut without any third-party modules, and only modules in the original\nnginx code base.\n.\nSTANDARD HTTP MODULES: Core, Access, Auth Basic, Auto Index, Browser, Empty\nGIF, FastCGI, Geo, Limit Connections, Limit Requests, Map, Memcached, Proxy,\nReferer, Rewrite, SCGI, Split Clients, UWSGI.\n.\nOPTIONAL HTTP MODULES: Addition, Auth Request, Charset, WebDAV, GeoIP, Gunzip,\nGzip, Gzip Precompression, Headers, HTTP/2, Image Filter, Index, Log, Real IP,\nSlice, SSI, SSL, SSL Preread, Stub Status, Substitution, Thread  Pool,\nUpstream, User ID, XSLT.\n.\nOPTIONAL MAIL MODULES: Mail Core, Auth HTTP, Proxy, SSL, IMAP, POP3, SMTP.\n.\nOPTIONAL STREAM MODULES: Stream Core, GeoIP");

        assert_eq!(
            control.to_string(),
            r#"Package: nginx-core
Source: nginx
Version: 1.22.0-3
Architecture: amd64
Maintainer: Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>
Installed-Size: 1302
Depends: libnginx-mod-http-geoip (= 1.22.0-3), libnginx-mod-http-image-filter (= 1.22.0-3), libnginx-mod-http-xslt-filter (= 1.22.0-3), libnginx-mod-mail (= 1.22.0-3), libnginx-mod-stream (= 1.22.0-3), libnginx-mod-stream-geoip (= 1.22.0-3), nginx-common (= 1.22.0-3), iproute2, libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpcre3, libssl3 (>= 3.0.0), zlib1g (>= 1:1.1.4)
Suggests: nginx-doc (= 1.22.0-3)
Conflicts: nginx-extras, nginx-light
Breaks: nginx-full (<< 1.18.0-1)
Replaces: nginx-full (<< 1.18.0-1)
Provides: httpd, httpd-cgi, nginx
Section: httpd
Priority: optional
Homepage: https://nginx.org
Description: nginx web/proxy server (standard version)
 Nginx ("engine X") is a high-performance web and reverse proxy server
 created by Igor Sysoev. It can be used both as a standalone web server
 and as a proxy to reduce the load on back-end HTTP or mail servers.
 .
 This package provides a version of nginx identical to that of nginx-full,
 but without any third-party modules, and only modules in the original
 nginx code base.
 .
 STANDARD HTTP MODULES: Core, Access, Auth Basic, Auto Index, Browser, Empty
 GIF, FastCGI, Geo, Limit Connections, Limit Requests, Map, Memcached, Proxy,
 Referer, Rewrite, SCGI, Split Clients, UWSGI.
 .
 OPTIONAL HTTP MODULES: Addition, Auth Request, Charset, WebDAV, GeoIP, Gunzip,
 Gzip, Gzip Precompression, Headers, HTTP/2, Image Filter, Index, Log, Real IP,
 Slice, SSI, SSL, SSL Preread, Stub Status, Substitution, Thread  Pool,
 Upstream, User ID, XSLT.
 .
 OPTIONAL MAIL MODULES: Mail Core, Auth HTTP, Proxy, SSL, IMAP, POP3, SMTP.
 .
 OPTIONAL STREAM MODULES: Stream Core, GeoIP
"#
        );
    }
}
