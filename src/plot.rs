use crate::args;
use crate::compression::{self, CompressedWith};
use crate::errors::*;
use crate::keygen::tls::KeygenTls;
use crate::keygen::{EmbeddedKey, Keygen};
use peekread::BufPeekReader;
use peekread::PeekRead;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ctx {
    pub plot: Plot,
    pub extras: PlotExtras,
}

impl Ctx {
    pub fn is_bundle<R: Read>(r: R) -> Result<Option<CompressedWith>> {
        let mut buf = Vec::new();
        r.take(256).read_to_end(&mut buf)?;
        let comp = compression::detect_compression(&buf);
        match comp {
            CompressedWith::Zstd => Ok(Some(comp)),
            CompressedWith::Unknown => Ok(None),
            _ => bail!("Unsupported file format: {:?}", comp),
        }
    }

    pub fn load_bundle<R: Read>(
        r: R,
        comp: CompressedWith,
        artifacts: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<String> {
        let r = compression::stream_decompress(r, comp)?;
        let mut tar = tar::Archive::new(r);

        let mut plot = None;
        debug!("Reading bundle...");
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let path = path.to_str().with_context(|| {
                anyhow!(
                    "Bundle contains entry with invalid utf8 filename: {:?}",
                    path
                )
            })?;
            debug!("Found entry in bundle: {:?}", path);
            match path {
                "plot.json" => {
                    let mut s = String::new();
                    entry.read_to_string(&mut s)?;
                    plot = Some(s);
                }
                name => {
                    debug!("Registering artifact: {:?}", name);
                    let name = name.to_string();
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf)?;
                    artifacts.insert(name, buf);
                }
            }
        }
        debug!("Finished reading bundle");

        plot.context("Bundle contains no plot")
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        let f = File::open(path).context("Failed to open plot")?;
        let mut r = BufPeekReader::new(f);

        let mut artifacts = BTreeMap::new();
        let plot = if let Some(comp) = Self::is_bundle(r.peek())? {
            Self::load_bundle(r, comp, &mut artifacts)?
        } else {
            let mut s = String::new();
            r.read_to_string(&mut s)?;
            s
        };

        let mut plot = Plot::load_from_str(&plot).context("Failed to deserialize plot")?;
        plot.validate().context("Plot failed to validate")?;
        let mut extras = plot.resolve_extras()?;

        extras.artifacts.extend(artifacts.into_iter());

        Ok(Ctx { plot, extras })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Plot {
    #[serde(default)]
    pub upstreams: BTreeMap<String, Upstream>,
    pub signing_keys: Option<BTreeMap<String, Keygen>>,
    #[serde(default)]
    pub artifacts: BTreeMap<String, Artifact>,
    pub tls: Option<KeygenTls>,
    pub routes: Vec<Route>,
    pub check: Option<Check>,
}

impl Plot {
    pub fn load_from_str(s: &str) -> Result<Self> {
        let plot = serde_yaml::from_str(s).context("Failed to load plot from string")?;
        trace!("Loaded plot: {:?}", plot);
        Ok(plot)
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let s =
            fs::read_to_string(path).with_context(|| anyhow!("Failed to read file: {:?}", path))?;
        let plot = Plot::load_from_str(&s).context("Failed to deserialize plot")?;
        plot.validate().context("Plot failed to validate")?;
        Ok(plot)
    }

    pub fn validate(&self) -> Result<()> {
        for route in &self.routes {
            if let Some(upstream) = route.action.upstream() {
                if !self.upstreams.contains_key(upstream) {
                    bail!("Reference to undefined upstream: {:?}", upstream);
                }
            }
            if let RouteAction::Static(route) = &route.action {
                match (&route.data, &route.artifact) {
                    (None, None) => bail!("Static route is missing both data and artifact reference"),
                    (Some(_), Some(_)) => bail!("Static route has both data and artifact reference but they are mutually exclusive"),
                    (None, Some(artifact)) => {
                        if self.artifacts.get(artifact).is_none() {
                            bail!("Reference to undefined artifact object: {:?}", artifact);
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(())
    }

    pub fn select_route(&self, request_path: &str) -> Result<&RouteAction> {
        let mut default_route = None;

        for route in &self.routes {
            if let Some(path) = &route.path {
                if path == request_path {
                    return Ok(&route.action);
                }
            } else {
                default_route = Some(route);
            }
        }

        let route = default_route.context("Could not find matching route and no default set")?;

        Ok(&route.action)
    }

    pub fn resolve_extras(&mut self) -> Result<PlotExtras> {
        let signing_keys = if let Some(keys) = self.signing_keys.take() {
            keys.into_iter()
                .map(|(key, value)| Ok((key, value.resolve()?)))
                .collect::<Result<_>>()?
        } else {
            BTreeMap::new()
        };

        let mut artifacts = BTreeMap::new();
        for (k, v) in &mut self.artifacts {
            match v {
                Artifact::Path(_) => (),
                Artifact::Url(_) => (),
                Artifact::Inline(inline) => {
                    let data = mem::take(&mut inline.data);
                    *v = Artifact::Memory;
                    let bytes = data.into_bytes();
                    artifacts.insert(k.to_string(), bytes);
                }
                Artifact::Memory => (),
            }
        }

        Ok(PlotExtras {
            signing_keys,
            artifacts,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlotExtras {
    pub signing_keys: BTreeMap<String, EmbeddedKey>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub url: url::Url,
    #[serde(default)]
    pub keep_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub path: Option<String>,
    #[serde(flatten)]
    pub action: RouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "args")]
pub enum RouteAction {
    #[serde(rename = "proxy")]
    Proxy(ProxyRoute),
    #[serde(rename = "static")]
    Static(StaticRoute),
    #[serde(rename = "patch-pacman-db")]
    PatchPacmanDbRoute(PatchPkgDatabaseRoute),
    #[serde(rename = "patch-apt-release")]
    PatchAptRelease(PatchAptReleaseRoute),
    #[serde(rename = "patch-apt-package-list")]
    PatchAptPackageList(PatchPkgDatabaseRoute),
    #[serde(rename = "oci-registry-manifest")]
    OciRegistryManifest(OciRegistryManifest),
    #[serde(rename = "append")]
    Append(Append),
}

impl RouteAction {
    pub fn upstream(&self) -> Option<&String> {
        match self {
            Self::Proxy(action) => Some(&action.upstream),
            Self::Static(_) => None,
            Self::PatchPacmanDbRoute(action) => Some(&action.proxy.upstream),
            Self::PatchAptRelease(action) => Some(&action.proxy.upstream),
            Self::PatchAptPackageList(action) => Some(&action.proxy.upstream),
            Self::OciRegistryManifest(_) => None,
            Self::Append(action) => Some(&action.proxy.upstream),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub upstream: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRoute {
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub data: Option<String>,
    pub artifact: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

pub trait PkgRef {
    fn name(&self) -> &str;

    fn version(&self) -> &str;

    fn namespace(&self) -> Option<&str> {
        None
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PkgFilter {
    pub name: String,
    pub version: Option<String>,
    pub namespace: Option<String>,
}

impl PkgFilter {
    pub fn matches_pkg<P: PkgRef>(&self, pkg: &P) -> bool {
        if pkg.name() != self.name {
            return false;
        }

        if let Some(version) = &self.version {
            if pkg.version() != version {
                return false;
            }
        }

        if self.namespace.is_some() && pkg.namespace() != self.namespace.as_deref() {
            return false;
        }

        true
    }
}

impl FromStr for PkgFilter {
    type Err = Error;

    fn from_str(mut s: &str) -> Result<Self> {
        let mut name = None;
        let mut version = None;
        let mut namespace = None;

        while !s.is_empty() {
            let idx = s.find('=').context("Filter key but no value")?;
            let key = &s[..idx];
            s = &s[idx + 1..];
            let idx = s.find(',').unwrap_or(s.len());
            let value = &s[..idx];
            s = &s[idx..];

            // skip the comma if there was one
            if !s.is_empty() {
                s = &s[1..];
            }

            match key {
                "name" => name = Some(value.to_string()),
                "version" => version = Some(value.to_string()),
                "namespace" => namespace = Some(value.to_string()),
                _ => bail!("Invalid key: {:?}", key),
            }
        }

        Ok(PkgFilter {
            name: name.context("Missing name")?,
            version,
            namespace,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize)]
pub struct PkgPatchValues<T> {
    #[serde(flatten)]
    pub values: BTreeMap<String, T>,
}

impl FromStr for PkgPatchValues<Vec<String>> {
    type Err = Error;

    fn from_str(mut s: &str) -> Result<Self> {
        let mut values = BTreeMap::<_, Vec<_>>::new();

        while !s.is_empty() {
            let idx = s.find('=').context("PkgPatch key but no value")?;
            let key = &s[..idx];
            s = &s[idx + 1..];
            let idx = s.find(',').unwrap_or(s.len());
            let value = &s[..idx];
            s = &s[idx..];

            // skip the comma if there was one
            if !s.is_empty() {
                s = &s[1..];
            }

            values
                .entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }

        Ok(PkgPatchValues { values })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PkgPatch<T> {
    #[serde(flatten)]
    pub filter: PkgFilter,
    pub set: PkgPatchValues<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPkgDatabaseRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    #[serde(flatten)]
    pub config: PatchPkgDatabaseConfig<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPkgDatabaseConfig<T> {
    #[serde(default)]
    pub patch: Vec<PkgPatch<T>>,
    #[serde(default)]
    pub exclude: Vec<PkgFilter>,
}

impl<T> PatchPkgDatabaseConfig<T> {
    pub fn is_excluded<P: PkgRef>(&self, pkg: &P) -> bool {
        for filter in &self.exclude {
            if filter.matches_pkg(pkg) {
                return true;
            }
        }

        false
    }

    pub fn get_patches<P: PkgRef>(&self, pkg: &P) -> Option<BTreeMap<&str, &T>> {
        let mut patch = BTreeMap::new();
        for rule in &self.patch {
            if rule.filter.matches_pkg(pkg) {
                for (key, value) in &rule.set.values {
                    patch.insert(key.as_str(), value);
                }
            }
        }
        if patch.is_empty() {
            None
        } else {
            Some(patch)
        }
    }
}

impl PatchPkgDatabaseConfig<Vec<String>> {
    pub fn from_args(args: args::TamperPackageDatabaseConfig) -> Result<Self> {
        let mut patch = Vec::new();

        if args.filter.len() != args.set.len() {
            bail!(
                "Number of --filter and --set differ, {} vs {}",
                args.filter.len(),
                args.set.len()
            );
        }

        for (filter, set) in args.filter.into_iter().zip(args.set) {
            patch.push(PkgPatch { filter, set });
        }

        Ok(Self {
            patch,
            exclude: args.exclude,
        })
    }
}

impl PatchPkgDatabaseConfig<String> {
    pub fn from_args(args: args::TamperPackageDatabaseConfig) -> Result<Self> {
        let mut patch = Vec::new();

        if args.filter.len() != args.set.len() {
            bail!(
                "Number of --filter and --set differ, {} vs {}",
                args.filter.len(),
                args.set.len()
            );
        }

        for (filter, set) in args.filter.into_iter().zip(args.set) {
            let mut values = BTreeMap::new();
            for (key, value) in set.values {
                let value = value
                    .into_iter()
                    .next()
                    .context("Values to set can't be empty")?;
                values.insert(key, value);
            }

            let set = PkgPatchValues { values };
            patch.push(PkgPatch { filter, set });
        }

        Ok(Self {
            patch,
            exclude: args.exclude,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAptReleaseRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    #[serde(flatten)]
    pub config: PatchAptReleaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRegistryManifest {
    pub name: String,
    pub tag: String,
    pub architecture: String,
    pub content_digest: String,
    #[serde(default)]
    pub fs_layers: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAptReleaseConfig {
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(flatten)]
    pub checksums: PatchPkgDatabaseConfig<String>,
    pub signing_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Append {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub image: String,
    pub install_certs: Option<Cmd>,
    #[serde(default)]
    pub install_pgp: Vec<InstallPgp>,
    #[serde(default)]
    pub register_hosts: Vec<String>,
    pub cmds: Vec<Cmd>,
    pub init: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cmd {
    Shell(String),
    Exec(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallPgp {
    pub key: String,
    #[serde(default)]
    pub binary: bool,
    pub cmd: Cmd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Artifact {
    Path(PathArtifact),
    Url(UrlArtifact),
    Inline(InlineArtifact),
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathArtifact {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlArtifact {
    pub url: Url,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineArtifact {
    pub data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pkg_filter_name() {
        let filter = "name=foo".parse::<PkgFilter>().unwrap();
        assert_eq!(
            filter,
            PkgFilter {
                name: "foo".to_string(),
                version: None,
                namespace: None,
            }
        );
    }

    #[test]
    fn test_parse_pkg_filter_name_version_namespace() {
        let filter = "name=foo,version=1.33.7,namespace=asdf"
            .parse::<PkgFilter>()
            .unwrap();
        assert_eq!(
            filter,
            PkgFilter {
                name: "foo".to_string(),
                version: Some("1.33.7".to_string()),
                namespace: Some("asdf".to_string()),
            }
        );
    }

    #[test]
    fn test_parse_pkg_filter_version_only() {
        let res = "version=1.33.7".parse::<PkgFilter>();
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_pkg_filter_invalid() {
        let res = "abc=xyz".parse::<PkgFilter>();
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_pkg_filter_empty() {
        let res = "".parse::<PkgFilter>();
        assert!(res.is_err());
    }
}
