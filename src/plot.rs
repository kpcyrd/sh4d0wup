use crate::args;
use crate::artifacts::{Artifact, HashedArtifact};
use crate::compression::{self, CompressedWith};
use crate::errors::*;
use crate::infect;
use crate::keygen::tls::KeygenTls;
use crate::keygen::{EmbeddedKey, Keygen};
use crate::selectors::{SelectorRef, Selectors};
use crate::sessions::Sessions;
use crate::templates;
use http::HeaderMap;
use indexmap::IndexMap;
use peekread::BufPeekReader;
use peekread::PeekRead;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use warp::host::Authority;
use warp::hyper::Body;

pub type Artifacts = BTreeMap<String, HashedArtifact>;
pub type SigningKeys = BTreeMap<String, EmbeddedKey>;

#[derive(Debug, Default, PartialEq)]
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
            CompressedWith::None => Ok(None),
            _ => bail!("Unsupported file format: {:?}", comp),
        }
    }

    pub fn load_bundle<R: Read>(
        r: R,
        comp: CompressedWith,
        artifacts: &mut Artifacts,
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
                    artifacts.insert(name, HashedArtifact::new(buf));
                }
            }
        }
        debug!("Finished reading bundle");

        plot.context("Bundle contains no plot")
    }

    pub async fn load_from_path<P: AsRef<Path>>(
        path: P,
        cache_from: Option<&Path>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let f = File::open(path).with_context(|| anyhow!("Failed to open plot at {:?}", path))?;
        let cache_from = if let Some(path) = cache_from {
            let f = File::open(path)
                .with_context(|| anyhow!("Failed to open cache plot at {:?}", path))?;
            Some(f)
        } else {
            None
        };
        Self::load_from_reader(f, cache_from).await
    }

    pub async fn load_from_reader<R1: Read, R2: Read>(
        reader: R1,
        cache_from: Option<R2>,
    ) -> Result<Self> {
        let mut r = BufPeekReader::new(reader);

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

        if let Some(path) = cache_from {
            Ctx::load_as_download_cache(path, &plot, &mut artifacts)
                .await
                .context("Failed to load existing plot as cache")?;
        }

        let extras = plot.resolve_extras(artifacts).await?;

        Ok(Ctx { plot, extras })
    }

    pub async fn load_as_download_cache<R: Read>(
        reader: R,
        plot: &Plot,
        out: &mut Artifacts,
    ) -> Result<()> {
        let mut r = BufPeekReader::new(reader);

        if r.peek().fill_buf().map(|b| b.is_empty()).ok() == Some(true) {
            debug!("Cache bundle is empty file, starting with empty cache...");
            return Ok(());
        }

        let mut existing = BTreeMap::new();
        if let Some(comp) = Self::is_bundle(r.peek())? {
            Self::load_bundle(r, comp, &mut existing)?
        } else {
            bail!("Only compiled plot bundles are supported");
        };

        for (key, artifact) in &plot.artifacts {
            if let Artifact::Url(artifact) = artifact {
                if let Some(existing) = existing.remove(key) {
                    let url = if let Some(url) = &artifact.url {
                        format!("{url:?}")
                    } else {
                        String::from("-")
                    };
                    info!(
                        "Found existing artifact for url artifact {:?}: {}",
                        key, url,
                    );
                    if let Some(expected) = &artifact.sha256 {
                        info!("Verifying sha256:{:?} matches cache content...", expected);
                        let existing_sha256 = existing.sha256();
                        if *expected != *existing_sha256 {
                            debug!("Not inserting into cache, existing artifact doesn't match sha256, expected: {:?}, existing: {:?}", expected, existing_sha256);
                            continue;
                        }
                    }

                    out.insert(key.to_string(), existing);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Plot {
    #[serde(default)]
    pub upstreams: BTreeMap<String, Upstream>,
    pub signing_keys: Option<BTreeMap<String, Keygen>>,
    #[serde(default)]
    pub artifacts: IndexMap<String, Artifact>,
    #[serde(default)]
    pub selectors: Selectors,
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
        info!("Loading plot from {:?}...", path);
        let s =
            fs::read_to_string(path).with_context(|| anyhow!("Failed to read file: {:?}", path))?;
        let plot = Plot::load_from_str(&s).context("Failed to deserialize plot")?;
        plot.validate().context("Plot failed to validate")?;
        Ok(plot)
    }

    pub fn ensure_artifact_exists(&self, artifact: &str) -> Result<()> {
        if self.artifacts.get(artifact).is_none() {
            bail!("Reference to undefined artifact object: {:?}", artifact);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        for route in &self.routes {
            if let Some(upstream) = route.action.upstream() {
                if !self.upstreams.contains_key(upstream) {
                    bail!("Reference to undefined upstream: {:?}", upstream);
                }
            }
            if let RouteAction::Static(route) = &route.action {
                match &route.source {
                    StaticSource::Data(_) => (),
                    StaticSource::Artifact(artifact) => self.ensure_artifact_exists(artifact)?,
                    StaticSource::Artifacts(artifacts) => {
                        for artifact in artifacts {
                            self.ensure_artifact_exists(artifact)?;
                        }
                    }
                    StaticSource::HashBucket(bucket) => {
                        for artifact in bucket.values() {
                            self.ensure_artifact_exists(artifact)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn select_route(
        &self,
        request_path: &str,
        addr: Option<&IpAddr>,
        authority: Option<&Authority>,
        headers: &HeaderMap,
    ) -> Result<&RouteAction> {
        for route in &self.routes {
            // if the route is for a specific path, verify it matches our request
            if let Some(path) = &route.path {
                if path != request_path {
                    continue;
                }
            }

            // if a host-header filter is specified, apply it to the request authority (this way it works on http2 too)
            if let Some(host) = &route.host {
                if authority.map(Authority::as_str) != Some(host) {
                    continue;
                }
            }

            // if a selector is selected and our request matches
            if let Some(selector) = &route.selector {
                let selector = selector.resolve(&self.selectors)?;
                if !selector.matches(&self.selectors, addr, authority, headers)? {
                    continue;
                }
            }

            // if the route is a static route with an artifact_hash_bucket for our request
            if let RouteAction::Static(action) = &route.action {
                if let StaticSource::HashBucket(bucket) = &action.source {
                    if !bucket.contains_key(request_path) {
                        continue;
                    }
                }
            }

            // The request matches this route
            return Ok(&route.action);
        }

        bail!("Could not find any matching route for request")
    }

    pub async fn resolve_extras(&mut self, artifacts: Artifacts) -> Result<PlotExtras> {
        debug!("Resolving signing keys...");
        let signing_keys = if let Some(keys) = self.signing_keys.take() {
            keys.into_iter()
                .map(|(key, value)| Ok((key, value.resolve()?)))
                .collect::<Result<_>>()?
        } else {
            BTreeMap::new()
        };

        let mut extras = PlotExtras {
            signing_keys,
            artifacts,
            ..Default::default()
        };

        debug!("Resolving artifacts...");
        for (k, v) in &mut self.artifacts {
            debug!("Resolving artifact {:?}...", k);
            if let Some(buf) = v.resolve(&mut extras, k).await? {
                extras
                    .artifacts
                    .insert(k.to_string(), HashedArtifact::new(buf));
            }
        }

        debug!("Updating path templates...");
        for route in &mut self.routes {
            route
                .resolve_path_template(&extras.artifacts)
                .context("Failed to resolve path for route")?;
        }

        Ok(extras)
    }

    pub async fn resolve(mut self) -> Result<Ctx> {
        let artifacts = BTreeMap::new();
        let extras = self.resolve_extras(artifacts).await?;
        Ok(Ctx { plot: self, extras })
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct PlotExtras {
    pub signing_keys: SigningKeys,
    pub artifacts: Artifacts,
    pub sessions: Sessions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Upstream {
    pub url: url::Url,
    #[serde(default)]
    pub keep_headers: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub path: Option<String>,
    pub host: Option<String>,
    pub selector: Option<SelectorRef>,
    #[serde(flatten)]
    pub action: RouteAction,
}

impl Route {
    pub fn resolve_path_template(&mut self, artifacts: &Artifacts) -> Result<()> {
        if let RouteAction::Static(action) = &mut self.action {
            let metadata = if let Some(metadata) = &action.template_metadata {
                let metadata = artifacts
                    .get(metadata)
                    .with_context(|| anyhow!("Reference to undefined artifact: {:?}", metadata))?;
                let metadata = templates::ArtifactMetadata::from_json(metadata.as_bytes())?;
                Some(metadata)
            } else {
                None
            };

            match &action.source {
                StaticSource::Artifact(artifact) => {
                    if let Some(path_template) = &action.path_template {
                        let artifact = artifacts.get(artifact).with_context(|| {
                            anyhow!("Reference to undefined artifact: {:?}", artifact)
                        })?;

                        let rendered =
                            templates::route::render(path_template, artifact, metadata.as_ref())?;
                        self.path = Some(rendered);
                    }
                }
                StaticSource::Artifacts(list) => {
                    let path_template = action
                        .path_template
                        .as_ref()
                        .context("List of artifacts configured but no path template")?;

                    let mut hash_bucket = HashMap::new();
                    for artifact_name in list {
                        let artifact = artifacts.get(artifact_name).with_context(|| {
                            anyhow!("Reference to undefined artifact: {:?}", artifact_name)
                        })?;

                        let rendered =
                            templates::route::render(path_template, artifact, metadata.as_ref())?;
                        hash_bucket.insert(rendered, artifact_name.to_string());
                    }
                    action.source = StaticSource::HashBucket(hash_bucket);
                }
                _ => (),
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "args", rename_all = "kebab-case")]
pub enum RouteAction {
    Proxy(ProxyRoute),
    Static(StaticRoute),
    PatchPacmanDb(PatchPkgDatabaseRoute),
    PatchAptRelease(PatchAptReleaseRoute),
    PatchAptPackageList(PatchPkgDatabaseRoute),
    OciRegistryManifest(OciRegistryManifestRoute),
    Append(AppendRoute),
    PatchShell(PatchShellRoute),
}

impl RouteAction {
    pub fn upstream(&self) -> Option<&String> {
        match self {
            Self::Proxy(action) => Some(&action.upstream),
            Self::Static(_) => None,
            Self::PatchPacmanDb(action) => Some(&action.proxy.upstream),
            Self::PatchAptRelease(action) => Some(&action.proxy.upstream),
            Self::PatchAptPackageList(action) => Some(&action.proxy.upstream),
            Self::OciRegistryManifest(_) => None,
            Self::Append(action) => Some(&action.proxy.upstream),
            Self::PatchShell(action) => Some(&action.proxy.upstream),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub upstream: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaticSource {
    Data(String),
    Artifact(String),
    Artifacts(Vec<String>),
    HashBucket(HashMap<String, String>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticRoute {
    pub path_template: Option<String>,
    pub template_metadata: Option<String>,

    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub compress: Option<CompressedWith>,
    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(flatten)]
    pub source: StaticSource,
}

impl StaticRoute {
    pub async fn get_artifact_bytes<'a>(
        &self,
        ctx: &'a Ctx,
        artifact: &str,
    ) -> Result<Cow<'a, [u8]>> {
        let config =
            ctx.plot.artifacts.get(artifact).with_context(|| {
                anyhow!("Undefined reference to artifact object: {:?}", artifact)
            })?;

        match config {
            Artifact::File(artifact) => {
                let data = tokio::fs::read(&artifact.path).await?;
                Ok(Cow::Owned(data))
            }
            Artifact::Url(_) => {
                bail!("Url artifacts are expected to be loaded into memory at this point");
            }
            Artifact::Inline(_) => {
                bail!("Inline artifacts are expected to be loaded into memory at this point");
            }
            _ => {
                let artifact = ctx.extras.artifacts.get(artifact).with_context(|| {
                    anyhow!("Undefined reference to artifact object: {:?}", artifact)
                })?;
                Ok(Cow::Borrowed(&artifact.bytes[..]))
            }
        }
    }

    pub async fn generate_response(
        &self,
        ctx: &Ctx,
        request_path: &str,
    ) -> Result<http::Response<Body>> {
        let status = self.status.unwrap_or(200);
        let mut builder = http::Response::builder().status(status);

        if let Some(value) = &self.content_type {
            builder = builder.header("Content-Type", value);
        }

        for (key, value) in &self.headers {
            builder = builder.header(key, value);
        }

        let data = match &self.source {
            StaticSource::Data(data) => Cow::Borrowed(data.as_bytes()),
            StaticSource::Artifact(artifact) => self.get_artifact_bytes(ctx, artifact).await?,
            StaticSource::Artifacts(_) => {
                bail!("List of artifacts is expected to be resolved into HashBucket at this point")
            }
            StaticSource::HashBucket(bucket) => {
                let artifact = bucket.get(request_path).with_context(|| {
                    anyhow!(
                        "Failed to find entry in hash bucket for key: {:?}",
                        request_path
                    )
                })?;
                self.get_artifact_bytes(ctx, artifact).await?
            }
        };

        let data = if let Some(compress) = self.compress {
            compression::compress(compress, &data)?
        } else {
            data.into_owned()
        };

        Ok(builder.body(Body::from(data)).unwrap())
    }
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
    pub artifact: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub set: PkgPatchValues<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchPkgDatabaseRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    #[serde(flatten)]
    pub config: PatchPkgDatabaseConfig<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    // TODO: not sure if this method is well thought out
    pub fn artifact<P: PkgRef>(&self, pkg: &P) -> Option<&str> {
        for rule in &self.patch {
            if rule.filter.matches_pkg(pkg) {
                if let Some(artifact) = &rule.artifact {
                    return Some(artifact.as_str());
                }
            }
        }
        None
    }

    // TODO: not sure if this method is well thought out
    pub fn signature<P: PkgRef>(&self, pkg: &P) -> Option<&str> {
        for rule in &self.patch {
            if rule.filter.matches_pkg(pkg) {
                if let Some(signature) = &rule.signature {
                    return Some(signature.as_str());
                }
            }
        }
        None
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
            patch.push(PkgPatch {
                filter,
                artifact: None,
                signature: None,
                set,
            });
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
            patch.push(PkgPatch {
                filter,
                artifact: None,
                signature: None,
                set,
            });
        }

        Ok(Self {
            patch,
            exclude: args.exclude,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchAptReleaseRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    #[serde(flatten)]
    pub config: PatchAptReleaseConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciRegistryManifestRoute {
    pub name: String,
    pub tag: String,
    pub architecture: String,
    pub content_digest: String,
    #[serde(default)]
    pub fs_layers: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchAptReleaseConfig {
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(flatten)]
    pub checksums: PatchPkgDatabaseConfig<String>,
    pub signing_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppendRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchShellRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    #[serde(flatten)]
    pub infect: infect::sh::Infect,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub image: String,
    pub install_certs: Option<Cmd>,
    #[serde(default)]
    pub install_keys: Vec<InstallKey>,
    #[serde(default)]
    pub register_hosts: Vec<String>,
    #[serde(default)]
    pub expose_fuse: bool,
    pub cmds: Vec<Cmd>,
    pub init: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cmd {
    Shell(String),
    Exec(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstallKey {
    pub key: String,
    #[serde(default)]
    pub binary: bool,
    pub cmd: Cmd,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts;
    use crate::build;
    use crate::infect;

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

    #[tokio::test]
    async fn test_load_empty_plot() -> Result<()> {
        let plot = b"routes: []";
        let ctx = Ctx::load_from_reader(&plot[..], Option::<File>::None).await?;
        assert_eq!(ctx, Ctx::default());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_empty_compiled_plot() -> Result<()> {
        let plot = r#"routes: []"#;
        let mut plot = Plot::load_from_str(plot)?;
        let mut w = Vec::new();
        build::build(&mut plot, Option::<File>::None)
            .await?
            .write(&mut w)?;
        assert_eq!(plot, Plot::default());

        let ctx = Ctx::load_from_reader(&w[..], Option::<File>::None).await?;
        assert_eq!(ctx, Ctx::default());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_compiled_plot() -> Result<()> {
        let plot = r#"
artifacts:
  foo:
    type: inline
    data: |
      hello world

routes: []"#;
        let mut plot = Plot::load_from_str(plot)?;
        let mut w = Vec::new();
        build::build(&mut plot, Option::<File>::None)
            .await?
            .write(&mut w)?;
        assert_eq!(
            plot,
            Plot {
                artifacts: indexmap::indexmap! {
                    "foo".to_string() => Artifact::Memory,
                },
                ..Default::default()
            }
        );

        let ctx = Ctx::load_from_reader(&w[..], Option::<File>::None).await?;
        assert_eq!(
            ctx,
            Ctx {
                plot: Plot {
                    artifacts: indexmap::indexmap! {
                        "foo".to_string() => Artifact::Memory,
                    },
                    ..Default::default()
                },
                extras: PlotExtras {
                    artifacts: maplit::btreemap! [
                        "foo".to_string() => HashedArtifact::new("hello world\n".into()),
                    ],
                    ..Default::default()
                },
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_ensure_embedded_artifacts_are_used() -> Result<()> {
        let plot = r#"
artifacts:
  src:
    type: inline
    data: |
      hello world
  foo:
    type: inline
    data: |
      this should not be overwritten

routes: []"#;
        let mut plot = Plot::load_from_str(plot)?;
        let mut w = Vec::new();
        let mut archive = build::build(&mut plot, Option::<File>::None).await?;
        archive.plot = r#"
{
  "artifacts": {
    "src": {"type": "memory"},
    "foo": {
      "type": "infect",
      "infect": "sh",
      "artifact": "src",
      "payload": "id",
      "hook_functions": ["foo"]
    }
  },
  "routes": []
}
"#
        .to_string();
        archive.write(&mut w)?;
        assert_eq!(
            plot,
            Plot {
                artifacts: indexmap::indexmap! {
                    "src".to_string() => Artifact::Memory,
                    "foo".to_string() => Artifact::Memory,
                },
                ..Default::default()
            }
        );

        let ctx = Ctx::load_from_reader(&w[..], Option::<File>::None).await?;
        assert_eq!(
            ctx,
            Ctx {
                plot: Plot {
                    artifacts: indexmap::indexmap! {
                        "src".to_string() => Artifact::Memory,
                        "foo".to_string() => Artifact::Memory,
                    },
                    ..Default::default()
                },
                extras: PlotExtras {
                    artifacts: maplit::btreemap! [
                        "src".to_string() => HashedArtifact::new("hello world\n".into()),
                        "foo".to_string() => HashedArtifact::new("this should not be overwritten\n".into()),
                    ],
                    ..Default::default()
                },
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_from() -> Result<()> {
        let plot = r#"
artifacts:
  foo:
    type: inline
    data: |
      hello world

routes: []"#;
        let mut plot = Plot::load_from_str(plot)?;
        let mut w = Vec::new();
        build::build(&mut plot, Option::<File>::None)
            .await?
            .write(&mut w)?;
        assert_eq!(
            plot,
            Plot {
                artifacts: indexmap::indexmap! {
                    "foo".to_string() => Artifact::Memory,
                },
                ..Default::default()
            }
        );

        let plot = br#"
artifacts:
  foo:
    type: url
    url: https://this.is.invalid/file.bin

routes: []"#;
        let ctx = Ctx::load_from_reader(&plot[..], Some(&w[..])).await?;
        assert_eq!(
            ctx,
            Ctx {
                plot: Plot {
                    artifacts: indexmap::indexmap! {
                        "foo".to_string() => Artifact::Memory,
                    },
                    ..Default::default()
                },
                extras: PlotExtras {
                    artifacts: maplit::btreemap! [
                        "foo".to_string() => HashedArtifact::new("hello world\n".into()),
                    ],
                    ..Default::default()
                },
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_from_only_use_referenced() -> Result<()> {
        let plot = r#"
artifacts:
  foo:
    type: inline
    data: |
      hello world

routes: []"#;
        let mut plot = Plot::load_from_str(plot)?;
        let mut w = Vec::new();
        build::build(&mut plot, Option::<File>::None)
            .await?
            .write(&mut w)?;
        assert_eq!(
            plot,
            Plot {
                artifacts: indexmap::indexmap! {
                    "foo".to_string() => Artifact::Memory,
                },
                ..Default::default()
            }
        );

        let plot = br#"routes: []"#;
        let ctx = Ctx::load_from_reader(&plot[..], Some(&w[..])).await?;
        assert_eq!(ctx, Ctx::default());
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_from_only_caches_url_artifacts() -> Result<()> {
        let plot = r#"
artifacts:
  url:
    type: inline
    data: hello world
  infect:
    type: inline
    data: this should be regenerated

routes: []"#;
        let mut plot = Plot::load_from_str(plot)?;
        let mut w = Vec::new();
        build::build(&mut plot, Option::<File>::None)
            .await?
            .write(&mut w)?;

        let plot = br#"
artifacts:
  url:
    type: url
    url: https://this.is.invalid/file.bin
  infect:
    type: infect
    infect: sh
    artifact: url
    payload: id
    hook_functions: [foo]

routes: []"#;
        let ctx = Ctx::load_from_reader(&plot[..], Some(&w[..])).await?;
        assert_eq!(
            ctx,
            Ctx {
                plot: Plot {
                    artifacts: indexmap::indexmap! {
                        "url".to_string() => Artifact::Memory,
                        "infect".to_string() => Artifact::Infect(artifacts::infect::InfectArtifact::Sh(artifacts::infect::InfectShArtifact {
                            artifact: "url".to_string(),
                            config: infect::sh::Infect {
                                hook_functions: vec!["foo".to_string()],
                                payload: "id".to_string(),
                            }
                        }
                        )),
                    },
                    ..Default::default()
                },
                extras: PlotExtras {
                    artifacts: maplit::btreemap! [
                        "url".to_string() => HashedArtifact::new("hello world".into()),
                        "infect".to_string() => HashedArtifact::new("hello world".into()),
                    ],
                    ..Default::default()
                },
            }
        );
        Ok(())
    }
}
