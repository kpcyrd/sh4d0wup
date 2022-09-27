use crate::errors::*;
use crate::pacman;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plot {
    #[serde(default)]
    pub upstreams: BTreeMap<String, Upstream>,
    pub routes: Vec<Route>,
}

impl Plot {
    pub fn load_from_str(s: &str) -> Result<Self> {
        let x = serde_yaml::from_str(s).context("Failed to load plot from string")?;
        Ok(x)
    }

    pub fn load_from_path(path: &str) -> Result<Self> {
        let s = fs::read_to_string(&path)
            .with_context(|| anyhow!("Failed to read file: {:?}", path))?;
        Plot::load_from_str(&s)
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
    PatchPacmanDbRoute(PatchPacmanDbRoute),
    #[serde(rename = "oci-registry-manifest")]
    OciRegistryManifest(OciRegistryManifest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub upstream: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRoute {
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub data: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgFilter {
    pub name: String,
    pub version: Option<String>,
}

impl PkgFilter {
    pub fn matches_pacman_pkg(&self, pkg: &pacman::Pkg) -> bool {
        if pkg.name() != self.name {
            return false;
        }

        if let Some(version) = &self.version {
            if pkg.version() != version {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgPatch {
    #[serde(flatten)]
    pub filter: PkgFilter,
    pub set: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPacmanDbRoute {
    pub upstream: String,
    pub path: Option<String>,
    #[serde(default)]
    pub patch: Vec<PkgPatch>,
    #[serde(default)]
    pub exclude: Vec<PkgFilter>,
}

impl PatchPacmanDbRoute {
    pub fn is_excluded(&self, pkg: &pacman::Pkg) -> bool {
        for filter in &self.exclude {
            if filter.matches_pacman_pkg(pkg) {
                return true;
            }
        }

        false
    }

    pub fn is_patched(&self, pkg: &pacman::Pkg) -> Option<&BTreeMap<String, Vec<String>>> {
        for rule in &self.patch {
            if !rule.filter.matches_pacman_pkg(pkg) {
                continue;
            }
            return Some(&rule.set);
        }
        None
    }
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
