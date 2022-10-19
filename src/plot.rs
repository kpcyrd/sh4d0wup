use crate::certs::Tls;
use crate::errors::*;
use crate::tamper_idx::pacman;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plot {
    #[serde(default)]
    pub upstreams: BTreeMap<String, Upstream>,
    pub tls: Option<Tls>,
    pub routes: Vec<Route>,
    pub check: Option<Check>,
}

impl Plot {
    pub fn load_from_str(s: &str) -> Result<Self> {
        let x = serde_yaml::from_str(s).context("Failed to load plot from string")?;
        Ok(x)
    }

    pub fn load_from_path(path: &str) -> Result<Self> {
        let s = fs::read_to_string(&path)
            .with_context(|| anyhow!("Failed to read file: {:?}", path))?;
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
    #[serde(rename = "append")]
    Append(Append),
}

impl RouteAction {
    pub fn upstream(&self) -> Option<&String> {
        match self {
            Self::Proxy(action) => Some(&action.upstream),
            Self::Static(_) => None,
            Self::PatchPacmanDbRoute(action) => Some(&action.proxy.upstream),
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
    pub data: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
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

impl FromStr for PkgFilter {
    type Err = Error;

    fn from_str(mut s: &str) -> Result<Self> {
        let mut name = None;
        let mut version = None;

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
                _ => bail!("Invalid key: {:?}", key),
            }
        }

        Ok(PkgFilter {
            name: name.context("Missing name")?,
            version,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PkgPatchValues {
    #[serde(flatten)]
    pub values: BTreeMap<String, Vec<String>>,
}

impl FromStr for PkgPatchValues {
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
pub struct PkgPatch {
    #[serde(flatten)]
    pub filter: PkgFilter,
    pub set: PkgPatchValues,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPacmanDbRoute {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    #[serde(default)]
    pub patch: Vec<PkgPatch>,
    #[serde(default)]
    pub exclude: Vec<PkgFilter>,
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
pub struct Append {
    #[serde(flatten)]
    pub proxy: ProxyRoute,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub image: String,
    pub cmds: Vec<Cmd>,
    pub init: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cmd {
    Shell(String),
    Exec(Vec<String>),
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
            }
        );
    }

    #[test]
    fn test_parse_pkg_filter_name_version() {
        let filter = "name=foo,version=1.33.7".parse::<PkgFilter>().unwrap();
        assert_eq!(
            filter,
            PkgFilter {
                name: "foo".to_string(),
                version: Some("1.33.7".to_string()),
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
