use crate::errors::*;
use http::HeaderMap;
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net;
use warp::host::Authority;

pub type Selectors = BTreeMap<String, Selector>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Selector {
    All(All),
    Any(Any),
    Not(Not),
    Host(Host),
    Header(Header),
    Ipaddr(IpAddr),
}

impl Selector {
    pub fn matches(
        &self,
        selectors: &Selectors,
        addr: Option<&net::IpAddr>,
        authority: Option<&Authority>,
        headers: &HeaderMap,
    ) -> Result<bool> {
        match self {
            Selector::All(all) => {
                for selector in &all.selectors {
                    let selector = selector.resolve(selectors)?;
                    if !selector.matches(selectors, addr, authority, headers)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Selector::Any(any) => {
                for selector in &any.selectors {
                    let selector = selector.resolve(selectors)?;
                    if selector.matches(selectors, addr, authority, headers)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Selector::Not(not) => {
                let selector = not.selector.resolve(selectors)?;
                Ok(!selector.matches(selectors, addr, authority, headers)?)
            }
            Selector::Host(host) => host.matches(authority),
            Selector::Header(header) => header.matches(headers),
            Selector::Ipaddr(ipaddr) => Ok(ipaddr.matches(addr)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SelectorRef {
    Key(String),
    Inline(Selector),
}

impl SelectorRef {
    pub fn resolve<'a>(&'a self, selectors: &'a Selectors) -> Result<&'a Selector> {
        match self {
            SelectorRef::Key(selector) => {
                let selector = selectors.get(selector).with_context(|| {
                    anyhow!("Referenced selector {:?} does not exist", selector)
                })?;
                Ok(selector)
            }
            SelectorRef::Inline(selector) => Ok(selector),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct All {
    pub selectors: Vec<SelectorRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Any {
    pub selectors: Vec<SelectorRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Not {
    pub selector: Box<SelectorRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub key: String,
    pub value: Option<String>,
    pub regex: Option<String>,
}

impl Header {
    pub fn matches(&self, headers: &HeaderMap) -> Result<bool> {
        if let Some(header) = headers.get(&self.key) {
            if let Some(value) = &self.value {
                Ok(header == value)
            } else if let Some(regex) = &self.regex {
                let re = Regex::new(regex)
                    .with_context(|| anyhow!("Failed to compile regex: {:?}", regex))?;
                Ok(re.is_match(header.to_str()?))
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddr {
    pub ipaddr: IpNetwork,
}

impl IpAddr {
    pub fn matches(&self, addr: Option<&net::IpAddr>) -> bool {
        if let Some(addr) = addr {
            self.ipaddr.contains(*addr)
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetMask {
    pub ipaddr: net::IpAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub value: Option<String>,
    pub regex: Option<String>,
}

impl Host {
    pub fn matches(&self, host: Option<&Authority>) -> Result<bool> {
        let Some(host) = host else { return Ok(false) };
        let host = host.as_str();

        if let Some(value) = &self.value {
            Ok(host == value)
        } else if let Some(regex) = &self.regex {
            let re = Regex::new(regex)
                .with_context(|| anyhow!("Failed to compile regex: {:?}", regex))?;
            Ok(re.is_match(host))
        } else {
            Ok(true)
        }
    }
}
