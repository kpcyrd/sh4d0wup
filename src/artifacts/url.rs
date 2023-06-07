use crate::errors::*;
use crate::plot::Artifacts;
use crate::sessions::OciAuth;
use crate::sessions::Sessions;
use crate::templates;
use crate::upstream;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlArtifact {
    pub url: Option<Url>,
    pub url_template: Option<String>,
    pub template_metadata: Option<String>,

    pub oci_auth: Option<OciAuth>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub sha256: Option<String>,
}

impl UrlArtifact {
    pub fn render(&self, artifacts: &Artifacts) -> Result<RenderedUrlArtifact> {
        let url = if let Some(url) = &self.url {
            url.clone()
        } else if let Some(artifact) = &self.template_metadata {
            let artifact = artifacts.get(artifact).with_context(|| {
                anyhow!("Referencing artifact that doesn't exist: {:?}", artifact)
            })?;

            let artifact = templates::ArtifactMetadata::from_json(artifact.as_bytes())?;

            let template = self
                .url_template
                .as_ref()
                .context("Missing `url_template` in url artifact config")?;

            let url = templates::url::render(template, &artifact)?;
            url.parse()
                .with_context(|| anyhow!("Failed to parse rendered url: {url:?}"))?
        } else {
            bail!("Missing both `url` and `template_metadata` in url artifact config")
        };

        Ok(RenderedUrlArtifact {
            url,
            oci_auth: self.oci_auth.as_ref(),
            headers: &self.headers,
            sha256: self.sha256.as_ref(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderedUrlArtifact<'a> {
    pub url: Url,
    pub oci_auth: Option<&'a OciAuth>,
    pub headers: &'a HashMap<String, String>,
    pub sha256: Option<&'a String>,
}

impl<'a> RenderedUrlArtifact<'a> {
    pub async fn download(&self, sessions: &mut Sessions) -> Result<warp::hyper::body::Bytes> {
        let mut headers = HeaderMap::<HeaderValue>::default();

        if let Some(oci_auth) = &self.oci_auth {
            let token = sessions.create_oci_auth_session(oci_auth).await?;
            if let Some(token) = token {
                let value = format!("Bearer {token}");
                let value = value.parse().with_context(|| {
                    anyhow!("Failed to convert input to http header value: {:?}", value)
                })?;
                headers.insert("Authorization", value);
            }
        }

        for (k, v) in self.headers {
            let k: HeaderName = k
                .parse()
                .with_context(|| anyhow!("Failed to convert input to http header key: {:?}", k))?;
            let v = v.parse().with_context(|| {
                anyhow!("Failed to convert input to http header value: {:?}", v)
            })?;
            headers.insert(k, v);
        }

        let response = upstream::download(Method::GET, self.url.clone(), Some(headers))
            .await?
            .error_for_status()?;
        let buf = response.bytes().await?;

        self.verify_sha256(&buf)?;

        Ok(buf)
    }

    pub fn verify_sha256(&self, bytes: &[u8]) -> Result<()> {
        if let Some(expected) = self.sha256 {
            debug!("Calculating hash sum...");
            let mut h = Sha256::new();
            h.update(bytes);
            let h = hex::encode(h.finalize());
            debug!("Calcuated sha256: {:?}", h);
            debug!("Expected sha256: {:?}", expected);

            if h != *expected {
                bail!(
                    "Calculated sha256 {:?} doesn't match expected sha256 {:?}",
                    h,
                    expected
                );
            }

            Ok(())
        } else {
            trace!("No sha256 configured for url artifact, skipping pinning");
            Ok(())
        }
    }
}
