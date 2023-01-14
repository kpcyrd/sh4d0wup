use crate::errors::*;
use crate::sessions::OciAuth;
use crate::sessions::Sessions;
use crate::upstream;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlArtifact {
    pub url: Url,
    pub oci_auth: Option<OciAuth>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub sha256: Option<String>,
}

impl UrlArtifact {
    pub async fn download(&self, sessions: &mut Sessions) -> Result<warp::hyper::body::Bytes> {
        let mut headers = HeaderMap::<HeaderValue>::default();

        if let Some(oci_auth) = &self.oci_auth {
            let token = sessions.create_oci_auth_session(oci_auth).await?;
            if let Some(token) = token {
                let value = format!("Bearer {}", token);
                let value = value.parse().with_context(|| {
                    anyhow!("Failed to convert input to http header value: {:?}", value)
                })?;
                headers.insert("Authorization", value);
            }
        }

        for (k, v) in &self.headers {
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
        if let Some(expected) = &self.sha256 {
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
