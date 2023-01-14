use crate::errors::*;
use crate::upstream;
use http::Method;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sessions {}

impl Sessions {
    pub async fn create_oci_auth_session(&mut self, auth: &OciAuth) -> Result<Option<String>> {
        let auth_resp = upstream::send_req(Method::GET, auth.url.clone(), None, false).await?;
        if let Some(www_auth) = auth_resp.headers().get("Www-Authenticate") {
            let www_auth = www_auth
                .to_str()
                .context("Www-Authenticate header contains invalid utf-8")?;
            let www_auth = www_auth
                .parse::<WwwAuthenticate>()
                .context("Failed to parse Www-Authenticate header")?;
            trace!("Got Www-Authenticate header: {:?}", www_auth);

            let realm = www_auth
                .realm
                .context("Missing realm in Www-Authenticate header")?;
            let service = www_auth
                .service
                .context("Missing service in Www-Authenticate header")?;
            let mut realm_url = realm
                .parse::<Url>()
                .context("Failed to parse realm into url")?;

            if !auth.scopes.is_empty() {
                let scopes = auth.scopes.join(" ");
                realm_url.query_pairs_mut().append_pair("scope", &scopes);
            }
            realm_url.query_pairs_mut().append_pair("service", &service);

            let resp = upstream::send_req(Method::GET, realm_url, None, false)
                .await?
                .error_for_status()?
                .json::<TokenResponse>()
                .await?;

            Ok(Some(resp.token))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciAuth {
    pub url: Url,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WwwAuthenticate {
    realm: Option<String>,
    service: Option<String>,
    scope: Option<String>,
}

impl FromStr for WwwAuthenticate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut s = s
            .strip_prefix("Bearer ")
            .context("Www-Authenticate header is expected to start with `Bearer `")?;
        let mut www = WwwAuthenticate::default();
        while !s.is_empty() {
            let idx = s.find("=\"").context("Failed to find end of key")?;
            let key = &s[..idx];
            let remaining = &s[idx + 2..];

            let idx = remaining
                .find('\"')
                .context("Failed to find end of value")?;
            let value = &remaining[..idx];
            let remaining = &remaining[idx + 1..];

            match key {
                "realm" => www.realm = Some(value.to_string()),
                "service" => www.service = Some(value.to_string()),
                "scope" => www.scope = Some(value.to_string()),
                _ => debug!("Skipping unknown Www-Authenticate header: {:?}", key),
            }

            s = remaining.strip_prefix(',').unwrap_or(remaining);
        }
        Ok(www)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_www_authenticate() -> Result<()> {
        let header = "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:user/image:pull\"";
        let parsed = header.parse::<WwwAuthenticate>()?;
        assert_eq!(
            parsed,
            WwwAuthenticate {
                realm: Some("https://ghcr.io/token".to_string()),
                service: Some("ghcr.io".to_string()),
                scope: Some("repository:user/image:pull".to_string()),
            }
        );
        Ok(())
    }
}
