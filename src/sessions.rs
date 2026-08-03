use crate::errors::*;
use crate::upstream;
use http::Method;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;
use www_authenticate_parser::Challenge;

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
        let (scheme, challenge) = www_authenticate_parser::parse_header(s)
            .map_err(|err| anyhow!("Failed to parse Www-Authenticate header: {err:#}"))?;

        if scheme.as_ref() != "Bearer" {
            bail!("Www-Authenticate header is expected to start with `Bearer `")
        }

        let mut www = WwwAuthenticate::default();

        match challenge {
            Challenge::Token68(_) => bail!("Www-Authenticate Bearer token is not supported"),
            Challenge::Fields(mut fields) => {
                www.realm = fields.remove("realm");
                www.service = fields.remove("service");
                www.scope = fields.remove("scope");
            }
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
    fn test_parse_www_authenticate_ghcr() -> Result<()> {
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

    #[test]
    fn test_parse_www_authenticate_gcr() -> Result<()> {
        let header = "Bearer realm=\"https://gcr.io/v2/token\",service=gcr.io";
        let parsed = header.parse::<WwwAuthenticate>()?;
        assert_eq!(
            parsed,
            WwwAuthenticate {
                realm: Some("https://gcr.io/v2/token".to_string()),
                service: Some("gcr.io".to_string()),
                scope: None,
            }
        );
        Ok(())
    }
}
