use crate::errors::*;
use http::Method;
use once_cell::sync::OnceCell;
use reqwest::redirect::Policy;
use url::Url;

pub static CLIENT: OnceCell<reqwest::Client> = OnceCell::new();

fn default_reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("Default reqwest client couldn't build")
}

pub async fn send_req(method: Method, url: Url) -> Result<reqwest::Response> {
    debug!("Sending request to {:?}", url.to_string());
    let response = CLIENT
        .get_or_init(default_reqwest_client)
        .request(method, url)
        .send()
        .await?;

    trace!("Upstream http response: {:?}", response);
    debug!(
        "Upstream response: {:?} {:?} - bytes={:?} etag={:?}",
        response.url().to_string(),
        response.status(),
        response.headers().get("content-length"),
        response.headers().get("etag")
    );

    Ok(response)
}
