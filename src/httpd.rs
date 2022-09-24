use crate::errors::*;
use crate::pacman;
use crate::plot::{PatchPacmanDbRoute, Plot, ProxyRoute, RouteAction, StaticRoute};
use crate::upstream;
use http::Method;
use http::{HeaderMap, HeaderValue};
use std::fmt::Write;
use std::net::SocketAddr;
use warp::path::FullPath;
use warp::{hyper::body::Bytes, Filter, Rejection, Reply};
use warp_reverse_proxy::extract_request_data_filter;
use warp_reverse_proxy::proxy_to_and_forward_response;
use warp_reverse_proxy::QueryParameters;

#[derive(Debug)]
struct HttpError(Error);

impl warp::reject::Reject for HttpError {}

fn http_error<I: Into<Error>>(err: I) -> HttpError {
    HttpError(err.into())
}

pub mod log {
    use super::*;

    #[derive(Debug, Default)]
    pub struct Fields(String);

    impl Fields {
        fn append_header(self, headers: &HeaderMap, key: &str) -> Self {
            self.append(key, headers.get(key))
        }

        fn append<T: std::fmt::Debug>(mut self, key: &str, value: Option<T>) -> Self {
            if let Some(value) = value {
                write!(self.0, " {}={:?}", key, value).ok();
            }
            self
        }

        fn into_string(self) -> String {
            self.0
        }
    }

    pub fn log_request(method: &Method, uri: &FullPath, headers: &HeaderMap) {
        let fields = Fields::default()
            .append_header(headers, "host")
            .append_header(headers, "user-agent")
            .append_header(headers, "if-match")
            .append_header(headers, "if-modified-since")
            .into_string();
        info!("Received: {:?} {:?}{}", method, uri, fields);
    }

    pub async fn log_response(
        uri: String,
        response: http::Response<Bytes>,
    ) -> Result<impl Reply, Rejection> {
        let headers = response.headers();
        let fields = Fields::default()
            .append_header(headers, "location")
            .append_header(headers, "etag")
            .append_header(headers, "last-modified")
            .into_string();
        info!(
            "Sending: {:?} {:?} - bytes={:?}{}",
            uri,
            response.status(),
            response.body().len(),
            fields,
        );
        debug!("Response headers: {:?}", headers);
        trace!("Sending response: {:?}", response);
        Ok(response)
    }
}

async fn proxy_forward_request(
    // response: reqwest::Response,
    args: &ProxyRoute,
    plot: &Plot,
    uri: FullPath,
    params: QueryParameters,
    method: Method,
    mut headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let upstream = plot
        .upstreams
        .get(&args.upstream)
        .context("Reference to undefined upstream")
        .map_err(http_error)?;

    let upstream_host = upstream.url.origin().unicode_serialization();

    if upstream.keep_headers {
        debug!("Not modifying headers due to keep_headers=true");
    } else {
        for (key, value) in &mut headers {
            if key == "host" {
                // this is a hacky solution
                let v = upstream_host
                    .rsplit_once('/')
                    .map(|(_, x)| x)
                    .unwrap_or(&upstream_host);
                *value = HeaderValue::from_str(v).map_err(http_error)?;
                debug!("Updating host header to {:?}", value);
            }
        }
    }

    let base_path = String::new();
    debug!("Sending request upstream to {:?}", upstream.url.to_string());
    proxy_to_and_forward_response(
        upstream.url.to_string(),
        base_path,
        uri,
        params,
        method,
        headers,
        body,
    )
    .await
}

async fn generate_static_response(
    // response: reqwest::Response,
    args: &StaticRoute,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let mut builder = http::Response::builder().status(200);

    if let Some(value) = &args.content_type {
        builder = builder.header("Content-Type", value);
    }

    Ok(builder
        .body(Bytes::from(args.data.as_bytes().to_vec()))
        .unwrap())
}

async fn patch_pacman_db_response(
    args: &PatchPacmanDbRoute,
    plot: &Plot,
    uri: FullPath,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let upstream = plot
        .upstreams
        .get(&args.upstream)
        .context("Reference to undefined upstream")
        .map_err(http_error)?;

    // debug!("upstream={:?}", upstream);
    // debug!("args={:?}", args);
    let path = args.path.as_deref().unwrap_or(uri.as_str());

    let url = upstream
        .url
        .join(path)
        .context("Failed to join urls")
        .map_err(http_error)?;

    let response = upstream::send_req(Method::GET, url)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;
    // debug!("bytes: {:?}", bytes);

    let response = pacman::modify_response(args, &bytes).map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(response)
        .unwrap())
}

async fn serve_request(
    plot: Plot,
    uri: FullPath,
    params: QueryParameters,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<(String, http::Response<Bytes>), Rejection> {
    log::log_request(&method, &uri, &headers);

    let route_action = plot
        .select_route(uri.as_str())
        .context("Failed to select route")
        .map_err(http_error)?;

    let path = uri.as_str().to_string();
    let response = match route_action {
        RouteAction::Proxy(args) => {
            proxy_forward_request(args, &plot, uri, params, method, headers, body).await?
        }
        RouteAction::Static(args) => generate_static_response(args).await?,
        RouteAction::PatchPacmanDbRoute(args) => patch_pacman_db_response(args, &plot, uri).await?,
    };

    Ok((path, response))
}

pub async fn run(bind: SocketAddr, plot: Plot) -> Result<()> {
    let request_filter = extract_request_data_filter();

    let app = warp::any()
        .and(request_filter)
        .and_then(
            move |uri: FullPath,
                  params: QueryParameters,
                  method: Method,
                  headers: HeaderMap,
                  body: Bytes| {
                serve_request(plot.clone(), uri, params, method, headers, body)
            },
        )
        .untuple_one()
        .and_then(log::log_response);

    // spawn proxy server
    info!("Binding to {:?}...", bind);
    warp::serve(app).run(bind).await;

    Ok(())
}
