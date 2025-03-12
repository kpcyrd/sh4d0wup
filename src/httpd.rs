use crate::errors::*;
use crate::infect;
use crate::keygen::tls;
use crate::plot::{
    self, Ctx, OciRegistryManifestRoute, PatchAptReleaseRoute, PatchPkgDatabaseRoute, Plot,
    ProxyRoute, RouteAction, StaticRoute,
};
use crate::tamper::{apt_package_list, apt_release, pacman};
use crate::upstream;
use crate::upstream::proxy_to_and_forward_response;
use http::Method;
use http::{HeaderMap, HeaderValue};
use serde::Serialize;
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::host::Authority;
use warp::hyper::Body;
use warp::hyper::body::HttpBody;
use warp::path::FullPath;
use warp::{Filter, Rejection, Reply, hyper::body::Bytes};
use warp_reverse_proxy::QueryParameters;
use warp_reverse_proxy::extract_request_data_filter;

#[derive(Debug)]
struct HttpError;

impl warp::reject::Reject for HttpError {}

fn http_error<I: Into<Error>>(err: I) -> HttpError {
    let err = err.into();
    error!("Request has caused an error: {err:#}");
    HttpError
}

pub mod log {
    use super::*;

    #[derive(Debug, Default)]
    pub struct Fields(String);

    impl Fields {
        fn append_header(self, headers: &HeaderMap, key: &str) -> Self {
            self.append(key, headers.get(key))
        }

        fn append_authority(self, authority: Option<&Authority>) -> Self {
            self.append("host", authority.map(Authority::as_str))
        }

        fn append<T: std::fmt::Debug>(mut self, key: &str, value: Option<T>) -> Self {
            if let Some(value) = value {
                write!(self.0, " {key}={value:?}").ok();
            }
            self
        }

        fn into_string(self) -> String {
            self.0
        }
    }

    pub fn url_to_string(uri: &FullPath, params: &QueryParameters) -> String {
        let mut url = uri.as_str().to_string();
        if let Some(query) = params {
            write!(url, "?{query}").ok();
        }
        url
    }

    pub fn log_request(
        method: &Method,
        authority: Option<&Authority>,
        url: &str,
        headers: &HeaderMap,
    ) {
        let fields = Fields::default()
            .append_authority(authority)
            .append_header(headers, "user-agent")
            .append_header(headers, "if-match")
            .append_header(headers, "if-modified-since")
            .into_string();
        info!("Received: {:?} {:?}{}", method, url, fields);
    }

    pub async fn log_response(
        url: String,
        response: http::Response<Body>,
    ) -> Result<impl Reply, Rejection> {
        let headers = response.headers();
        let size = response.body().size_hint().exact();
        let fields = Fields::default()
            .append("bytes", size)
            .append_header(headers, "content-length")
            .append_header(headers, "location")
            .append_header(headers, "etag")
            .append_header(headers, "last-modified")
            .into_string();
        info!("Sending: {:?} {:?} -{}", url, response.status(), fields);
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
) -> Result<http::Response<Body>, Rejection> {
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
                trace!("Updating host header to {:?}", value);
            }
        }
    }

    let mut url = upstream.url.clone();
    if let Some(path) = &args.path {
        url.set_path(path);
    } else {
        url.set_path(uri.as_str());
    };
    let proxy_uri = url.to_string();

    debug!(
        "Sending request upstream to {:?}, headers={:?}",
        &proxy_uri, headers
    );
    proxy_to_and_forward_response(proxy_uri, uri, params, method, headers, body).await
}

async fn generate_static_response(
    args: &StaticRoute,
    ctx: &Ctx,
    uri: FullPath,
) -> Result<http::Response<Body>, Rejection> {
    Ok(args
        .generate_response(ctx, uri.as_str())
        .await
        .map_err(http_error)?)
}

async fn fetch_upstream(
    proxy: &ProxyRoute,
    plot: &Plot,
    uri: FullPath,
) -> Result<reqwest::Response> {
    let upstream = plot
        .upstreams
        .get(&proxy.upstream)
        .context("Reference to undefined upstream")?;

    let path = proxy.path.as_deref().unwrap_or(uri.as_str());

    let url = upstream.url.join(path).context("Failed to join urls")?;

    let response = upstream::send_req(Method::GET, url, None, false).await?;

    Ok(response)
}

async fn patch_pacman_db_response(
    args: &PatchPkgDatabaseRoute,
    ctx: &Ctx,
    uri: FullPath,
) -> Result<http::Response<Body>, Rejection> {
    let response = fetch_upstream(&args.proxy, &ctx.plot, uri)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;
    let response =
        pacman::modify_response(&args.config, &ctx.extras, &bytes).map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(Body::from(response))
        .unwrap())
}

async fn patch_apt_release_response(
    args: &PatchAptReleaseRoute,
    ctx: &Ctx,
    uri: FullPath,
) -> Result<http::Response<Body>, Rejection> {
    let response = fetch_upstream(&args.proxy, &ctx.plot, uri)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;
    let response =
        apt_release::modify_response(&args.config, &ctx.extras, &bytes).map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(Body::from(response))
        .unwrap())
}

async fn patch_apt_package_list_response(
    args: &PatchPkgDatabaseRoute,
    ctx: &Ctx,
    uri: FullPath,
) -> Result<http::Response<Body>, Rejection> {
    let response = fetch_upstream(&args.proxy, &ctx.plot, uri)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;

    let response = apt_package_list::modify_response(&args.config, &ctx.extras.artifacts, &bytes)
        .map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(Body::from(response))
        .unwrap())
}

#[derive(Debug, Serialize)]
pub struct OciFsLayer {
    #[serde(rename = "blobSum")]
    pub blob_sum: String,
}

#[derive(Debug, Serialize)]
pub struct OciRegistryManifestResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    name: String,
    tag: String,
    architecture: String,
    #[serde(rename = "fsLayers")]
    fs_layers: Vec<OciFsLayer>,
    signatures: Vec<serde_json::Value>,
}

async fn generate_oci_registry_manifest_response(
    args: &OciRegistryManifestRoute,
) -> Result<http::Response<Body>, Rejection> {
    let response = OciRegistryManifestResponse {
        schema_version: 1,
        name: args.name.clone(),
        tag: args.tag.clone(),
        architecture: args.architecture.clone(),
        fs_layers: args
            .fs_layers
            .iter()
            .cloned()
            .map(|blob_sum| OciFsLayer { blob_sum })
            .collect(),
        signatures: args.signatures.clone(),
    };

    let buf = serde_json::to_vec(&response).map_err(http_error)?;
    Ok(http::Response::builder()
        .status(200)
        .header(
            "content-type",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .header("docker-content-digest", &args.content_digest)
        .header("docker-distribution-api-version", "registry/2.0")
        .header("etag", format!("\"{}\"", args.content_digest))
        .header("x-content-type-options", "nosniff")
        .body(Body::from(buf))
        .unwrap())
}

async fn append_response(
    args: &plot::AppendRoute,
    plot: &Plot,
    uri: FullPath,
) -> Result<http::Response<Body>, Rejection> {
    let mut response = fetch_upstream(&args.proxy, plot, uri)
        .await
        .map_err(http_error)?;

    // TODO: rewrite to stream, then use Body::wrap_stream
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http_error)? {
        body.extend(&chunk);
    }
    body.extend(args.data.as_bytes());

    Ok(http::Response::builder()
        .status(response.status())
        .body(Body::from(body))
        .unwrap())
}

async fn patch_shell_response(
    args: &plot::PatchShellRoute,
    plot: &Plot,
    uri: FullPath,
) -> Result<http::Response<Body>, Rejection> {
    let response = fetch_upstream(&args.proxy, plot, uri)
        .await
        .map_err(http_error)?;

    let status = response.status();
    let body = response.bytes().await.map_err(http_error)?;

    let mut out = Vec::new();
    infect::sh::infect(&args.infect, &body, &mut out)
        .await
        .map_err(http_error)?;

    Ok(http::Response::builder()
        .status(status)
        .body(Body::from(out))
        .unwrap())
}

struct Request {
    addr: Option<SocketAddr>,
    authority: Option<Authority>,
    uri: FullPath,
    params: QueryParameters,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
}

async fn serve_request(
    ctx: Arc<plot::Ctx>,
    req: Request,
) -> Result<(String, http::Response<Body>), Rejection> {
    let url = log::url_to_string(&req.uri, &req.params);

    log::log_request(&req.method, req.authority.as_ref(), &url, &req.headers);

    let route_action = ctx
        .plot
        .select_route(
            req.uri.as_str(),
            req.addr.map(|a| a.ip()).as_ref(),
            req.authority.as_ref(),
            &req.headers,
        )
        .context("Failed to select route")
        .map_err(http_error)?;

    let response = match route_action {
        RouteAction::Proxy(args) => {
            proxy_forward_request(
                args,
                &ctx.plot,
                req.uri,
                req.params,
                req.method,
                req.headers,
                req.body,
            )
            .await?
        }
        RouteAction::Static(args) => generate_static_response(args, &ctx, req.uri).await?,
        RouteAction::PatchPacmanDb(args) => patch_pacman_db_response(args, &ctx, req.uri).await?,
        RouteAction::PatchAptRelease(args) => {
            patch_apt_release_response(args, &ctx, req.uri).await?
        }
        RouteAction::PatchAptPackageList(args) => {
            patch_apt_package_list_response(args, &ctx, req.uri).await?
        }
        RouteAction::OciRegistryManifest(args) => {
            generate_oci_registry_manifest_response(args).await?
        }
        RouteAction::Append(args) => append_response(args, &ctx.plot, req.uri).await?,
        RouteAction::PatchShell(args) => patch_shell_response(args, &ctx.plot, req.uri).await?,
    };

    Ok((url, response))
}

#[derive(Debug, Clone)]
pub struct Tls {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl TryFrom<tls::KeygenTls> for Tls {
    type Error = Error;

    fn try_from(tls: tls::KeygenTls) -> Result<Self> {
        match tls {
            tls::KeygenTls::Embedded(embedded) => Ok(Self::from(embedded)),
            tls::KeygenTls::Generate(generate) => {
                let tls = tls::generate(generate)?;
                Ok(tls.into())
            }
        }
    }
}

impl From<tls::TlsEmbedded> for Tls {
    fn from(tls: tls::TlsEmbedded) -> Self {
        Tls {
            cert: tls.cert.into_bytes(),
            key: tls.key.into_bytes(),
        }
    }
}

pub async fn run(bind: SocketAddr, tls: Option<Tls>, ctx: Arc<plot::Ctx>) -> Result<()> {
    let request_filter = extract_request_data_filter();

    let app = warp::any()
        .and(warp::filters::addr::remote())
        .and(warp::host::optional())
        .and(request_filter)
        .and_then(
            move |addr: Option<SocketAddr>,
                  authority: Option<Authority>,
                  uri: FullPath,
                  params: QueryParameters,
                  method: Method,
                  headers: HeaderMap,
                  body: Bytes| {
                serve_request(
                    ctx.clone(),
                    Request {
                        addr,
                        authority,
                        uri,
                        params,
                        method,
                        headers,
                        body,
                    },
                )
            },
        )
        .untuple_one()
        .and_then(log::log_response);

    // spawn proxy server
    let server = warp::serve(app);
    info!("Binding to {:?}...", bind);
    if let Some(tls) = tls {
        server.tls().cert(tls.cert).key(tls.key).run(bind).await;
    } else {
        server.run(bind).await;
    }

    Ok(())
}
