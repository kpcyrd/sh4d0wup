use crate::artifacts::Artifact;
use crate::errors::*;
use crate::keygen::tls;
use crate::plot::{
    self, OciRegistryManifest, PatchAptReleaseRoute, PatchPkgDatabaseRoute, Plot, PlotExtras,
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
use tokio::fs;
use warp::path::FullPath;
use warp::{hyper::body::Bytes, Filter, Rejection, Reply};
use warp_reverse_proxy::extract_request_data_filter;
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

    let mut url = upstream.url.clone();
    if let Some(path) = &args.path {
        url.set_path(path);
    } else {
        url.set_path(uri.as_str());
    };
    let proxy_uri = url.to_string();

    debug!("Sending request upstream to {:?}", &proxy_uri);
    proxy_to_and_forward_response(proxy_uri, uri, params, method, headers, body).await
}

async fn generate_static_response(
    args: &StaticRoute,
    plot: &Plot,
    plot_extras: &PlotExtras,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let status = args.status.unwrap_or(200);
    let mut builder = http::Response::builder().status(status);

    if let Some(value) = &args.content_type {
        builder = builder.header("Content-Type", value);
    }

    for (key, value) in &args.headers {
        builder = builder.header(key, value);
    }

    let data = if let Some(data) = &args.data {
        data.as_bytes().to_vec()
    } else if let Some(artifact) = &args.artifact {
        let config = plot
            .artifacts
            .get(artifact)
            .with_context(|| anyhow!("Undefined reference to artifact object: {:?}", artifact))
            .map_err(http_error)?;

        match config {
            Artifact::Path(artifact) => fs::read(&artifact.path).await.map_err(http_error)?,
            Artifact::Url(_) => {
                return Err(http_error(anyhow!(
                    "Url artifacts are expected to be loaded into memory at this point"
                ))
                .into())
            }
            Artifact::Inline(_) => {
                return Err(http_error(anyhow!(
                    "Inline artifacts are expected to be loaded into memory at this point"
                ))
                .into())
            }
            Artifact::Memory => plot_extras
                .artifacts
                .get(artifact)
                .with_context(|| anyhow!("Undefined reference to artifact object: {:?}", artifact))
                .map_err(http_error)?
                .clone(),
        }
    } else {
        return Err(http_error(anyhow!("No data or artifact configured for static route")).into());
    };

    Ok(builder.body(Bytes::from(data)).unwrap())
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

    let response = upstream::send_req(Method::GET, url).await?;

    Ok(response)
}

async fn patch_pacman_db_response(
    args: &PatchPkgDatabaseRoute,
    plot: &Plot,
    uri: FullPath,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let response = fetch_upstream(&args.proxy, plot, uri)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;
    let response = pacman::modify_response(&args.config, &bytes).map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(response)
        .unwrap())
}

async fn patch_apt_release_response(
    args: &PatchAptReleaseRoute,
    plot: &Plot,
    plot_extras: &PlotExtras,
    uri: FullPath,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let response = fetch_upstream(&args.proxy, plot, uri)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;
    let response = apt_release::modify_response(&args.config, &plot_extras.signing_keys, &bytes)
        .map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(response)
        .unwrap())
}

async fn patch_apt_package_list_response(
    args: &PatchPkgDatabaseRoute,
    plot: &Plot,
    uri: FullPath,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let response = fetch_upstream(&args.proxy, plot, uri)
        .await
        .map_err(http_error)?;

    let bytes = response.bytes().await.map_err(http_error)?;

    let response = apt_package_list::modify_response(&args.config, &bytes).map_err(http_error)?;

    Ok(http::Response::builder()
        .status(200)
        .body(response)
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
    args: &OciRegistryManifest,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
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
        .body(Bytes::from(buf))
        .unwrap())
}

async fn append_response(
    args: &plot::Append,
    plot: &Plot,
    uri: FullPath,
) -> std::result::Result<http::Response<Bytes>, Rejection> {
    let mut response = fetch_upstream(&args.proxy, plot, uri)
        .await
        .map_err(http_error)?;

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http_error)? {
        body.extend(&chunk);
    }
    body.extend(args.data.as_bytes());
    let body = Bytes::from(body);

    Ok(http::Response::builder()
        .status(response.status())
        .body(body)
        .unwrap())
}

async fn serve_request(
    ctx: Arc<plot::Ctx>,
    uri: FullPath,
    params: QueryParameters,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<(String, http::Response<Bytes>), Rejection> {
    log::log_request(&method, &uri, &headers);

    let route_action = ctx
        .plot
        .select_route(uri.as_str())
        .context("Failed to select route")
        .map_err(http_error)?;

    let path = uri.as_str().to_string();
    let response = match route_action {
        RouteAction::Proxy(args) => {
            proxy_forward_request(args, &ctx.plot, uri, params, method, headers, body).await?
        }
        RouteAction::Static(args) => generate_static_response(args, &ctx.plot, &ctx.extras).await?,
        RouteAction::PatchPacmanDbRoute(args) => {
            patch_pacman_db_response(args, &ctx.plot, uri).await?
        }
        RouteAction::PatchAptRelease(args) => {
            patch_apt_release_response(args, &ctx.plot, &ctx.extras, uri).await?
        }
        RouteAction::PatchAptPackageList(args) => {
            patch_apt_package_list_response(args, &ctx.plot, uri).await?
        }
        RouteAction::OciRegistryManifest(args) => {
            generate_oci_registry_manifest_response(args).await?
        }
        RouteAction::Append(args) => append_response(args, &ctx.plot, uri).await?,
    };

    Ok((path, response))
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

pub async fn run(bind: SocketAddr, tls: Option<Tls>, ctx: plot::Ctx) -> Result<()> {
    let request_filter = extract_request_data_filter();

    let ctx = Arc::new(ctx);
    let app = warp::any()
        .and(request_filter)
        .and_then(
            move |uri: FullPath,
                  params: QueryParameters,
                  method: Method,
                  headers: HeaderMap,
                  body: Bytes| {
                serve_request(ctx.clone(), uri, params, method, headers, body)
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
