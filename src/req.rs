use crate::args;
use crate::errors::*;
use crate::plot::RouteAction;
use futures_util::StreamExt;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::io::Write;
use tokio::io::AsyncWriteExt;

pub async fn run(req: &args::Req) -> Result<()> {
    let ctx = req.plot.load_into_context().await?;

    let mut headers = HeaderMap::new();
    for header in &req.headers {
        let (k, v) = header.split_once(':').with_context(|| {
            anyhow!("Configured header has no value (missing `:`): {:?}", header)
        })?;
        let v = v.strip_prefix(' ').unwrap_or(v);
        headers.insert(
            HeaderName::from_bytes(k.as_bytes())?,
            HeaderValue::try_from(v)?,
        );
    }

    let route_action = ctx
        .plot
        .select_route(&req.req_path, req.addr.as_ref(), &headers)
        .context("Failed to select route")?;
    info!("Selected route: {:?}", route_action);

    if req.show_response || req.show_status || req.show_headers || req.show_content {
        let response = match route_action {
            RouteAction::Static(route) => route.generate_response(&ctx, &req.req_path).await?,
            _ => bail!("Emulation of this route is currently not supported"),
        };

        let mut stdout = tokio::io::stdout();
        let mut preceding_data = false;
        if req.show_response || req.show_status {
            let status = format!("{}\n", response.status());
            stdout.write_all(status.as_bytes()).await?;
            preceding_data = true;
        }
        if req.show_response || req.show_headers {
            for (k, v) in response.headers() {
                let mut buf = Vec::new();
                write!(buf, "{}: ", k)?;
                buf.extend(v.as_bytes());
                buf.push(b'\n');
                stdout.write_all(&buf).await?;
            }
            preceding_data = true;
        }
        if preceding_data {
            stdout.write_all(b"\n").await?;
        }
        if req.show_response || req.show_content {
            let mut body = response.into_body();
            while let Some(chunk) = body.next().await {
                stdout.write_all(&chunk?).await?;
            }
        }
    }
    Ok(())
}
