use crate::args;
use crate::errors::*;
use crate::plot::RouteAction;
use futures_util::StreamExt;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::io::Write;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

pub struct Hexdumper {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
}

impl Hexdumper {
    pub fn spawn() -> Result<Self> {
        let mut child = tokio::process::Command::new("hexdump")
            .arg("-C")
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to spawn hexdump process")?;
        let stdin = child.stdin.take().unwrap();
        Ok(Self { child, stdin })
    }
}

pub enum OutputWriter {
    Stdout(tokio::io::Stdout),
    Hexdump(Hexdumper),
}

impl OutputWriter {
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            OutputWriter::Stdout(stdout) => stdout.write_all(buf).await?,
            OutputWriter::Hexdump(hexdump) => hexdump.stdin.write_all(buf).await?,
        }
        Ok(())
    }

    pub async fn wait(self) -> Result<()> {
        match self {
            OutputWriter::Stdout(_) => Ok(()),
            OutputWriter::Hexdump(mut hexdump) => {
                drop(hexdump.stdin);
                hexdump.child.wait().await?;
                Ok(())
            }
        }
    }
}

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
        .select_route(
            &req.req_path,
            req.addr.as_ref(),
            req.authority.as_ref(),
            &headers,
        )
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
            let mut out = if req.hexdump {
                OutputWriter::Hexdump(Hexdumper::spawn()?)
            } else {
                OutputWriter::Stdout(stdout)
            };
            while let Some(chunk) = body.next().await {
                out.write_all(&chunk?).await?;
            }
        }
    }
    Ok(())
}
