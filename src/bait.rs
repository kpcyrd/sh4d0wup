use crate::args;
use crate::errors::*;
use crate::httpd;
use crate::plot::Ctx;
use tokio::fs;
use std::sync::Arc;

pub async fn run(ctx: Ctx, bind: &args::Bind, tls: &args::Tls) -> Result<()> {
    let tls = if let Some(path) = &tls.cert {
        let cert = fs::read(path).await
            .with_context(|| anyhow!("Failed to read certificate from path: {:?}", path))?;

        let key = if let Some(path) = &tls.key {
            fs::read(path).await
                .with_context(|| anyhow!("Failed to read certificate from path: {:?}", path))?
        } else {
            cert.clone()
        };

        Some(httpd::Tls { cert, key })
    } else if let Some(tls) = ctx.plot.tls.clone() {
        Some(httpd::Tls::try_from(tls)?)
    } else {
        None
    };

    if !bind.no_bind {
        httpd::run(bind.addr, tls, Arc::new(ctx)).await?;
    }

    Ok(())
}
