pub mod c;
pub mod go;
pub mod rust;

use crate::args;
use crate::codegen;
use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use tokio::fs::File;
use tokio::io::AsyncWrite;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Infect {
    pub backend: Option<codegen::Backend>,
    pub exec_path: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

impl Infect {
    fn exec_path(&self) -> &str {
        self.exec_path.as_deref().unwrap_or("/bin/sh")
    }

    fn args(&self, exec_path: &str) -> Cow<Vec<String>> {
        if self.args.is_empty() {
            Cow::Owned(vec![exec_path.to_string()])
        } else {
            Cow::Borrowed(&self.args)
        }
    }
}

impl TryFrom<args::InfectElfFwdStdin> for Infect {
    type Error = Error;

    fn try_from(args: args::InfectElfFwdStdin) -> Result<Self> {
        Ok(Infect {
            backend: args.compile.backend,
            exec_path: args.exec,
            args: args.args,
        })
    }
}

pub async fn infect<W: AsyncWrite + Unpin>(
    config: &Infect,
    orig: &[u8],
    out: &mut W,
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin_path = dir.path().join("bin");

    match config.backend {
        Some(codegen::Backend::C) | None => c::infect(&bin_path, config, orig).await?,
        Some(codegen::Backend::Rust) => rust::infect(&bin_path, config, orig).await?,
        Some(codegen::Backend::Go) => {
            // go needs an extra file for source code
            let src_path = dir.path().join("src.go");
            go::infect(&bin_path, &src_path, config, orig).await?
        }
    }

    debug!("Copying compiled binary to final destination");
    let mut f = File::open(&bin_path)
        .await
        .with_context(|| anyhow!("Failed to open compiled binary at {:?}", bin_path))?;
    tokio::io::copy(&mut f, out).await?;

    info!("Successfully generated binary");

    Ok(())
}
