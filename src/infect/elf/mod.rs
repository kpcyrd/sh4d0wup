pub mod c;

use crate::args;
use crate::codegen::{self, Backend};
use crate::errors::*;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncWrite;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload<'a> {
    Shell(&'a str),
    Elf(&'a [u8]),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Infect {
    pub backend: Option<codegen::Backend>,
    pub payload: Option<String>,
    #[serde(default)]
    pub self_replace: bool,
    pub assume_path: Option<String>,
}

impl TryFrom<args::InfectElf> for Infect {
    type Error = Error;

    fn try_from(args: args::InfectElf) -> Result<Self> {
        Ok(Infect {
            backend: args.compile.backend,
            payload: args.payload,
            self_replace: args.self_replace,
            assume_path: args.assume_path,
        })
    }
}

pub async fn infect<W: AsyncWrite + Unpin>(
    config: &Infect,
    orig: &[u8],
    elf_payload: Option<&[u8]>,
    out: &mut W,
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bin");

    let payload = if let Some(elf) = elf_payload {
        Some(Payload::Elf(elf))
    } else {
        config
            .payload
            .as_ref()
            .map(|payload| Payload::Shell(payload))
    };

    match config.backend {
        Some(Backend::C) | None => c::infect(&bin, config, orig, payload.as_ref()).await?,
        _ => bail!("Backend is not implemented yet"),
    }

    debug!("Copying compiled binary to final destination");
    let mut f = File::open(&bin)
        .await
        .with_context(|| anyhow!("Failed to open compiled binary at {:?}", bin))?;
    tokio::io::copy(&mut f, out).await?;

    info!("Successfully generated binary");

    Ok(())
}
