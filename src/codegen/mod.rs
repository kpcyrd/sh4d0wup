pub mod c;
pub mod go;
pub mod rust;

use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    C,
    Go,
    Rust,
    RustNostd,
}

pub fn escape(data: &[u8], out: &mut String) -> Result<()> {
    for b in data {
        write!(out, "\\x{b:02x}")?;
    }
    Ok(())
}
