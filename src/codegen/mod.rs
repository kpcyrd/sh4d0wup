pub mod c;
pub mod go;
pub mod rust;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    C,
    Go,
    Rust,
    RustNostd,
}
