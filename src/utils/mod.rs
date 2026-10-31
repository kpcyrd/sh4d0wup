pub mod apk;

use crate::errors::*;
use std::borrow::Cow;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncReadExt;

// replace this with option_env!(...).unwrap_or after it became const
// https://github.com/rust-lang/rust/issues/67792
macro_rules! compile_env {
    ($key:expr, $default:expr) => {
        if let Some(val) = option_env!($key) {
            val
        } else {
            $default
        }
    };
}
pub(crate) use compile_env;

pub async fn read_input_path(path: &Path) -> Result<Vec<u8>> {
    if path.to_str() == Some("-") {
        let mut buf = Vec::new();
        tokio::io::stdin().read_to_end(&mut buf).await?;
        Ok(buf)
    } else {
        let data = tokio::fs::read(path)
            .await
            .with_context(|| anyhow!("Failed to read from path: {:?}", path))?;
        Ok(data)
    }
}

pub async fn derive_output_path<'a>(out: &'a Path, input: &Path) -> Cow<'a, Path> {
    if let Ok(md) = fs::metadata(out).await
        && md.is_dir()
        && let Some(file_name) = input.file_name()
        && !file_name.is_empty()
    {
        Cow::Owned(out.join(file_name))
    } else {
        Cow::Borrowed(out)
    }
}
