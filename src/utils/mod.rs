pub mod apk;

use crate::errors::*;
use std::path::Path;
use tokio::io::AsyncReadExt;

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
