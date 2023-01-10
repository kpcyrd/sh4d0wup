use crate::errors::*;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};

pub fn escape(data: &[u8], out: &mut String) -> Result<()> {
    for b in data {
        write!(out, "\\x{:02x}", b)?;
    }
    Ok(())
}

pub async fn stream_bin(orig: &[u8], stdin: &mut File) -> Result<()> {
    debug!("Passing through binary...");
    let mut buf = String::new();
    for chunk in orig.chunks(2048) {
        buf.clear();
        escape(chunk, &mut buf)?;
        stdin.write_all(b"f.Write([]byte(\"").await?;
        stdin.write_all(buf.as_bytes()).await?;
        stdin.write_all(b"\"))\n").await?;
    }
    Ok(())
}

pub struct Compiler {
    pub f: File,
    out: PathBuf,
    src: PathBuf,
}

impl Compiler {
    pub async fn spawn(out: &Path, src: &Path) -> Result<Self> {
        info!("Opening file for go source code...");
        let f = File::create(src).await?;
        let compiler = Compiler {
            f,
            out: out.to_owned(),
            src: src.to_owned(),
        };
        Ok(compiler)
    }

    pub async fn add_line(&mut self, line: &str) -> Result<()> {
        debug!("Sending to compiler: {:?}", line);
        self.f.write_all(line.as_bytes()).await?;
        Ok(())
    }

    pub async fn add_lines(&mut self, lines: &[&str]) -> Result<()> {
        for line in lines {
            self.add_line(line).await?;
        }
        Ok(())
    }

    pub fn done(self) -> Result<PendingCompile> {
        info!("Spawning Go compiler...");
        let child = Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&self.out)
            .arg(&self.src)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .context("Failed to spawn Go compiler")?;
        Ok(PendingCompile { child })
    }
}

pub struct PendingCompile {
    pub child: Child,
}

impl PendingCompile {
    pub async fn wait(&mut self) -> Result<()> {
        let status = self.child.wait().await?;
        if !status.success() {
            bail!("Compile failed, compiler exited with {:?}", status);
        } else {
            Ok(())
        }
    }
}
