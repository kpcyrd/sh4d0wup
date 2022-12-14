use crate::errors::*;
use std::fmt::Write;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};

pub fn escape(data: &[u8], out: &mut String) -> Result<()> {
    for b in data {
        write!(out, "\\x{:02x}", b)?;
    }
    Ok(())
}

pub async fn stream_bin(orig: &[u8], stdin: &mut ChildStdin) -> Result<()> {
    debug!("Passing through binary...");
    let mut buf = String::new();
    for chunk in orig.chunks(2048) {
        buf.clear();
        escape(chunk, &mut buf)?;
        stdin.write_all(b"if f.write_all(b\"").await?;
        stdin.write_all(buf.as_bytes()).await?;
        stdin.write_all(b"\").is_err() { exit(1) };\n").await?;
    }
    Ok(())
}

pub struct Compiler {
    child: Child,
    pub stdin: ChildStdin,
}

impl Compiler {
    pub async fn spawn(out: &Path) -> Result<Self> {
        info!("Spawning Rust compiler...");
        let mut child = Command::new("rustc")
            .arg("-Cpanic=abort")
            .arg("-Cstrip=symbols")
            .arg("--target=x86_64-unknown-linux-musl")
            .arg("-o")
            .arg(out)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("Failed to spawn Rust compiler")?;

        let stdin = child.stdin.take().unwrap();
        let compiler = Compiler { child, stdin };

        Ok(compiler)
    }

    pub async fn add_line(&mut self, line: &str) -> Result<()> {
        debug!("Sending to compiler: {:?}", line);
        self.stdin.write_all(line.as_bytes()).await?;
        Ok(())
    }

    pub async fn add_lines(&mut self, lines: &[&str]) -> Result<()> {
        for line in lines {
            self.add_line(line).await?;
        }
        Ok(())
    }

    pub fn done(self) -> PendingCompile {
        PendingCompile { child: self.child }
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
