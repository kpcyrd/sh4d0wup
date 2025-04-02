use crate::codegen;
use crate::errors::*;
use crate::utils;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};

const GCC_BINARY: &str = utils::compile_env!("SH4D0WUP_GCC_BINARY", "gcc");

pub async fn define_write_all(compiler: &mut Compiler) -> Result<()> {
    compiler
        .add_lines(&[
            "int write_all(int fd, char* buf, size_t count) {\n",
            "while (count > 0) {\n",
            "ssize_t n = write(fd, buf, count);\n",
            "if (n < 0) return -1;\n",
            "buf += n;\n",
            "count -= n;\n",
            "}\n",
            "return 0;\n",
            "}\n",
        ])
        .await
}

pub async fn stream_bin(orig: &[u8], stdin: &mut ChildStdin) -> Result<()> {
    debug!("Passing through binary...");
    let mut buf = String::new();
    for chunk in orig.chunks(2048) {
        buf.clear();
        codegen::escape(chunk, &mut buf)?;
        stdin.write_all(b"if (write_all(f, \"").await?;
        stdin.write_all(buf.as_bytes()).await?;
        stdin
            .write_all(format!("\", {}) != 0) exit(1);\n", chunk.len()).as_bytes())
            .await?;
    }
    Ok(())
}

pub struct Compiler {
    child: Child,
    pub stdin: ChildStdin,
}

impl Compiler {
    pub async fn spawn(out: &Path) -> Result<Self> {
        info!("Spawning C compiler...");
        let mut cmd = Command::new(GCC_BINARY);
        cmd.arg("-static")
            .arg("-s")
            .arg("-Os")
            .arg("-o")
            .arg(out)
            .arg("-xc")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        debug!(
            "Setting up process: {:?} {:?}",
            cmd.as_std().get_program(),
            cmd.as_std().get_args()
        );
        let mut child = cmd
            .spawn()
            .with_context(|| anyhow!("Failed to spawn C compiler: {GCC_BINARY:?}"))?;

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
