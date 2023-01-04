use crate::args;
use crate::codegen::c;
use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use tokio::fs::File;
use tokio::io::AsyncWrite;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Infect {
    pub exec_path: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

impl Infect {
    fn exec_path(&self) -> &str {
        self.exec_path.as_deref().unwrap_or("/bin/sh")
    }

    fn args(&self, exec_path: &str) -> Cow<Vec<String>> {
        if self.args.is_empty() {
            Cow::Owned(vec![exec_path.to_string()])
        } else {
            Cow::Borrowed(&self.args)
        }
    }
}

impl TryFrom<args::InfectElfFwdStdin> for Infect {
    type Error = Error;

    fn try_from(args: args::InfectElfFwdStdin) -> Result<Self> {
        Ok(Infect {
            exec_path: args.exec,
            args: args.args,
        })
    }
}

pub async fn infect<W: AsyncWrite + Unpin>(
    config: &Infect,
    orig: &[u8],
    out: &mut W,
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin_path = dir.path().join("bin");

    let mut compiler = c::Compiler::spawn(&bin_path).await?;

    info!("Generating source code...");
    let exec_path = config.exec_path();

    let mut args = String::from("char *args[]={");
    for arg in config.args(exec_path).iter() {
        args.push('"');
        c::escape(arg.as_bytes(), &mut args)?;
        args.push_str("\", ");
    }
    args.push_str("NULL};\n");

    let mut exec_path_escaped = String::new();
    c::escape(exec_path.as_bytes(), &mut exec_path_escaped)?;

    compiler
        .add_lines(&[
            "#define _GNU_SOURCE\n",
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "#include <unistd.h>\n",
            "#include <sys/wait.h>\n",
            "int main(int argc, char** argv) {\n",
            "int pipefd[2];\n",
            "pipe(pipefd);\n",
            "pid_t c = fork();\n",
            "if (c) goto fwd;\n",
            "close(pipefd[1]);\n",
            "if (dup2(pipefd[0], STDIN_FILENO) == -1) return 1;\n",
            &args,
            &format!("execve(\"{}\", args, environ);\n", exec_path_escaped),
            "exit(0);\n",
            "fwd:\n",
            "close(pipefd[0]);\n",
            "int f = pipefd[1];\n",
        ])
        .await?;

    c::stream_bin(orig, &mut compiler.stdin).await?;
    compiler
        .add_lines(&[
            "close(pipefd[1]);\n",
            "if (c == -1) return 1;\n",
            "int wstatus;\n",
            "do {\n",
            "if (waitpid(c, &wstatus, 0) == -1) return 1;\n",
            "} while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));\n",
            "exit(0);\n",
            "}\n",
        ])
        .await?;

    let mut pending = compiler.done();
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    debug!("Copying compiled binary to final destination");
    let mut f = File::open(&bin_path)
        .await
        .with_context(|| anyhow!("Failed to open compiled binary at {:?}", bin_path))?;
    tokio::io::copy(&mut f, out).await?;

    info!("Successfully generated binary");

    Ok(())
}
