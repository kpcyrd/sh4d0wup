#![allow(non_upper_case_globals)]
#![allow(clippy::too_many_arguments)]

use crate::errors::*;
use std::fmt::Write;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};

const SIGCHLD: u64 = 17;

const __NR_write: u64 = 1;
const __NR_close: u64 = 3;
const __NR_pipe: u64 = 22;
const __NR_dup2: u64 = 33;
const __NR_fork: u64 = 57;
const __NR_execve: u64 = 59;
const __NR_exit: u64 = 60;
const __NR_wait4: u64 = 61;

pub fn escape(data: &[u8], out: &mut String) -> Result<()> {
    for b in data {
        write!(out, "\\x{b:02x}")?;
    }
    Ok(())
}

pub async fn stream_bin_std(orig: &[u8], stdin: &mut ChildStdin) -> Result<()> {
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

pub async fn stream_bin_nostd(orig: &[u8], stdin: &mut ChildStdin) -> Result<()> {
    debug!("Passing through binary...");
    let mut buf = String::new();
    for chunk in orig.chunks(2048) {
        buf.clear();
        escape(chunk, &mut buf)?;
        stdin.write_all(b"if write_all(f, b\"").await?;
        stdin.write_all(buf.as_bytes()).await?;
        stdin.write_all(b"\".as_ptr(), ").await?;
        stdin.write_all(chunk.len().to_string().as_bytes()).await?;
        stdin.write_all(b") == -1 { exit(1) }\n").await?;
    }
    Ok(())
}

pub struct Compiler {
    child: Child,
    pub stdin: ChildStdin,
}

impl Compiler {
    pub async fn spawn(out: &Path, target: Option<&str>) -> Result<Self> {
        let target = target.unwrap_or("x86_64-unknown-linux-musl");
        info!("Spawning Rust compiler...");
        let mut cmd = Command::new("rustc");
        cmd.arg("-Copt-level=3")
            .arg("-Cpanic=abort")
            .arg("-Cstrip=symbols")
            .arg(format!("--target={target}"))
            .arg("-o")
            .arg(out)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        debug!(
            "Setting up process: {:?} {:?}",
            cmd.as_std().get_program(),
            cmd.as_std().get_args()
        );
        let mut child = cmd.spawn().context("Failed to spawn Rust compiler")?;

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

    pub async fn syscall0_readonly(&mut self, ret: &str, nr: u64) -> Result<()> {
        self.add_lines(&[
            "unsafe {\n",
            &format!("let r0: {ret};\n"),
            "asm!(\"syscall\",\n",
            &format!("inlateout(\"rax\") {nr}{ret} => r0,\n"),
            "lateout(\"rcx\") _,\n",
            "lateout(\"r11\") _,\n",
            "options(nostack, preserves_flags)\n",
            ");\n",
            "r0\n",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn syscall1_readonly(&mut self, ret: &str, nr: u64, a0: &str) -> Result<()> {
        self.add_lines(&[
            "unsafe {\n",
            &format!("let r0: {ret};\n"),
            "asm!(\"syscall\",\n",
            &format!("inlateout(\"rax\") {nr}{ret} => r0,\n"),
            &format!("in(\"rdi\") {a0},\n"),
            "lateout(\"rcx\") _,\n",
            "lateout(\"r11\") _,\n",
            "options(nostack, preserves_flags)\n",
            ");\n",
            "r0\n",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn syscall2_readonly(
        &mut self,
        ret: &str,
        nr: u64,
        a0: &str,
        a1: &str,
    ) -> Result<()> {
        self.add_lines(&[
            "unsafe {\n",
            &format!("let r0: {ret};\n"),
            "asm!(\"syscall\",\n",
            &format!("inlateout(\"rax\") {nr}{ret} => r0,\n"),
            &format!("in(\"rdi\") {a0},\n"),
            &format!("in(\"rsi\") {a1},\n"),
            "lateout(\"rcx\") _,\n",
            "lateout(\"r11\") _,\n",
            "options(nostack, preserves_flags)\n",
            ");\n",
            "r0\n",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn syscall3_readonly(
        &mut self,
        ret: &str,
        nr: u64,
        a0: &str,
        a1: &str,
        a2: &str,
    ) -> Result<()> {
        self.add_lines(&[
            "unsafe {\n",
            &format!("let r0: {ret};\n"),
            "asm!(\"syscall\",\n",
            &format!("inlateout(\"rax\") {nr}{ret} => r0,\n"),
            &format!("in(\"rdi\") {a0},\n"),
            &format!("in(\"rsi\") {a1},\n"),
            &format!("in(\"rdx\") {a2},\n"),
            "lateout(\"rcx\") _,\n",
            "lateout(\"r11\") _,\n",
            "options(nostack, preserves_flags)\n",
            ");\n",
            "r0\n",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn syscall4_readonly(
        &mut self,
        ret: &str,
        nr: u64,
        a0: &str,
        a1: &str,
        a2: &str,
        a3: &str,
    ) -> Result<()> {
        self.add_lines(&[
            "unsafe {\n",
            &format!("let r0: {ret};\n"),
            "asm!(\"syscall\",\n",
            &format!("inlateout(\"rax\") {nr}{ret} => r0,\n"),
            &format!("in(\"rdi\") {a0},\n"),
            &format!("in(\"rsi\") {a1},\n"),
            &format!("in(\"rdx\") {a2},\n"),
            &format!("in(\"r10\") {a3},\n"),
            "lateout(\"rcx\") _,\n",
            "lateout(\"r11\") _,\n",
            "options(nostack, preserves_flags)\n",
            ");\n",
            "r0\n",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn syscall5_readonly(
        &mut self,
        ret: &str,
        nr: u64,
        a0: &str,
        a1: &str,
        a2: &str,
        a3: &str,
        a4: &str,
    ) -> Result<()> {
        self.add_lines(&[
            "unsafe {\n",
            &format!("let r0: {ret};\n"),
            "asm!(\"syscall\",\n",
            &format!("inlateout(\"rax\") {nr}{ret} => r0,\n"),
            &format!("in(\"rdi\") {a0},\n"),
            &format!("in(\"rsi\") {a1},\n"),
            &format!("in(\"rdx\") {a2},\n"),
            &format!("in(\"r10\") {a3},\n"),
            &format!("in(\"r8\") {a4},\n"),
            "lateout(\"rcx\") _,\n",
            "lateout(\"r11\") _,\n",
            "options(nostack, preserves_flags)\n",
            ");\n",
            "r0\n",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn generate_exit_fn(&mut self) -> Result<()> {
        self
        .add_lines(&[
            "fn exit(code: i32) -> ! {\n",
            &format!("unsafe {{ asm!(\"syscall\", in(\"rax\") {}, in(\"rdi\") code, options(noreturn)) }}\n", __NR_exit),
            "}\n",
        ])
        .await
    }

    pub async fn generate_execve_fn(&mut self) -> Result<()> {
        self.add_lines(&[
            "fn execve(prog: *const u8, argv: *const *const u8, envp: *const *const u8) -> u64 {\n",
        ])
        .await?;
        self.syscall3_readonly("u64", __NR_execve, "prog", "argv", "envp")
            .await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_fork_fn(&mut self) -> Result<()> {
        self.add_lines(&["fn fork() -> i32 {\n"]).await?;
        let zero = "ptr::null_mut::<u64>()";
        self.syscall5_readonly(
            "i32",
            __NR_fork,
            &SIGCHLD.to_string(),
            zero,
            zero,
            zero,
            zero,
        )
        .await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_wait4_fn(&mut self) -> Result<()> {
        self.add_lines(&["fn wait4(pid: i32, status: *const i32, options: i32, rusage: *const core::ffi::c_void) -> i32 {\n"]).await?;
        self.syscall4_readonly("i32", __NR_wait4, "pid", "status", "options", "rusage")
            .await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_pipe_fn(&mut self) -> Result<()> {
        self.add_lines(&["fn pipe(pipefd: *const i32) -> i32 {\n"])
            .await?;
        self.syscall1_readonly("i32", __NR_pipe, "pipefd").await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_close_fn(&mut self) -> Result<()> {
        self.add_lines(&["fn close(fd: i32) -> i32 {\n"]).await?;
        self.syscall1_readonly("i32", __NR_close, "fd").await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_dup2_fn(&mut self) -> Result<()> {
        self.add_lines(&["fn dup2(oldfd: i32, newfd: i32) -> i32 {\n"])
            .await?;
        self.syscall2_readonly("i32", __NR_dup2, "oldfd", "newfd")
            .await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_write_fn(&mut self) -> Result<()> {
        self.add_lines(&["fn write(fd: i32, buf: *const u8, count: usize) -> isize {\n"])
            .await?;
        self.syscall3_readonly("isize", __NR_write, "fd", "buf", "count")
            .await?;
        self.add_lines(&["}\n"]).await?;
        Ok(())
    }

    pub async fn generate_write_all_fn(&mut self) -> Result<()> {
        self.add_lines(&[
            "fn write_all(fd: i32, mut buf: *const u8, mut count: usize) -> i32 {\n",
            "while count > 0 {\n",
            "let n = write(fd, buf, count);\n",
            "if n < 0 { return -1 }\n",
            "buf = unsafe { buf.offset(n) };\n",
            "count -= n as usize;\n",
            "}\n",
            "0",
            "}\n",
        ])
        .await?;
        Ok(())
    }

    pub async fn generate_entrypoint(&mut self) -> Result<()> {
        self.add_lines(&[
            "global_asm!(",
            "\".global _start\",",
            "\"_start:\", \"mov rdi, rsp\", \"call main\"",
            ");\n",
        ])
        .await
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
