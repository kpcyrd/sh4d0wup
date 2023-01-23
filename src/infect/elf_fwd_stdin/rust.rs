use crate::codegen::rust;
use crate::errors::*;
use crate::infect::elf_fwd_stdin::Infect;
use std::path::Path;

fn gen_args_src(args: &[String]) -> Result<String> {
    let mut s = String::new();
    for arg in args {
        s.push_str(".arg(\"");
        rust::escape(arg.as_bytes(), &mut s)?;
        s.push_str("\")\n");
    }
    Ok(s)
}

pub async fn infect(bin: &Path, config: &Infect, orig: &[u8]) -> Result<()> {
    let exec_path = config.exec_path();
    let args = config.args(exec_path);

    let mut compiler = rust::Compiler::spawn(bin, config.target.as_deref()).await?;

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

    let args_src = gen_args_src(&args[1..])?;

    compiler
        .add_lines(&[
            "use std::io::Write;\n",
            "#[cfg(unix)]\n",
            "use std::os::unix::process::CommandExt;\n",
            "use std::process::Command;\n",
            "use std::process::Stdio;\n",
            "use std::process::exit;\n",
            "fn main() {\n",
            &format!("let mut cmd = Command::new(\"{}\");\n", exec_path_escaped),
            "#[cfg(unix)]\n",
            &format!("cmd.arg0(\"{}\");\n", arg0_escaped),
            "cmd",
            &args_src,
            ".stdin(Stdio::piped());\n",
            "let Ok(mut child) = cmd.spawn() else { exit(1) };\n",
            "let Some(mut f) = child.stdin.take() else { exit(1) };\n",
        ])
        .await?;

    rust::stream_bin(orig, &mut compiler.stdin).await?;

    compiler
        .add_lines(&[
            "drop(f);\n",
            "let Ok(status) = child.wait() else { exit(1) };\n",
            "exit(status.code().unwrap_or(1));\n",
            "}\n",
        ])
        .await?;

    let mut pending = compiler.done();
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    Ok(())
}
