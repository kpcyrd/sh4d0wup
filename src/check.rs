use crate::args;
use crate::errors::*;
use crate::httpd;
use crate::plot;
use crate::plot::Cmd;
use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::process::Stdio;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::signal;
use tokio::time::{sleep, Duration};

pub async fn wait_for_server(addr: &SocketAddr) -> Result<()> {
    debug!("Waiting for server to start up...");
    for _ in 0..5 {
        sleep(Duration::from_millis(100)).await;
        if TcpStream::connect(addr).await.is_ok() {
            debug!("Successfully connected to tcp port");
            return Ok(());
        }
    }
    bail!("Failed to connect to server");
}

pub async fn podman<I, S>(args: I, capture_stdout: bool) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr> + fmt::Debug,
{
    let mut cmd = Command::new("podman");
    let args = args.into_iter().collect::<Vec<_>>();
    cmd.args(&args);
    if capture_stdout {
        cmd.stdout(Stdio::piped());
    }
    debug!("Spawning child process: podman {:?}", args);
    let child = cmd.spawn()?;
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!(
            "Podman command ({:?}) failed to execute: {:?}",
            args,
            out.status
        );
    }
    Ok(out.stdout)
}

#[derive(Debug)]
pub struct Container {
    id: String,
}

impl Container {
    pub async fn create(image: &str, init: &[String]) -> Result<Container> {
        let mut args = vec![
            "container",
            "run",
            "--detach",
            "--rm",
            "--network=host",
            "-v=/usr/bin/catatonit:/usr/bin/catatonit:ro",
            "--",
            image,
        ];
        args.extend(init.iter().map(|s| s.as_str()));
        let mut out = podman(&args, true).await?;
        if let Some(idx) = memchr::memchr(b'\n', &out) {
            out.truncate(idx);
        }
        let id = String::from_utf8(out)?;
        Ok(Container { id })
    }

    pub async fn exec<I, S>(&self, args: I, env: &[String]) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str> + fmt::Debug + Clone,
    {
        let args = args.into_iter().collect::<Vec<_>>();
        let mut a = vec!["container".to_string(), "exec".to_string()];
        for env in env {
            a.push(format!("-e={}", env));
        }
        a.extend(["--".to_string(), self.id.to_string()]);
        a.extend(args.iter().map(|x| x.as_ref().to_string()));
        podman(&a, false)
            .await
            .with_context(|| anyhow!("Failed to execute {:?}", args))?;
        Ok(())
    }

    pub async fn kill(self) -> Result<()> {
        podman(&["container", "kill", &self.id], true)
            .await
            .context("Failed to remove container")?;
        Ok(())
    }

    pub async fn run_check(&self, addr: &SocketAddr, config: &plot::Check) -> Result<()> {
        for cmd in &config.cmds {
            let args = match &cmd {
                Cmd::Shell(cmd) => vec!["sh", "-c", cmd],
                Cmd::Exec(cmd) => cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            };
            info!("Executing check: {:?}", args);
            self.exec(&args, &[format!("SH4D0WUP_BOUND_ADDR={}", addr)])
                .await
                .map_err(|err| {
                    error!("Command failed: {:#}", err);
                    err
                })
                .context("Test failed")?;
        }
        info!("Test completed successfully");
        Ok(())
    }
}

pub async fn run(addr: SocketAddr, check: args::Check, plot: plot::Plot) -> Result<()> {
    let check_config = plot.check.context("No test configured in this plot")?;
    wait_for_server(&addr).await?;

    let image = &check_config.image;
    let init = check_config
        .init
        .clone()
        .unwrap_or_else(|| vec!["catatonit".to_string(), "-P".to_string()]);

    if check.pull
        || podman(&["image", "exists", "--", image], false)
            .await
            .is_err()
    {
        info!("Pulling container image...");
        podman(&["image", "pull", "--", image], false).await?;
    }

    info!("Creating container...");
    let container = Container::create(image, &init).await?;
    let container_id = container.id.clone();
    let result = tokio::select! {
        result = container.run_check(&addr, &check_config) => result,
        _ = signal::ctrl_c() => Err(anyhow!("Ctrl-c received")),
    };
    info!("Removing container...");
    if let Err(err) = container.kill().await {
        warn!("Failed to kill container {:?}: {:#}", container_id, err);
    }

    result
}

pub async fn spawn(check: args::Check, plot: plot::Plot) -> Result<()> {
    let addr = if let Some(addr) = &check.bind {
        *addr
    } else {
        let sock = TcpListener::bind("127.0.0.1:0").await?;
        sock.local_addr()?
    };

    let httpd = httpd::run(addr, plot.clone());
    let check = run(addr, check, plot);

    tokio::select! {
        httpd = httpd => httpd.context("httpd thread terminated")?,
        check = check => check?,
    };

    Ok(())
}
