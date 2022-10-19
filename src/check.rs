use crate::args;
use crate::errors::*;
use crate::httpd;
use crate::plot;
use crate::plot::Cmd;
use nix::sched::CloneFlags;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::process::Stdio;
use tokio::fs;
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

pub fn test_userns_clone() -> Result<()> {
    let cb = Box::new(|| 0);
    let stack = &mut [0; 1024];
    let flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER;

    let pid =
        nix::sched::clone(cb, stack, flags, None).context("Failed to create user namespace")?;
    let status = nix::sys::wait::waitpid(pid, Some(WaitPidFlag::__WCLONE))
        .context("Failed to reap child")?;

    if status != WaitStatus::Exited(pid, 0) {
        bail!("Unexpected wait result: {:?}", status);
    }

    Ok(())
}

pub async fn test_for_unprivileged_userns_clone() -> Result<()> {
    debug!("Testing if user namespaces can be created");
    if let Err(err) = test_userns_clone() {
        match fs::read("/proc/sys/kernel/unprivileged_userns_clone").await {
            Ok(buf) => {
                if buf == b"0\n" {
                    warn!("User namespaces are not enabled in /proc/sys/kernel/unprivileged_userns_clone")
                }
            }
            Err(err) => warn!(
                "Failed to check if unprivileged_userns_clone are allowed: {:#}",
                err
            ),
        }

        Err(err)
    } else {
        debug!("Successfully tested for user namespaces");
        Ok(())
    }
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
        let bin = init
            .first()
            .context("Command for container can't be empty")?;
        let cmd_args = &init[1..];
        let entrypoint = format!("--entrypoint={}", bin);
        let mut podman_args = vec![
            "container",
            "run",
            "--detach",
            "--rm",
            "--network=host",
            "-v=/usr/bin/catatonit:/__:ro",
            &entrypoint,
            "--",
            image,
        ];
        podman_args.extend(cmd_args.iter().map(|s| s.as_str()));
        let mut out = podman(&podman_args, true).await?;
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
            self.exec(
                &args,
                &[
                    format!("SH4D0WUP_BOUND_ADDR={}", addr),
                    format!("SH4D0WUP_BOUND_IP={}", addr.ip()),
                    format!("SH4D0WUP_BOUND_PORT={}", addr.port()),
                ],
            )
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
        .unwrap_or_else(|| vec!["/__".to_string(), "-P".to_string()]);

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
    test_for_unprivileged_userns_clone().await?;

    let addr = if let Some(addr) = check.bind {
        addr
    } else {
        let sock = TcpListener::bind("127.0.0.1:0").await?;
        sock.local_addr()?
    };

    let tls = if let Some(tls) = plot.tls.clone() {
        Some(httpd::Tls::try_from(tls)?)
    } else {
        None
    };
    let httpd = httpd::run(addr, tls, plot.clone());
    let check = run(addr, check, plot);

    tokio::select! {
        httpd = httpd => httpd.context("httpd thread terminated")?,
        check = check => check?,
    };

    Ok(())
}
