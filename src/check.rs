use crate::args;
use crate::errors::*;
use crate::httpd;
use crate::keygen::EmbeddedKey;
use crate::plot;
use crate::plot::Cmd;
use nix::sched::CloneFlags;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
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

    let pid = unsafe { nix::sched::clone(cb, stack, flags, None) }
        .context("Failed to create user namespace")?;
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

pub async fn podman<I, S>(args: I, capture_stdout: bool, stdin: Option<&[u8]>) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr> + fmt::Debug,
{
    let mut cmd = Command::new("podman");
    let args = args.into_iter().collect::<Vec<_>>();
    cmd.args(&args);
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    if capture_stdout {
        cmd.stdout(Stdio::piped());
    }
    debug!("Spawning child process: podman {:?}", args);
    let mut child = cmd.spawn().context("Failed to execute podman binary")?;

    if let Some(data) = stdin {
        debug!("Sending {} bytes to child process...", data.len());
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(data).await?;
        stdin.flush().await?;
    }

    let out = child.wait_with_output().await?;
    debug!("Podman command exited: {:?}", out.status);
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
    addr: SocketAddr,
}

impl Container {
    pub async fn create(
        image: &str,
        init: &[String],
        addr: SocketAddr,
        expose_fuse: bool,
    ) -> Result<Container> {
        let bin = init
            .first()
            .context("Command for container can't be empty")?;
        let cmd_args = &init[1..];
        let entrypoint = format!("--entrypoint={bin}");
        let mut podman_args = vec![
            "container",
            "run",
            "--detach",
            "--rm",
            "--network=host",
            "-v=/usr/bin/catatonit:/__:ro",
        ];
        if expose_fuse {
            debug!("Mapping /dev/fuse into the container");
            podman_args.push("--device=/dev/fuse");
        }

        podman_args.extend([&entrypoint, "--", image]);
        podman_args.extend(cmd_args.iter().map(|s| s.as_str()));

        let mut out = podman(&podman_args, true, None).await?;
        if let Some(idx) = memchr::memchr(b'\n', &out) {
            out.truncate(idx);
        }
        let id = String::from_utf8(out)?;
        Ok(Container { id, addr })
    }

    pub async fn exec<I, S>(
        &self,
        args: I,
        stdin: Option<&[u8]>,
        env: &[String],
        user: Option<String>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str> + fmt::Debug + Clone,
    {
        let args = args.into_iter().collect::<Vec<_>>();
        let mut a = vec!["container".to_string(), "exec".to_string()];
        if let Some(user) = user {
            a.extend(["-u".to_string(), user]);
        }
        if stdin.is_some() {
            a.push("-i".to_string());
        }
        for env in env {
            a.push(format!("-e={env}"));
        }
        a.extend(["--".to_string(), self.id.to_string()]);
        a.extend(args.iter().map(|x| x.as_ref().to_string()));
        podman(&a, false, stdin)
            .await
            .with_context(|| anyhow!("Failed to execute in container: {:?}", args))?;
        Ok(())
    }

    pub async fn kill(self) -> Result<()> {
        podman(&["container", "kill", &self.id], true, None)
            .await
            .context("Failed to remove container")?;
        Ok(())
    }

    pub async fn exec_cmd_stdin(
        &self,
        cmd: &Cmd,
        stdin: Option<&[u8]>,
        user: Option<String>,
    ) -> Result<()> {
        let args = match cmd {
            Cmd::Shell(cmd) => vec!["sh", "-c", cmd],
            Cmd::Exec(cmd) => cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        };
        info!("Executing process in container: {:?}", args);
        self.exec(
            &args,
            stdin,
            &[
                format!("SH4D0WUP_BOUND_ADDR={}", self.addr),
                format!("SH4D0WUP_BOUND_IP={}", self.addr.ip()),
                format!("SH4D0WUP_BOUND_PORT={}", self.addr.port()),
            ],
            user,
        )
        .await
        .map_err(|err| {
            error!("Command failed: {:#}", err);
            err
        })
        .context("Command failed")?;
        Ok(())
    }

    pub async fn exec_cmd(&self, cmd: &Cmd, user: Option<String>) -> Result<()> {
        self.exec_cmd_stdin(cmd, None, user).await
    }

    pub async fn run_check(
        &self,
        config: &plot::Check,
        plot_extras: &plot::PlotExtras,
        tls: Option<&httpd::Tls>,
        keep: bool,
    ) -> Result<()> {
        info!("Finishing setup in container...");
        if let (Some(tls), Some(cmd)) = (tls, &config.install_certs) {
            info!("Installing certificates...");
            self.exec_cmd_stdin(cmd, Some(&tls.cert), Some("0".to_string()))
                .await
                .context("Failed to install certificates")?;
        }
        for install in &config.install_keys {
            info!("Installing key {:?} with {:?}...", install.key, install.cmd);
            let key = plot_extras
                .signing_keys
                .get(&install.key)
                .context("Invalid reference to signing key")?;

            let cert = match key {
                EmbeddedKey::Pgp(pgp) => pgp.to_cert(install.binary)?,
                EmbeddedKey::Ssh(ssh) => ssh.to_cert()?,
                EmbeddedKey::Openssl(openssl) => openssl.to_cert(install.binary)?,
                EmbeddedKey::InToto(_in_toto) => {
                    bail!("Installing in-toto keys into the container isn't supported yet")
                }
            };

            self.exec_cmd_stdin(&install.cmd, Some(&cert), None)
                .await
                .context("Failed to install certificates")?;
        }
        for host in &config.register_hosts {
            info!(
                "Installing /etc/hosts entry, {:?} => {}",
                host,
                self.addr.ip()
            );
            let cmd = format!("echo \"{} {}\" >> /etc/hosts", self.addr.ip(), host);
            self.exec_cmd(&Cmd::Shell(cmd), Some("0".to_string()))
                .await
                .context("Failed to register /etc/hosts entry")?;
        }

        info!("Starting test...");
        for cmd in &config.cmds {
            self.exec_cmd(cmd, None)
                .await
                .context("Attack failed to execute on test environment")?;
        }
        info!("Test completed successfully");

        if keep {
            info!("Keeping container around until ^C...");
            futures::future::pending().await
        } else {
            Ok(())
        }
    }
}

pub async fn run(
    addr: SocketAddr,
    check: args::Check,
    tls: Option<&httpd::Tls>,
    ctx: Arc<plot::Ctx>,
) -> Result<()> {
    let check_config = ctx
        .plot
        .check
        .as_ref()
        .context("No test configured in this plot")?;
    wait_for_server(&addr).await?;

    let image = &check_config.image;
    let init = check_config
        .init
        .clone()
        .unwrap_or_else(|| vec!["/__".to_string(), "-P".to_string()]);

    if check.pull
        || podman(&["image", "exists", "--", image], false, None)
            .await
            .is_err()
    {
        info!("Pulling container image...");
        podman(&["image", "pull", "--", image], false, None).await?;
    }

    info!("Creating container...");
    let container = Container::create(image, &init, addr, check_config.expose_fuse).await?;
    let container_id = container.id.clone();
    let result = tokio::select! {
        result = container.run_check(check_config, &ctx.extras, tls, check.keep) => result,
        _ = signal::ctrl_c() => Err(anyhow!("Ctrl-c received")),
    };
    info!("Removing container...");
    if let Err(err) = container.kill().await {
        warn!("Failed to kill container {:?}: {:#}", container_id, err);
    }
    info!("Cleanup complete");

    result
}

pub async fn spawn(check: args::Check, ctx: plot::Ctx) -> Result<()> {
    test_for_unprivileged_userns_clone().await?;

    let addr = if let Some(addr) = check.bind {
        addr
    } else {
        let sock = TcpListener::bind("127.0.0.1:0").await?;
        sock.local_addr()?
    };

    let tls = if let Some(tls) = ctx.plot.tls.clone() {
        Some(httpd::Tls::try_from(tls)?)
    } else {
        None
    };

    let ctx = Arc::new(ctx);
    let httpd = httpd::run(addr, tls.clone(), ctx.clone());
    let check = run(addr, check, tls.as_ref(), ctx);

    tokio::select! {
        httpd = httpd => httpd.context("httpd thread terminated")?,
        check = check => check?,
    };

    Ok(())
}
