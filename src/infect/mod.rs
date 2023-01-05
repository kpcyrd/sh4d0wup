pub mod apk;
pub mod deb;
pub mod elf;
pub mod elf_fwd_stdin;
pub mod oci;
pub mod pacman;
pub mod sh;

use crate::args::Infect;
use crate::errors::*;
use crate::keygen::openssl::OpensslEmbedded;
use crate::keygen::EmbeddedKey;
use crate::plot::PlotExtras;
use crate::utils;
use std::fs::File;

pub async fn run(infect: Infect) -> Result<()> {
    match infect {
        Infect::Pacman(infect) => {
            let pkg = utils::read_input_path(&infect.path).await?;
            let mut out = File::create(&infect.out)?;
            pacman::infect(&infect.try_into()?, &pkg, &mut out)?;
        }
        Infect::Deb(infect) => {
            let pkg = utils::read_input_path(&infect.path).await?;
            let mut out = File::create(&infect.out)?;
            deb::infect(&infect.try_into()?, &pkg, &mut out)?;
        }
        Infect::Oci(infect) => {
            let pkg = utils::read_input_path(&infect.path).await?;
            let mut out = File::create(&infect.out)?;
            oci::infect(&infect, &pkg, &mut out)?;
        }
        Infect::Apk(infect) => {
            let pkg = utils::read_input_path(&infect.path).await?;
            let signing_key = OpensslEmbedded::read_from_disk(&infect.signing_key)?;

            let mut out = File::create(&infect.out)?;

            let mut plot_extras = PlotExtras::default();
            plot_extras
                .signing_keys
                .insert("openssl".to_string(), EmbeddedKey::Openssl(signing_key));

            apk::infect(
                &apk::Infect {
                    signing_key: "openssl".to_string(),
                    signing_key_name: infect.signing_key_name,
                    payload: infect.payload,
                },
                &plot_extras.signing_keys,
                &pkg,
                &mut out,
            )?;
        }
        Infect::Elf(infect) => {
            let elf = utils::read_input_path(&infect.path).await?;
            let mut out = tokio::fs::File::create(&infect.out).await?;
            elf::infect(&infect.try_into()?, &elf, &mut out).await?;
        }
        Infect::ElfFwdStdin(infect) => {
            let sh = utils::read_input_path(&infect.path).await?;
            let mut out = tokio::fs::File::create(&infect.out).await?;
            elf_fwd_stdin::infect(&infect.try_into()?, &sh, &mut out).await?;
        }
        Infect::Sh(infect) => {
            let sh = utils::read_input_path(&infect.path).await?;
            let mut out = tokio::fs::File::create(&infect.out).await?;
            sh::infect(&infect.try_into()?, &sh, &mut out).await?;
        }
    }

    Ok(())
}
