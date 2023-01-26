use crate::errors::*;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use flate2::GzBuilder;
use std::io;
use std::io::prelude::*;
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

pub fn patch_signature_container(
    original_container: &[u8],
    signature: &[u8],
    key_algo_id: &str,
    signing_key_name: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut builder = tar::Builder::new(&mut out);
    let mut archive = Archive::new(original_container);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let mut header = entry.header().clone();
        debug!("Found entry in tar: {:?}", header.path());

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;

        debug!("Replacing signature ({} bytes): {:?}", buf.len(), buf);
        let name = format!(".SIGN.{key_algo_id}.{signing_key_name}");
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
