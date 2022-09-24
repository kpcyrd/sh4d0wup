use crate::errors::*;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::Read;
use xz::read::XzDecoder;
use xz::write::XzEncoder;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CompressedWith {
    // .gz
    Gzip,
    // .bz2
    Bzip2,
    // .xz
    Xz,
    // .zstd
    Zstd,
    Unknown,
}

pub fn detect_compression(bytes: &[u8]) -> CompressedWith {
    let mime = tree_magic_mini::from_u8(bytes);
    debug!("Detected mimetype for possibly compressed data: {:?}", mime);

    match mime {
        "application/gzip" => CompressedWith::Gzip,
        "application/x-bzip" => CompressedWith::Bzip2,
        "application/x-xz" => CompressedWith::Xz,
        "application/zstd" => CompressedWith::Zstd,
        _ => CompressedWith::Unknown,
    }
}

pub fn stream_decompress<'a>(comp: CompressedWith, bytes: &'a [u8]) -> Result<Box<dyn Read + 'a>> {
    match comp {
        CompressedWith::Gzip => Ok(Box::new(GzDecoder::new(bytes))),
        CompressedWith::Bzip2 => Ok(Box::new(BzDecoder::new(bytes))),
        CompressedWith::Xz => Ok(Box::new(XzDecoder::new(bytes))),
        CompressedWith::Zstd => Ok(Box::new(zstd::Decoder::new(bytes)?)),
        CompressedWith::Unknown => Ok(Box::new(bytes)),
    }
}

pub fn compress(comp: CompressedWith, bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let mut out = Vec::new();

    match comp {
        CompressedWith::Gzip => {
            let mut e = GzEncoder::new(out, flate2::Compression::default());
            e.write_all(bytes)?;
            out = e.finish()?;
        }
        CompressedWith::Bzip2 => {
            let mut e = BzEncoder::new(out, bzip2::Compression::default());
            e.write_all(bytes)?;
            out = e.finish()?;
        }
        CompressedWith::Xz => {
            let mut e = XzEncoder::new(out, 6);
            e.write_all(bytes)?;
            out = e.finish()?;
        }
        CompressedWith::Zstd => {
            let mut e = zstd::Encoder::new(out, zstd::DEFAULT_COMPRESSION_LEVEL)?;
            e.write_all(bytes)?;
            out = e.finish()?;
        }
        CompressedWith::Unknown => {
            out = bytes.to_vec();
        }
    }

    Ok(out)
}
