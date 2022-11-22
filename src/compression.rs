use crate::errors::*;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io;
use std::io::prelude::*;
use xz::read::XzDecoder;
use xz::write::XzEncoder;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressedWith {
    // .gz
    Gzip,
    // .bz2
    Bzip2,
    // .xz
    Xz,
    // .zstd
    Zstd,
    None,
}

pub fn detect_compression(bytes: &[u8]) -> CompressedWith {
    let mime = tree_magic_mini::from_u8(bytes);
    debug!("Detected mimetype for possibly compressed data: {:?}", mime);

    match mime {
        "application/gzip" => CompressedWith::Gzip,
        "application/x-bzip" => CompressedWith::Bzip2,
        "application/x-xz" => CompressedWith::Xz,
        "application/zstd" => CompressedWith::Zstd,
        _ => CompressedWith::None,
    }
}

pub fn stream_decompress<'a, R: Read + 'a>(
    r: R,
    comp: CompressedWith,
) -> Result<Box<dyn Read + 'a>> {
    match comp {
        CompressedWith::Gzip => Ok(Box::new(GzDecoder::new(r))),
        CompressedWith::Bzip2 => Ok(Box::new(BzDecoder::new(r))),
        CompressedWith::Xz => Ok(Box::new(XzDecoder::new(r))),
        CompressedWith::Zstd => Ok(Box::new(zstd::Decoder::new(r)?)),
        CompressedWith::None => Ok(Box::new(r)),
    }
}

pub enum Compressor<'a, W: Write> {
    Gzip(GzEncoder<W>),
    Bzip2(BzEncoder<W>),
    Xz(XzEncoder<W>),
    Zstd(zstd::Encoder<'a, W>),
    Passthru(W),
}

impl<W: Write> Compressor<'_, W> {
    pub fn finish(self) -> Result<()> {
        match self {
            Compressor::Gzip(w) => {
                w.finish()?;
            }
            Compressor::Bzip2(w) => {
                w.finish()?;
            }
            Compressor::Xz(w) => {
                w.finish()?;
            }
            Compressor::Zstd(w) => {
                w.finish()?;
            }
            Compressor::Passthru(_) => (),
        }
        Ok(())
    }
}

impl<W: Write> Write for Compressor<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Compressor::Gzip(w) => w.write(buf),
            Compressor::Bzip2(w) => w.write(buf),
            Compressor::Xz(w) => w.write(buf),
            Compressor::Zstd(w) => w.write(buf),
            Compressor::Passthru(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Compressor::Gzip(w) => w.flush(),
            Compressor::Bzip2(w) => w.flush(),
            Compressor::Xz(w) => w.flush(),
            Compressor::Zstd(w) => w.flush(),
            Compressor::Passthru(w) => w.flush(),
        }
    }
}

pub fn stream_compress<W: Write>(w: W, comp: CompressedWith) -> Result<Compressor<'static, W>> {
    match comp {
        CompressedWith::Gzip => Ok(Compressor::Gzip(GzEncoder::new(
            w,
            flate2::Compression::default(),
        ))),
        CompressedWith::Bzip2 => Ok(Compressor::Bzip2(BzEncoder::new(
            w,
            bzip2::Compression::default(),
        ))),
        CompressedWith::Xz => Ok(Compressor::Xz(XzEncoder::new(w, 6))),
        CompressedWith::Zstd => Ok(Compressor::Zstd(zstd::Encoder::new(
            w,
            zstd::DEFAULT_COMPRESSION_LEVEL,
        )?)),
        CompressedWith::None => Ok(Compressor::Passthru(w)),
    }
}

pub fn compress(comp: CompressedWith, bytes: &[u8]) -> Result<Vec<u8>> {
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
        CompressedWith::None => {
            out = bytes.to_vec();
        }
    }

    Ok(out)
}
