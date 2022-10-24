use crate::errors::*;
use std::io::prelude::*;
use warp::hyper::body::Bytes;

pub fn patch<W: Write>(_config: &(), bytes: &[u8], out: &mut W) -> Result<()> {
    // TODO: implement
    out.write_all(bytes)?;
    Ok(())
}

pub fn modify_response(config: &(), bytes: &[u8]) -> Result<Bytes> {
    let mut out = Vec::new();
    patch(config, bytes, &mut out)?;
    Ok(Bytes::from(out))
}
