use crate::args;
use crate::errors::*;
use crate::plot;

pub async fn spawn(_check: args::Check, _ctx: plot::Ctx) -> Result<()> {
    bail!("Running `sh4d0wup check` is not supported on this platform");
}
