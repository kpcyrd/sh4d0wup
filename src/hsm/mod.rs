#[cfg(feature = "hsm")]
pub mod pgp;

// Expose dummy functions
#[cfg(not(feature = "hsm"))]
pub mod pgp {
    use crate::args::HsmAccess;
    use crate::errors::*;

    pub fn access(_access: &HsmAccess) -> Result<()> {
        bail!("HSM support is not available in this binary");
    }
}
