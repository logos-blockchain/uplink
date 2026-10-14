//! The referral program's reproducibly built guest binary, packed as a [`Program`].

#[cfg(feature = "artifacts")]
pub use inner::*;

#[cfg(feature = "artifacts")]
mod inner {
    use std::borrow::Cow;

    use guests::{REFERRAL_ELF, REFERRAL_ID};
    use lee::program::Program;

    mod guests {
        include!(concat!(env!("OUT_DIR"), "/programs/referral/mod.rs"));
    }

    #[must_use]
    #[inline]
    pub const fn referral() -> Program {
        Program::new_unchecked(REFERRAL_ID, Cow::Borrowed(REFERRAL_ELF))
    }
}
