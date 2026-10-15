//! Wallet support for the referral program, on top of the Logos Execution Zone wallet.
//!
//! [`Referral`] builds and submits the program's operations through a [`wallet::WalletCore`], and
//! keeps what it needs to resume them in its own store next to the wallet's storage.

pub use facade::{Opening, Receipt, Referral};
pub use receipt::receipt_secret;

pub mod facade;
pub mod receipt;
pub mod store;
