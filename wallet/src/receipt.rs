//! The receipt secret a node's operator derives from its node key.

use sha2::{Digest as _, Sha256};

const RECEIPT_SECRET_DOMAIN: &[u8; 24] = b"Uplink/ReceiptSecret/v1\0";

/// The receipt secret of the node whose Ed25519 secret key is `node_secret`.
///
/// Derived once by the node's operator and handed to its participant's wallet, which derives the
/// blinding factor of each cash-out receipt from it with [`referral_core::blinding_factor`]. The
/// node key is then needed again only to derive the secret anew, for instance after losing the
/// device that held it. Computed as `SHA256("Uplink/ReceiptSecret/v1\0" || node_secret)`,
/// whose domain keeps it apart from the key's own SHA-512 expansion.
#[must_use]
pub fn receipt_secret(node_secret: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(RECEIPT_SECRET_DOMAIN)
        .chain_update(node_secret)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use sha2::Sha512;

    use super::*;

    #[test]
    fn the_receipt_secret_is_the_prefixed_hash_of_the_node_secret() {
        assert_eq!(
            receipt_secret(&[7; 32]),
            [
                0x7f, 0xa0, 0x48, 0xd0, 0xe5, 0x46, 0x69, 0x25, 0xa9, 0xff, 0x21, 0x3b, 0x16, 0x8f,
                0xcb, 0x2d, 0xd0, 0x8d, 0x61, 0xb6, 0xee, 0xed, 0xf7, 0x79, 0x50, 0x2a, 0x13, 0x65,
                0x03, 0x41, 0x9f, 0x30,
            ]
        );
        assert_ne!(receipt_secret(&[8; 32]), receipt_secret(&[7; 32]));
    }

    #[test]
    fn the_receipt_secret_is_neither_half_of_the_keys_own_expansion() {
        let expanded = Sha512::digest([7; 32]);
        let secret = receipt_secret(&[7; 32]);

        assert_ne!(secret.as_slice(), &expanded[..32]);
        assert_ne!(secret.as_slice(), &expanded[32..]);
    }
}
