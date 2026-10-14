//! The receipt secret a node's operator derives from its node key.

use sha2::{Digest as _, Sha256};

const RECEIPT_SECRET_DOMAIN: &[u8; 30] = b"LEZ/Referral/ReceiptSecret/v1\0";

/// The receipt secret of the node whose Ed25519 secret key is `node_secret`.
///
/// Derived once by the node's operator and handed to its participant's wallet, which derives the
/// blinding factor of each cash-out receipt from it with [`referral_core::blinding_factor`]. The
/// node key is then needed again only to derive the secret anew, for instance after losing the
/// device that held it. Computed as `SHA256("LEZ/Referral/ReceiptSecret/v1\0" || node_secret)`,
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
                0x2a, 0xf3, 0x88, 0x0e, 0xf4, 0xe8, 0x57, 0x2d, 0xbb, 0x6c, 0x53, 0x69, 0x2c, 0x2d,
                0xab, 0x0c, 0x78, 0x40, 0x16, 0x18, 0x65, 0xc6, 0xeb, 0xc3, 0x0f, 0x2e, 0xd7, 0xd2,
                0xee, 0x5d, 0x7b, 0xa7,
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
