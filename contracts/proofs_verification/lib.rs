#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs_verification {
    use ink::prelude::{string::String, vec::Vec};

    // use ink_e2e::sr25519::verify;
    use tiny_keccak::{Hasher, Keccak};

    #[ink(storage)]
    pub struct ProofsVerification {}

    impl ProofsVerification {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        /// Verifies the signature for given data
        #[ink(message)]
        pub fn verify_signed_proof(
            &self,
            signer: AccountId,
            data: Vec<u8>,
            signature: Vec<u8>,
        ) -> bool {
            let mut keccak = Keccak::v256();
            keccak.update(&data);
            let mut data_hash = [0u8; 32];
            keccak.finalize(&mut data_hash);
            Self::verify(self, signer, data_hash, signature)
        }

        #[ink(message)]
        pub fn verify(&self, signer: AccountId, data_hash: [u8; 32], signature: Vec<u8>) -> bool {
            let msg_prefix: Vec<u8> = vec![0x19u8, 0x45u8];
            let msg_text = b"Ethereum Signed Message:\n32";
            let mut msg_hash_bytes = Vec::new();
            msg_hash_bytes.extend(msg_prefix);
            msg_hash_bytes.extend_from_slice(msg_text);
            msg_hash_bytes.extend_from_slice(&data_hash);

            let mut keccak = Keccak::v256();
            keccak.update(&msg_hash_bytes);
            let mut msg_hash = [0u8; 32];
            keccak.finalize(&mut msg_hash);

            // TODO: import cryptography library for ECDSA
            // let res = ecdsa::signature::Verifier::verify(&self, &data_hash, &signature);
            // if res.is_err() {
            //     return false;
            // } else {
            //     return true; // TODO: compare resulting address and `signer`
            // }
            true
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn default_works() {
            // let proofs_verification = ProofsVerification::default();
            // assert_eq!(proofs_verification.get(), false);
        }
    }
}
