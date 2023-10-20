#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs_verification {
    use ink::prelude::vec::Vec;
    use ink_env::hash::CryptoHash;
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
            signature: [u8; 65],
        ) -> bool {
            let mut keccak = Keccak::v256();
            keccak.update(&data);
            let mut data_hash = [0u8; 32];
            keccak.finalize(&mut data_hash);
            Self::verify(self, signer, data_hash, signature)
        }

        #[ink(message)]
        pub fn verify(&self, signer: AccountId, data_hash: [u8; 32], signature: [u8; 65]) -> bool {
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
            let mut uncompressed_public_key = [0; 33];
            let _ = ink_env::ecdsa_recover(&signature, &data_hash, &mut uncompressed_public_key);

            // Get AccountId from output (compressed public key)
            let mut generated_account_id_data = [0u8; 32];
            let _ = ink_env::hash::Blake2x256::hash(
                &uncompressed_public_key,
                &mut generated_account_id_data,
            );
            let generated_account_id = AccountId::from(generated_account_id_data);
            if signer == generated_account_id {
                return true;
            }
            false
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn constructor() {
            let _ = ProofsVerification::new();
        }
    }
}
