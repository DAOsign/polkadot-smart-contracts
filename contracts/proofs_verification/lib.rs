#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs_verification {
    use hex::FromHex;
    use ink::prelude::vec::Vec;
    use ink_env::hash::CryptoHash;
    use tiny_keccak::{Hasher, Keccak};

    #[ink(storage)]
    pub struct ProofsVerification {}

    impl ProofsVerification {
        #[ink(constructor)]
        pub fn new() -> Self {
            ink::env::debug_println!("created new instance at {}", Self::env().block_number());
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
            let mut hasher = Keccak::v256();
            let prefix = b"\x19Ethereum Signed Message:\n32"; // Ethereum's message prefix

            // Concatenate the prefix and the hash
            hasher.update(prefix);
            hasher.update(&data_hash);

            // Finalize the hash
            let mut result = [0u8; 32];
            hasher.finalize(&mut result);

            // Convert to array
            let mut msg_hash = [0u8; 32];
            msg_hash.copy_from_slice(&result);

            ink::env::debug_println!("msg hash bytes {:?}", msg_hash);

            // TODO: import cryptography library for ECDSA
            let mut uncompressed_public_key = [0; 33];
            let _ = ink_env::ecdsa_recover(&signature, &msg_hash, &mut uncompressed_public_key);

            ink::env::debug_println!("uncompressed_public_key {:?}", uncompressed_public_key);

            // // Get AccountId from output (compressed public key)
            // let mut generated_account_id_data = [0u8; 32];
            // let _ = ink_env::hash::Blake2x256::hash(
            //     &uncompressed_public_key,
            //     &mut generated_account_id_data,
            // );
            // let generated_account_id =
            //     AccountId::from(uncompressed_public_key /*generated_account_id_data*/);

            let mut account_id: [u8; 20] = [0; 20];
            let _ = ink_env::ecdsa_to_eth_address(&uncompressed_public_key, &mut account_id);
            let mut generated_account_id = [0; 32];
            // AccountId::from(account_id);
            generated_account_id[12..].copy_from_slice(&account_id);

            ink::env::debug_println!("account_id {:?}", generated_account_id);
            ink::env::debug_println!("signer {:?}", signer);

            if signer == AccountId::from(generated_account_id) {
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

        #[ink::test]
        fn verify_signed_proof_works() {
            let contract = ProofsVerification::new();

            // Values from Ethereum. Replace these dummy values with real ones.
            let signer: AccountId = AccountId::from(
                <[u8; 32]>::from_hex("00".repeat(12) + "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
                    .unwrap(),
            );

            let data: [u8; 32] = <[u8; 32]>::from_hex(
                "49145797d5b241d1bc807fddde38d675212624d4556f22246bde8be447967f8e",
            )
            .unwrap();
            ink::env::debug_println!("data hash {:?}", data);

            let signature: [u8; 65] = <[u8; 65]>::from_hex("1fccf4ff11872b0426c7b7826db58b876d9d02d78759b5a7bccc1035f451248b5369ccbebc00094043f55746733f975dfbf7c2000c204853a9ea38ebccf8eb101c").unwrap();
            ink::env::debug_println!("signature {:?}", signature);

            // Verify that the signature is valid
            let is_valid = contract.verify(signer, data, signature);
            assert_eq!(is_valid, true);
        }
    }
}
