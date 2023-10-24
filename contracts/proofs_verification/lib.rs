#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs_verification {
    use ink::prelude::vec::Vec;
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
            // Convert data hash to Etereum signed message format
            let msg_hash = Self::to_eth_signed_message_hash(data_hash);

            // Recover ECDSA signature
            let mut uncompressed_public_key = [0; 33];
            let _ = ink_env::ecdsa_recover(&signature, &msg_hash, &mut uncompressed_public_key);
            ink::env::debug_println!("uncompressed_public_key {:?}", uncompressed_public_key);

            // Public key to Eth address
            let mut account_id_bytes = [0; 20];
            let _ = ink_env::ecdsa_to_eth_address(&uncompressed_public_key, &mut account_id_bytes);

            // Validate that recovered Eth address matches the expected address
            if signer
                == AccountId::from({
                    let mut tmp = [0u8; 32];
                    tmp[12..].copy_from_slice(&account_id_bytes);
                    tmp
                })
            {
                return true;
            }
            false
        }

        fn to_eth_signed_message_hash(data_hash: [u8; 32]) -> [u8; 32] {
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

            msg_hash
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hex::FromHex;

        #[ink::test]
        fn constructor() {
            let _ = ProofsVerification::new();
        }

        #[ink::test]
        fn verify_any_signature() {
            let contract = ProofsVerification::new();

            // Note: accounds, messages, and signatures are taken from DAOsign Solidity implementation
            let signer_1: AccountId = AccountId::from(
                <[u8; 32]>::from_hex("00".repeat(12) + "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
                    .unwrap(),
            );
            let signer_2: AccountId = AccountId::from(
                <[u8; 32]>::from_hex("00".repeat(12) + "90F79bf6EB2c4f870365E785982E1f101E93b906")
                    .unwrap(),
            );
            let message_1: [u8; 32] = <[u8; 32]>::from_hex(
                "49145797d5b241d1bc807fddde38d675212624d4556f22246bde8be447967f8e",
            )
            .unwrap();
            let message_2: [u8; 32] = <[u8; 32]>::from_hex(
                "0413d1a7675fa28b9c504ace913dc39e627894d5775c840a06a245d500ce5009",
            )
            .unwrap();
            let signature_1: [u8; 65] = <[u8; 65]>::from_hex("1fccf4ff11872b0426c7b7826db58b876d9d02d78759b5a7bccc1035f451248b5369ccbebc00094043f55746733f975dfbf7c2000c204853a9ea38ebccf8eb101c").unwrap();
            let signature_2: [u8; 65] = <[u8; 65]>::from_hex("78ed8734ca4fc72cedfdb2eee4080cc0e2802dc12a7cac5906839a96dd60f0ea4e05fcfab9181fffa5a694a02ca0ba3eee87a842ffc64c66a8fd0ff6780db0c31b").unwrap();

            // correct signer of message1
            let is_valid = contract.verify(signer_1, message_1, signature_1);
            assert_eq!(is_valid, true);

            // wrong signer of message1
            let is_valid = contract.verify(signer_2, message_1, signature_1);
            assert_eq!(is_valid, false);

            // correct signer of message2
            let is_valid = contract.verify(signer_2, message_2, signature_2);
            assert_eq!(is_valid, true);

            // wrong signer of message2
            let is_valid = contract.verify(signer_1, message_2, signature_2);
            assert_eq!(is_valid, false);

            // wrong signature of message2
            let is_valid = contract.verify(signer_1, message_2, signature_1);
            assert_eq!(is_valid, false);
        }

        #[ink::test]
        fn verify_signed_proof() {
            let contract = ProofsVerification::new();

            let signer_1: AccountId = AccountId::from(
                <[u8; 32]>::from_hex("00".repeat(12) + "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
                    .unwrap(),
            );
            let signer_2: AccountId = AccountId::from(
                <[u8; 32]>::from_hex("00".repeat(12) + "90F79bf6EB2c4f870365E785982E1f101E93b906")
                    .unwrap(),
            );
            let string_data = String::from("{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint64\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],\"Agreement\":[{\"name\":\"from\",\"type\":\"address\"},{\"name\":\"agreementFileCID\",\"type\":\"string\"},{\"name\":\"signers\",\"type\":\"Signers\"},{\"name\":\"app\",\"type\":\"string\"},{\"name\":\"timestamp\",\"type\":\"uint64\"},{\"name\":\"metadata\",\"type\":\"string\"}],\"Signers\":[{\"name\":\"address\",\"type\":\"string\"},{\"name\":\"metadata\",\"type\":\"string\"}]},\"domain\":{\"name\":\"daosign\",\"version\":\"0.1.0\"},\"primaryType\":\"Agreement\",\"message\":{\"from\":\"0x70997970C51812dc3A010C7d01b50e0d17dc79C8\",\"agreementFileCID\":\"QmQY5XFRomrnAD3o3yMWkTz1HWcCfZYuE87Gbwe7SjV1kk\",\"signers\":[\"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC\",\"0x90F79bf6EB2c4f870365E785982E1f101E93b906\",\"0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65\"],\"app\":\"daosign\",\"timestamp\":1698106902,\"metadata\":{}}}");
            let data = string_data.into_bytes();

            let poa_signature1: [u8; 65] = <[u8; 65]>::from_hex(
                "355e26d4e5dc8586d916bc795fea15e9034b33a5cb9086ef3e7e5dd7800babb65da380e2a32684370a52937d6553e54010a7df7ccba9de3d6bfa2150785cddc81c",
            )
            .unwrap();
            let poa_signature2: [u8; 65] = <[u8; 65]>::from_hex(
                "89a325f3d371a0db456532c2b907243c48c608b2898c1eee39cbb99a752f313360a4e59e3dcc6548319774187af8df424721e82e40f6dc2edee81ef723ebd94e1c",
            )
            .unwrap();

            // correct signer of the proof
            let is_valid = contract.verify_signed_proof(signer_1, data.clone(), poa_signature1);
            assert_eq!(is_valid, true);
            let is_valid = contract.verify_signed_proof(signer_2, data.clone(), poa_signature2);
            assert_eq!(is_valid, true);
            // wrong signer of the proof
            let is_valid = contract.verify_signed_proof(signer_2, data.clone(), poa_signature1);
            assert_eq!(is_valid, false);
            let is_valid = contract.verify_signed_proof(signer_1, data.clone(), poa_signature2);
            assert_eq!(is_valid, false);
        }
    }
}
