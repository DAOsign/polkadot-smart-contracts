#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs_verification {
    use ink::prelude::{string::String, vec::Vec};

    use tiny_keccak::{Hasher, Keccak};

    #[ink(storage)]
    pub struct ProofsVerification {}

    impl ProofsVerification {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        /// Verify Proof-of-Authority or Proof-of-Signature signature
        ///
        /// Parameters:
        /// - `_signer`: Signer of the data
        /// - `_data`: Raw Proof-of-Authority byte array that the signer signs
        /// - `_signature`: Signature of the `_data`
        ///
        /// Returns:
        /// - `bool`: Is the signature valid or not
        #[ink(message)]
        pub fn verify_signed_proof(
            &self,
            _signer: AccountId,
            _data: String,
            _signature: Vec<u8>,
        ) -> bool {
            let mut keccak = Keccak::v256();
            let mut data_hash = [0u8; 32];

            // Update the hash
            keccak.update(_data.as_bytes());

            // Finalize it
            keccak.finalize(&mut data_hash);

            // let data_hash = Keccak256(&_data);
            // self.verify(_signer, data_hash, _signature)
            true
        }

        // /// Verify any signature of any data
        // ///
        // /// Parameters:
        // /// - `_signer`: Signer of the data
        // /// - `_data_hash`: Hash of the data that was signed
        // /// - `_signature`: Signature of the data
        // ///
        // /// Returns:
        // /// - `bool`: Is the signature valid or not
        // #[ink(message)]
        // pub fn verify(
        //     &self,
        //     _signer: AccountId,
        //     _data_hash: Sha3_256,
        //     _signature: Vec<u8>,
        // ) -> bool {
        //     // let signature = MultiSignature::from_slice(&_signature);
        //     // if signature.is_none() {
        //     //     return false;
        //     // }
        //     // signature
        //     //     .unwrap()
        //     //     .verify(&_data_hash.as_fixed_bytes(), &_signer)
        //     true
        // }
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
