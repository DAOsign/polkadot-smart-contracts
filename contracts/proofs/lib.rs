#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs {
    use scale::{Decode, Encode};

    /// The Proofs error types
    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ProofsError {
        // ZeroAddress, // Address provided is not defined
    }

    #[ink(storage)]
    #[derive(PartialEq)]
    pub struct Proofs {
        proofs_metadata: AccountId,
    }

    impl Proofs {
        #[ink(constructor)]
        pub fn new(proofs_metadata: AccountId) -> Self {
            if proofs_metadata == Self::zero_address() {
                panic!("Zero address provided");
            }
            Self { proofs_metadata }
        }

        #[ink(message)]
        pub fn get_proofs_metadata(&self) -> AccountId {
            self.proofs_metadata
        }

        fn zero_address() -> AccountId {
            [0u8; 32].into()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        #[should_panic(expected = "Zero address provided")]
        fn constructor_error() {
            let _ = Proofs::new(/* zero address */ [0u8; 32].into());
        }

        #[ink::test]
        fn constructor_success() {
            let proofs = Proofs::new([1u8; 32].into());
            assert_eq!(proofs.proofs_metadata, [1u8; 32].into());
        }
    }
}
