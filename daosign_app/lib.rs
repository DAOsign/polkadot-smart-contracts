#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
pub mod daosign_app {
    use daosign_eip712::daosign_eip712::{
        DAOsignEIP712, EIP712Domain, EIP712ProofOfAgreement, EIP712ProofOfAuthority,
        EIP712ProofOfSignature, ProofOfAgreement, ProofOfAuthority, ProofOfSignature,
    };
    use ink::prelude::string::String;
    use scale::{Decode, Encode};

    //
    // structs definition
    //

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedProofOfAuthority {
        message: ProofOfAuthority,
        signature: [u8; 65],
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedProofOfAuthorityMsg {
        message: EIP712ProofOfAuthority,
        signature: [u8; 65],
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedProofOfSignature {
        message: ProofOfSignature,
        signature: [u8; 65],
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedProofOfSignatureMsg {
        message: EIP712ProofOfSignature,
        signature: [u8; 65],
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedProofOfAgreement {
        message: ProofOfAgreement,
        signature: [u8; 65],
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedProofOfAgreementMsg {
        message: EIP712ProofOfAgreement,
        signature: [u8; 65],
    }

    //
    // DAOsignApp contract
    //

    #[ink(storage)]
    pub struct DAOsignApp {
        eip712: DAOsignEIP712,
    }

    impl DAOsignApp {
        #[ink(constructor)]
        pub fn new(domain: EIP712Domain) -> Self {
            Self {
                eip712: DAOsignEIP712::new(domain),
            }
        }

        #[ink(message)]
        pub fn plus3(&self, x: u128) -> u128 {
            self.eip712.plus1(x) + 2
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_plus3() {
            let instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });
            assert_eq!(instance.plus3(5), 8);
            // assert_eq!(1 + 1, 2);
        }
    }
}
