#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod daosign_eip712 {
    use ink::prelude::{string::String, vec::Vec};
    use scale::{Decode, Encode};

    //
    // structs definitions
    //

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712Domain {
        name: String,
        version: String,
        chain_id: u128,
        verifying_contract: AccountId,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Signer {
        addr: AccountId,
        metadata: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfAuthority {
        name: String,
        from: AccountId,
        agreement_cid: String,
        signers: Vec<Signer>,
        app: String,
        timestamp: u128,
        metadata: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfSignature {
        name: String,
        signer: AccountId,
        agreement_cid: String,
        app: String,
        timestamp: u128,
        metadata: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfAgreement {
        agreement_cid: String,
        signature_cids: Vec<String>,
        app: String,
        timestamp: u128,
        metadata: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712PropertyType {
        name: String,
        kind: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfAuthorityTypes {
        eip712_domain: Vec<EIP712PropertyType>,
        signer: Vec<EIP712PropertyType>,
        proof_of_authority: Vec<EIP712PropertyType>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfAuthority {
        types: EIP712ProofOfAuthorityTypes,
        domain: EIP712Domain,
        primary_type: String,
        message: ProofOfAuthority,
    }

    #[derive(Default, Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfSignatureTypes {
        eip712_domain: Vec<EIP712PropertyType>,
        proof_of_signature: Vec<EIP712PropertyType>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfSignature {
        types: EIP712ProofOfSignatureTypes,
        domain: EIP712Domain,
        primary_type: String,
        message: ProofOfSignature,
    }

    #[derive(Default, Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfAgreementTypes {
        eip712_domain: Vec<EIP712PropertyType>,
        proof_of_agreement: Vec<EIP712PropertyType>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfAgreement {
        types: EIP712ProofOfAgreementTypes,
        domain: EIP712Domain,
        primary_type: String,
        message: ProofOfAgreement,
    }

    //
    // DAOsignEIP712 contract
    //

    #[ink(storage)]
    pub struct DAOsignEIP712 {
        // bytes32 DOMAIN_HASH;
        // EIP712Domain domain;
        proof_of_authority_types: EIP712ProofOfAuthorityTypes,
        proof_of_signature_types: EIP712ProofOfSignatureTypes,
        proof_of_agreement_types: EIP712ProofOfAgreementTypes,
    }

    impl DAOsignEIP712 {
        #[ink(constructor)]
        pub fn new() -> Self {
            let mut instance = Self {
                proof_of_authority_types: EIP712ProofOfAuthorityTypes::default(),
                proof_of_signature_types: EIP712ProofOfSignatureTypes::default(),
                proof_of_agreement_types: EIP712ProofOfAgreementTypes::default(),
            };
            instance.init_eip712_types();
            instance
        }

        fn init_eip712_types(&mut self) -> () {
            // Initialize EIP712Domain types
            let domain_types = vec![
                EIP712PropertyType {
                    name: "name".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "version".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "chainId".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "verifyingContract".to_string(),
                    kind: "address".to_string(),
                },
            ];

            // Initialize Signer types
            let signer_types = vec![
                EIP712PropertyType {
                    name: "addr".to_string(),
                    kind: "address".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ];

            // Initialize ProofOfAuthority types
            let proof_of_authority_types = vec![
                EIP712PropertyType {
                    name: "name".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "from".to_string(),
                    kind: "address".to_string(),
                },
                EIP712PropertyType {
                    name: "agreementCID".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "signers".to_string(),
                    kind: "Signer[]".to_string(),
                },
                EIP712PropertyType {
                    name: "app".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "timestamp".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ];

            // Initialize ProofOfSignature types
            let proof_of_signature_types = vec![
                EIP712PropertyType {
                    name: "name".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "signer".to_string(),
                    kind: "address".to_string(),
                },
                EIP712PropertyType {
                    name: "agreementCID".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "app".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "timestamp".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ];

            // Initialize ProofOfAgreement types
            let proof_of_agreement_types = vec![
                EIP712PropertyType {
                    name: "agreementCID".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "signatureCIDs".to_string(),
                    kind: "string[]".to_string(),
                },
                EIP712PropertyType {
                    name: "app".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "timestamp".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ];

            // Set the types in the contract's storage
            self.proof_of_authority_types.eip712_domain = domain_types.clone();
            self.proof_of_authority_types.signer = signer_types.clone();
            self.proof_of_authority_types.proof_of_authority = proof_of_authority_types.clone();

            self.proof_of_signature_types.eip712_domain = domain_types.clone();
            self.proof_of_signature_types.proof_of_signature = proof_of_signature_types.clone();

            self.proof_of_agreement_types.eip712_domain = domain_types;
            self.proof_of_agreement_types.proof_of_agreement = proof_of_agreement_types;
        }
    }

    impl DAOsignEIP712 {
        #[ink(message)]
        pub fn hash(&self) -> [u8; 32] {
            [1; 32]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn hash() {
            let instance = DAOsignEIP712::new();
            assert_eq!(instance.hash(), [1; 32]);
        }
    }
}
