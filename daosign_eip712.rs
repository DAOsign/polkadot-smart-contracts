#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod daosign_eip712 {
    use hex::FromHex;
    use ink::prelude::{string::String, vec::Vec};
    use scale::{Decode, Encode};
    use tiny_keccak::{Hasher, Keccak};

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
        domain_hash: [u8; 32],
        eip712domain_typehash: [u8; 32],
        signer_typehash: [u8; 32],
        proof_of_authority_typehash: [u8; 32],
        proof_of_signature_typehash: [u8; 32],
        proof_of_agreement_typehash: [u8; 32],
        proof_of_authority_types: EIP712ProofOfAuthorityTypes,
        proof_of_signature_types: EIP712ProofOfSignatureTypes,
        proof_of_agreement_types: EIP712ProofOfAgreementTypes,
    }

    impl DAOsignEIP712 {
        #[ink(constructor)]
        pub fn new(domain: EIP712Domain) -> Self {
            let mut instance = Self {
                domain_hash: [0; 32],
                eip712domain_typehash: [0; 32],
                signer_typehash: [0; 32],
                proof_of_authority_typehash: [0; 32],
                proof_of_signature_typehash: [0; 32],
                proof_of_agreement_typehash: [0; 32],
                proof_of_authority_types: EIP712ProofOfAuthorityTypes::default(),
                proof_of_signature_types: EIP712ProofOfSignatureTypes::default(),
                proof_of_agreement_types: EIP712ProofOfAgreementTypes::default(),
            };
            instance.init_domainhash(domain);
            instance.init_typehashes();
            instance.init_eip712_types();
            instance
        }

        fn init_domainhash(&mut self, domain: EIP712Domain) -> () {
            // TODO: use hash function
            self.domain_hash = Self::keccak_hash("");
        }

        fn init_typehashes(&mut self) -> () {
            self.eip712domain_typehash = Self::keccak_hash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
            self.signer_typehash = Self::keccak_hash("Signer(address addr,string metadata)");
            self.proof_of_authority_typehash = Self::keccak_hash("ProofOfAuthority(string name,address from,string agreementCID,Signer[] signers,string app,uint256 timestamp,string metadata)Signer(address addr,string metadata)");
            self.proof_of_signature_typehash = Self::keccak_hash("ProofOfSignature(string name,address signer,string agreementCID,string app,uint256 timestamp,string metadata)");
            self.proof_of_agreement_typehash = Self::keccak_hash("ProofOfAgreement(string agreementCID,string[] signatureCIDs,string app,uint256 timestamp,string metadata)");
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

        fn keccak_hash(input: &str) -> [u8; 32] {
            let mut keccak = Keccak::v256();
            let mut output = [0u8; 32];
            keccak.update(input.as_bytes());
            keccak.finalize(&mut output);
            output
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
        fn constructor() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 0,
                verifying_contract: [0; 32].into(),
            });

            // Test typehashes
            assert_eq!(
                instance.eip712domain_typehash,
                <[u8; 32]>::from_hex(
                    "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f",
                )
                .unwrap()
            );
            assert_eq!(
                instance.signer_typehash,
                <[u8; 32]>::from_hex(
                    "67aa40d26f889f44ec5fecd21b812b43af0974bbc5e74283b01e36ceb272966f",
                )
                .unwrap()
            );
            assert_eq!(
                instance.proof_of_authority_typehash,
                <[u8; 32]>::from_hex(
                    "8f114d1a21f1f0a7cbd7762e89178eff7aebe129bd6e17c5ba78039f051a7fd4",
                )
                .unwrap()
            );
            assert_eq!(
                instance.proof_of_signature_typehash,
                <[u8; 32]>::from_hex(
                    "6fef47b94b61b28c42811a67d3c72900a80a641dc7de99d8a9943e5bf6f6a274",
                )
                .unwrap()
            );
            assert_eq!(
                instance.proof_of_agreement_typehash,
                <[u8; 32]>::from_hex(
                    "2d150e81098c40977881d8ba98e4cecf43b28d790b59c176028dd6f16f9ee628",
                )
                .unwrap()
            );

            // Test Proof-of-Authority
            assert_eq!(
                instance.proof_of_authority_types.eip712_domain.len() > 0,
                true
            );
            assert_eq!(instance.proof_of_authority_types.signer.len() > 0, true);
            assert_eq!(
                instance.proof_of_authority_types.proof_of_authority.len() > 0,
                true
            );

            // Test Proof-of-Signature
            assert_eq!(
                instance.proof_of_signature_types.eip712_domain.len() > 0,
                true
            );
            assert_eq!(
                instance.proof_of_signature_types.proof_of_signature.len() > 0,
                true
            );

            // Test Proof-of-Agreement
            assert_eq!(
                instance.proof_of_agreement_types.eip712_domain.len() > 0,
                true
            );
            assert_eq!(
                instance.proof_of_agreement_types.proof_of_agreement.len() > 0,
                true
            );
        }

        #[ink::test]
        fn hash() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 0,
                verifying_contract: [0; 32].into(),
            });
            assert_eq!(instance.hash(), [1; 32]);
        }
    }
}
