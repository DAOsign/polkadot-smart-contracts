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
        // As max size in Rust is u128 comparing to u256 in Solidity, chain_id is defined as an
        // array of u8 of size 32 rather than u128. This is done to not loose precision
        chain_id: [u8; 32],
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
        // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
        timestamp: [u8; 32],
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
        // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
        timestamp: [u8; 32],
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
        // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
        timestamp: [u8; 32],
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
            instance.init_typehashes();
            instance.init_domainhash(domain);
            instance.init_eip712_types();
            instance
        }

        fn init_domainhash(&mut self, domain: EIP712Domain) -> () {
            self.domain_hash = self.hash_domain(domain);
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

        fn keccak_hash_bytes(input: &[u8]) -> [u8; 32] {
            let mut keccak = Keccak::v256();
            let mut output = [0u8; 32];
            keccak.update(input);
            keccak.finalize(&mut output);
            output
        }
    }

    impl DAOsignEIP712 {
        #[ink(message)]
        pub fn hash_domain(&self, data: EIP712Domain) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.eip712domain_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(data.name.as_str()));
            encoded_data.extend_from_slice(&Self::keccak_hash(data.version.as_str()));
            encoded_data.extend_from_slice(data.chain_id.as_slice());
            encoded_data.extend_from_slice(data.verifying_contract.encode().as_slice());

            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn hash_signer(&self, data: Signer) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.signer_typehash.as_slice());
            encoded_data.extend_from_slice(data.addr.encode().as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata.as_str()));

            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn hash_signers(&self, data: Vec<Signer>) -> [u8; 32] {
            let mut encoded_data = Vec::new();
            for signer in data.iter() {
                encoded_data.extend_from_slice(&self.hash_signer(signer.clone()));
            }
            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn hash_proof_of_authority(&self, data: ProofOfAuthority) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.proof_of_authority_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.name));
            encoded_data.extend_from_slice(data.from.encode().as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
            encoded_data.extend_from_slice(&self.hash_signers(data.signers));
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.app));
            encoded_data.extend_from_slice(data.timestamp.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn hash_proof_of_signature(&self, data: ProofOfSignature) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.proof_of_signature_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.name));
            encoded_data.extend_from_slice(data.signer.encode().as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.app));
            encoded_data.extend_from_slice(data.timestamp.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn hash_strings(&self, data: Vec<String>) -> [u8; 32] {
            let mut encoded_data = Vec::new();
            for string in data.iter() {
                encoded_data.extend_from_slice(&Self::keccak_hash(string));
            }
            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn hash_proof_of_agreement(&self, data: ProofOfAgreement) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.proof_of_agreement_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
            encoded_data.extend_from_slice(&self.hash_strings(data.signature_cids));
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.app));
            encoded_data.extend_from_slice(data.timestamp.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

            Self::keccak_hash_bytes(&encoded_data)
        }

        #[ink(message)]
        pub fn recover(&self, message: [u8; 32], sig: [u8; 65]) -> [u8; 20] {
            // Recover the public key from the signature
            let mut uncompressed_public_key = [0; 33];
            let _ = ink::env::ecdsa_recover(&sig, &message, &mut uncompressed_public_key);

            // Convert public key to Ethereum address
            let mut account_id_bytes = [0; 20];
            let _ = ink::env::ecdsa_to_eth_address(&uncompressed_public_key, &mut account_id_bytes);

            account_id_bytes
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
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            // Test domain hash
            assert_eq!(
                instance.domain_hash,
                <[u8; 32]>::from_hex(
                    "98670852334fc8f702b23d30e8b0adf9084b364869f775b23e9b89e3c50390c0",
                )
                .unwrap()
            );

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
        fn recover() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            // Note: accounds, messages, and signatures are taken from DAOsign Solidity implementation
            let signer_1 =
                <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let message_1 = <[u8; 32]>::from_hex(
                "b4ba9fa5bd01eac4ecd44891aaf6393135b1f6591d58ee35c6ed8ec659c8e70a",
            )
            .unwrap();
            let signature_1 = <[u8; 65]>::from_hex("554077fec636b586196831bd072559673dc34af8aea2cd98b05de209934fa7f034c5bc8da3c314c0cc0fa94dd70e31406fbb167b52a8ac9d916d0d30275ed6b41b").unwrap();
            let message_2 = <[u8; 32]>::from_hex(
                "c95811b04c82d394fb0bce7b59316f7932db448a15cbae7d74f3f8df0284fe01",
            )
            .unwrap();
            let signature_2 = <[u8; 65]>::from_hex("db447694c8688c5b057d131f90cde25ec656fee4467c78243063e98e37523799311df7f7527b6d3eba0c84d6d5faa9f257e837496890f545a2a4d10611ce6d331c").unwrap();

            assert_eq!(instance.recover(message_1, signature_1), signer_1);
            assert_eq!(instance.recover(message_2, signature_2), signer_1);
        }
    }
}
