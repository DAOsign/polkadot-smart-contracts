#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
pub mod daosign_eip712 {
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
        pub name: String,
        pub version: String,
        // As max size in Rust is u128 comparing to u256 in Solidity, chain_id is defined as an
        // array of u8 of size 32 rather than u128. This is done to not loose precision
        pub chain_id: [u8; 32],
        // As we're storing Solidity address here (and in other structs), we will use [u8; 32]
        // instead of AccountId
        pub verifying_contract: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Signer {
        addr: [u8; 32],
        metadata: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfAuthority {
        name: String,
        from: [u8; 32],
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
        signer: [u8; 32],
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

    #[derive(Debug)]
    #[ink(storage)]
    pub struct DAOsignEIP712 {
        domain_hash: [u8; 32],
        domain: EIP712Domain,
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
                domain: domain.clone(),
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
        pub fn plus1(&self, x: u128) -> u128 {
            x + 1
        }

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

        #[ink(message)]
        pub fn recover_proof_of_authority(
            &self,
            data: ProofOfAuthority,
            signature: [u8; 65],
        ) -> [u8; 20] {
            let packet_hash = self.hash_proof_of_authority(data);

            // Encode the packet hash with the domain hash
            let mut encoded = Vec::new();
            encoded.extend_from_slice(b"\x19\x01");
            encoded.extend_from_slice(&self.domain_hash);
            encoded.extend_from_slice(&packet_hash);

            let digest = Self::keccak_hash_bytes(&encoded);

            self.recover(digest, signature)
        }

        #[ink(message)]
        pub fn recover_proof_of_signature(
            &self,
            data: ProofOfSignature,
            signature: [u8; 65],
        ) -> [u8; 20] {
            let packet_hash = self.hash_proof_of_signature(data);

            // Encode the packet hash with the domain hash
            let mut encoded = Vec::new();
            encoded.extend_from_slice(b"\x19\x01");
            encoded.extend_from_slice(&self.domain_hash);
            encoded.extend_from_slice(&packet_hash);

            let digest = Self::keccak_hash_bytes(&encoded);

            self.recover(digest, signature)
        }

        #[ink(message)]
        pub fn recover_proof_of_agreement(
            &self,
            data: ProofOfAgreement,
            signature: [u8; 65],
        ) -> [u8; 20] {
            let packet_hash = self.hash_proof_of_agreement(data);

            // Encode the packet hash with the domain hash
            let mut encoded = Vec::new();
            encoded.extend_from_slice(b"\x19\x01");
            encoded.extend_from_slice(&self.domain_hash);
            encoded.extend_from_slice(&packet_hash);

            let digest = Self::keccak_hash_bytes(&encoded);

            self.recover(digest, signature)
        }

        #[ink(message)]
        pub fn to_eip712_message_proof_of_authority(
            &self,
            message: ProofOfAuthority,
        ) -> EIP712ProofOfAuthority {
            EIP712ProofOfAuthority {
                types: self.proof_of_authority_types.clone(),
                domain: self.domain.clone(),
                primary_type: "ProofOfAuthority".to_string(),
                message,
            }
        }

        #[ink(message)]
        pub fn to_eip712_message_proof_of_signature(
            &self,
            message: ProofOfSignature,
        ) -> EIP712ProofOfSignature {
            EIP712ProofOfSignature {
                types: self.proof_of_signature_types.clone(),
                domain: self.domain.clone(),
                primary_type: "ProofOfSignature".to_string(),
                message,
            }
        }

        #[ink(message)]
        pub fn to_eip712_message_proof_of_agreement(
            &self,
            message: ProofOfAgreement,
        ) -> EIP712ProofOfAgreement {
            EIP712ProofOfAgreement {
                types: self.proof_of_agreement_types.clone(),
                domain: self.domain.clone(),
                primary_type: "ProofOfAgreement".to_string(),
                message,
            }
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
        fn hash_proof_of_authority() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Fisrt Proof-of-Authority
            //

            // prepare timestamp
            let timestamp1: u64 = 1701975136;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signers
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let data1 = ProofOfAuthority {
                name: String::from("Proof-of-Authority"),
                from: signer1_arr,
                agreement_cid: String::from("agreement file cid                            "),
                signers: Vec::from([Signer {
                    addr: signer1_arr,
                    metadata: String::from("{}"),
                }]),
                app: String::from("daosign"),
                timestamp: timestamp1_arr,
                metadata: String::from("proof metadata"),
            };

            let expected_hash1 = <[u8; 32]>::from_hex(
                "982eeb361acc7f0d6402a812683b34e53f1e59f239fb32156e8b0bd2f9dfd039",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_authority(data1), expected_hash1);

            //
            // Second Proof-of-Authority
            //
            // prepare timestamp
            let timestamp2: u64 = 1701975136;
            let timestamp2_bytes = timestamp2.to_be_bytes();
            let mut timestamp2_arr: [u8; 32] = [0; 32];
            timestamp2_arr[24..].copy_from_slice(&timestamp2_bytes);

            // prepare signers
            let signer2 = <[u8; 20]>::from_hex("70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
            let mut signer2_arr: [u8; 32] = [0; 32];
            signer2_arr[12..].copy_from_slice(&signer2);

            let data2 = ProofOfAuthority {
                name: String::from("Proof-of-Authority"),
                from: signer1_arr,
                agreement_cid: String::from("QmbuRibrtidhy9rJuFUjafKG7dDhwDEctc2oWr3NGVxKrd"),
                signers: Vec::from([
                    Signer {
                        addr: signer1_arr,
                        metadata: String::from("custom metadata #1"),
                    },
                    Signer {
                        addr: signer2_arr,
                        metadata: String::from("metadata #2"),
                    },
                ]),
                app: String::from("daosign"),
                timestamp: timestamp2_arr,
                metadata: String::from("proof metadata"),
            };

            let expected_hash2 = <[u8; 32]>::from_hex(
                "7764e27376e6d1a8e28583b6bda4bdabce356f493348688fe3ec5d0344700935",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_authority(data2), expected_hash2);
        }

        #[ink::test]
        fn hash_proof_of_signature() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1701984120;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signers
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let data1 = ProofOfSignature {
                name: String::from("Proof-of-Signature"),
                signer: signer1_arr,
                agreement_cid: String::from("ProofOfAuthority proof cid                    "),
                app: String::from("daosign"),
                timestamp: timestamp1_arr,
                metadata: String::from("proof metadata"),
            };

            let expected_hash1 = <[u8; 32]>::from_hex(
                "73c2ba7034333fee702ce484bdc6c9d0229bc46f5593b557869e497e5045352c",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_signature(data1), expected_hash1);
        }

        #[ink::test]
        fn hash_proof_of_agreement() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Simple Proof-of-Agreement
            //

            // prepare timestamp
            let timestamp1: u64 = 1701984586;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            let data1 = ProofOfAgreement {
                agreement_cid: String::from("agreementCID                                  "),
                signature_cids: Vec::from([
                    String::from("signatureCID0                                 "),
                    String::from("signatureCID1                                 "),
                ]),
                app: String::from("daosign"),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
            };

            let expected_hash1: [u8; 32] = <[u8; 32]>::from_hex(
                "b5f4a49baad54521096e836a8dceefccf8e3d69ae39e0d5ea3860e31d98b6372",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_agreement(data1), expected_hash1);

            //
            // Looong metadata test + the same CIDs
            //

            // prepare timestamp
            let timestamp2: u64 = 1701984586;
            let timestamp2_bytes = timestamp2.to_be_bytes();
            let mut timestamp2_arr: [u8; 32] = [0; 32];
            timestamp2_arr[24..].copy_from_slice(&timestamp2_bytes);

            let data2 = ProofOfAgreement {
                agreement_cid: String::from("signatureCID0                                 "),
                signature_cids: Vec::from([
                    String::from("signatureCID0                                 "),
                    String::from("signatureCID0                                 "),
                ]),
                app: String::from("daosign"),
                timestamp: timestamp2_arr,
                metadata: String::from("[{'constant':true,'inputs':[],'name':'name','outputs':[{'name':'','type':'string'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':false,'inputs':[{'name':'_spender','type':'address'},{'name':'_value','type':'uint256'}],'name':'approve','outputs':[{'name':'','type':'bool'}],'payable':false,'stateMutability':'nonpayable','type':'function'},{'constant':true,'inputs':[],'name':'totalSupply','outputs':[{'name':'','type':'uint256'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':false,'inputs':[{'name':'_from','type':'address'},{'name':'_to','type':'address'},{'name':'_value','type':'uint256'}],'name':'transferFrom','outputs':[{'name':'','type':'bool'}],'payable':false,'stateMutability':'nonpayable','type':'function'},{'constant':true,'inputs':[],'name':'decimals','outputs':[{'name':'','type':'uint8'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':true,'inputs':[{'name':'_owner','type':'address'}],'name':'balanceOf','outputs':[{'name':'balance','type':'uint256'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':true,'inputs':[],'name':'symbol','outputs':[{'name':'','type':'string'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':false,'inputs':[{'name':'_to','type':'address'},{'name':'_value','type':'uint256'}],'name':'transfer','outputs':[{'name':'','type':'bool'}],'payable':false,'stateMutability':'nonpayable','type':'function'},{'constant':true,'inputs':[{'name':'_owner','type':'address'},{'name':'_spender','type':'address'}],'name':'allowance','outputs':[{'name':'','type':'uint256'}],'payable':false,'stateMutability':'view','type':'function'},{'payable':true,'stateMutability':'payable','type':'fallback'},{'anonymous':false,'inputs':[{'indexed':true,'name':'owner','type':'address'},{'indexed':true,'name':'spender','type':'address'},{'indexed':false,'name':'value','type':'uint256'}],'name':'Approval','type':'event'},{'anonymous':false,'inputs':[{'indexed':true,'name':'from','type':'address'},{'indexed':true,'name':'to','type':'address'},{'indexed':false,'name':'value','type':'uint256'}],'name':'Transfer','type':'event'}]"),
            };

            let expected_hash2: [u8; 32] = <[u8; 32]>::from_hex(
                "7732dfecbf18bf462c5c246643b734fa0d31f785f55de7c970e64bf0092f0a46",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_agreement(data2), expected_hash2);
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

        #[ink::test]
        fn recover_proof_of_authority() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1701990045;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signer & signature
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let signature1 = <[u8; 65]>::from_hex("65cc7b7ba2a2c61cddd5522a65e0a01fc8b5e0846adc743cf7874bc99a68f76072439f0eac2d61e9d4f59b8e8c40c35c50d645d2c2ea6cb2cfed34e0c05373b01b").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let message1 = ProofOfAuthority {
                name: String::from("Proof-of-Authority"),
                from: signer1_arr,
                agreement_cid: String::from("agreementCID                                  "),
                signers: Vec::from([Signer {
                    addr: signer1_arr,
                    metadata: String::from("metadata"),
                }]),
                app: String::from("daosign"),
                timestamp: timestamp1_arr,
                metadata: String::from("metadatas"),
            };

            assert_eq!(
                instance.recover_proof_of_authority(message1, signature1),
                signer1
            );
        }

        #[ink::test]
        fn recover_proof_of_signature() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1701990355;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signer & signature
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let signature1 = <[u8; 65]>::from_hex("acc5ef63564dcb4273272e9e52fb6ab585cfdf366187c1ff26c55d028fccad4803e9ed36739373c2ea4c27123fbc4a07504fd0512379a13a590f80213bb81e6b1b").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let message1 = ProofOfSignature {
                name: String::from("Proof-of-Signature"),
                signer: signer1_arr,
                agreement_cid: String::from("agreementCID                                  "),
                app: String::from("daosign"),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
            };

            assert_eq!(
                instance.recover_proof_of_signature(message1, signature1),
                signer1
            );
        }

        #[ink::test]
        fn recover_proof_of_agreement() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1701990469;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signer & signature
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let signature1 = <[u8; 65]>::from_hex("7a6510c1ee7785a2019ea2ad009086fea5a3baa25f349c00a14707891ff9d0752c90a694d342010b52975501acf7f98abbe7640e8d685e73608118212eac432f1b").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let message1 = ProofOfAgreement {
                agreement_cid: String::from("agreementCID                                  "),
                signature_cids: Vec::from([
                    String::from("signatureCID0                                 "),
                    String::from("signatureCID1                                 "),
                ]),
                app: String::from("daosign"),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
            };

            assert_eq!(
                instance.recover_proof_of_agreement(message1, signature1),
                signer1
            );
        }
    }
}
