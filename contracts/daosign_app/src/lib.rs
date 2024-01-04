#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
pub mod daosign_app {
    use daosign_eip712::daosign_eip712::{
        DAOsignEIP712, EIP712Domain, EIP712ProofOfAgreement, EIP712ProofOfAuthority,
        EIP712ProofOfSignature, ProofOfAgreement, ProofOfAuthority, ProofOfSignature,
    };
    use ink::prelude::{string::String, vec::Vec};
    use ink::storage::Mapping;
    use scale::{Decode, Encode};

    const IPFS_CID_LENGTH: usize = 46;
    const ZERO_ADDR: [u8; 32] = [0u8; 32];
    //
    // structs definition
    //

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedProofOfAuthority {
        message: ProofOfAuthority,
        signature: Vec<u8>,
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedProofOfAuthorityMsg {
        message: EIP712ProofOfAuthority,
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedProofOfSignature {
        message: ProofOfSignature,
        signature: Vec<u8>,
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedProofOfSignatureMsg {
        message: EIP712ProofOfSignature,
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedProofOfAgreement {
        message: ProofOfAgreement,
        signature: Vec<u8>,
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedProofOfAgreementMsg {
        message: EIP712ProofOfAgreement,
        signature: Vec<u8>,
    }

    //
    // DAOsignApp contract
    //

    #[ink(event)]
    pub struct NewProofOfAuthority {
        data: SignedProofOfAuthority,
    }

    #[ink(event)]
    pub struct NewProofOfSignature {
        data: SignedProofOfSignature,
    }

    #[ink(event)]
    pub struct NewProofOfAgreement {
        data: SignedProofOfAgreement,
    }

    #[ink(storage)]
    pub struct DAOsignApp {
        eip712: DAOsignEIP712,
        poaus: Mapping<String, SignedProofOfAuthority>,
        posis: Mapping<String, SignedProofOfSignature>,
        poags: Mapping<String, SignedProofOfAgreement>,
        proof2signer: Mapping<String, [u8; 32]>,
        poau_signers_idx: Mapping<(String, [u8; 32]), u32>,
    }

    impl DAOsignApp {
        fn vec_to_array(vec: Vec<u8>) -> Result<[u8; 65], &'static str> {
            if vec.len() == 65 {
                let array: [u8; 65] = vec.try_into().map_err(|_| "Conversion failed")?;
                Ok(array)
            } else {
                Err("Vector does not have exactly 65 elements")
            }
        }
    }

    impl DAOsignApp {
        #[ink(constructor)]
        pub fn new(domain: EIP712Domain) -> Self {
            let eip712 = DAOsignEIP712::new(domain);
            Self {
                eip712,
                poaus: Mapping::new(),
                posis: Mapping::new(),
                poags: Mapping::new(),
                proof2signer: Mapping::new(),
                poau_signers_idx: Mapping::new(),
            }
        }

        #[ink(message)]
        pub fn get_5(&self) -> u128 {
            5
        }

        #[ink(message)]
        pub fn store_proof_of_authority(&mut self, data: SignedProofOfAuthority) {
            // convert address stored in 32 bytes to 20 bytes
            let from_arr20: [u8; 20] = data.message.from[12..].try_into().unwrap();
            assert!(
                self.eip712.recover_proof_of_authority(
                    data.message.clone(),
                    DAOsignApp::vec_to_array(data.signature.clone()).unwrap()
                ) == from_arr20,
                "Invalid signature"
            );

            // Validate the data
            assert!(
                self.validate_signed_proof_of_authority(data.clone()),
                "Invalid message"
            );

            // Store
            self.poaus.insert(data.proof_cid.clone(), &data.clone());

            // Update the signer indices and push new signers
            for (i, signer) in data.message.signers.iter().enumerate() {
                self.poau_signers_idx
                    .insert((data.proof_cid.clone(), signer.addr), &(i as u32));
            }

            // Update proof to signer mapping
            self.proof2signer
                .insert(data.proof_cid.clone(), &data.message.from);

            Self::env().emit_event(NewProofOfAuthority { data });
        }

        #[ink(message)]
        pub fn store_proof_of_signature(&mut self, data: SignedProofOfSignature) {
            // convert address stored in 32 bytes to 20 bytes
            let from_arr20: [u8; 20] = data.message.signer[12..].try_into().unwrap();
            assert!(
                self.eip712.recover_proof_of_signature(
                    data.message.clone(),
                    DAOsignApp::vec_to_array(data.signature.clone()).unwrap()
                ) == from_arr20,
                "Invalid signature"
            );

            // Validate the data
            assert!(
                self.validate_signed_proof_of_signature(data.clone()),
                "Invalid message"
            );

            // Store
            self.posis.insert(data.proof_cid.clone(), &data.clone());

            // Update proof to signer mapping
            self.proof2signer
                .insert(data.proof_cid.clone(), &data.message.signer);

            Self::env().emit_event(NewProofOfSignature { data });
        }

        #[ink(message)]
        pub fn store_proof_of_agreement(&mut self, data: SignedProofOfAgreement) {
            // Validate the data
            assert!(
                self.validate_signed_proof_of_agreement(data.clone()),
                "Invalid message"
            );

            // Store
            self.poags.insert(data.proof_cid.clone(), &data.clone());

            Self::env().emit_event(NewProofOfAgreement { data });
        }

        #[ink(message)]
        pub fn get_proof_of_authority(&self, cid: String) -> SignedProofOfAuthority {
            self.poaus.get(cid).unwrap()
        }

        #[ink(message)]
        pub fn get_proof_of_signature(&self, cid: String) -> SignedProofOfSignature {
            self.posis.get(cid).unwrap()
        }

        #[ink(message)]
        pub fn get_proof_of_agreement(&self, cid: String) -> SignedProofOfAgreement {
            self.poags.get(cid).unwrap()
        }

        pub fn validate_signed_proof_of_authority(&self, data: SignedProofOfAuthority) -> bool {
            assert!(data.proof_cid.len() == IPFS_CID_LENGTH, "Invalid proof CID");
            assert!(data.message.app == "daosign", "Invalid app name");
            assert!(
                data.message.name == "Proof-of-Authority",
                "Invalid proof name"
            );
            assert!(
                data.message.agreement_cid.len() == IPFS_CID_LENGTH,
                "Invalid agreement CID"
            );
            for signer in data.message.signers.iter() {
                assert!(signer.addr != ZERO_ADDR, "Invalid signer");
            }
            true
        }

        pub fn validate_signed_proof_of_signature(&self, data: SignedProofOfSignature) -> bool {
            assert!(data.proof_cid.len() == IPFS_CID_LENGTH, "Invalid proof CID");
            assert!(data.message.app == "daosign", "Invalid app name");
            assert!(
                data.message.name == "Proof-of-Signature",
                "Invalid proof name"
            );

            let i: usize = self
                .poau_signers_idx
                .get((&data.message.agreement_cid, &data.message.signer))
                .unwrap()
                .try_into()
                .unwrap();
            assert!(
                self.poaus
                    .get(&data.message.agreement_cid)
                    .unwrap()
                    .message
                    .signers[i]
                    .addr
                    == data.message.signer,
                "Invalid signer"
            );

            true
        }

        pub fn validate_signed_proof_of_agreement(&self, data: SignedProofOfAgreement) -> bool {
            assert!(data.proof_cid.len() == IPFS_CID_LENGTH, "Invalid proof CID");
            assert!(data.message.app == "daosign", "Invalid app name");
            assert!(
                self.poaus
                    .get(&data.message.agreement_cid)
                    .unwrap()
                    .message
                    .name
                    == "Proof-of-Authority",
                "Invalid Proof-of-Authority name"
            );
            assert!(
                self.poaus
                    .get(&data.message.agreement_cid)
                    .unwrap()
                    .message
                    .signers
                    .len()
                    == data.message.signature_cids.len(),
                "Invalid Proofs-of-Signatures length"
            );

            for (_, signature_cid) in data.message.signature_cids.iter().enumerate() {
                let idx: usize = self
                    .poau_signers_idx
                    .get((
                        &data.message.agreement_cid,
                        &self.posis.get(signature_cid).unwrap().message.signer,
                    ))
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(
                    self.poaus
                        .get(&data.message.agreement_cid)
                        .unwrap()
                        .message
                        .signers[idx]
                        .addr
                        == self.posis.get(signature_cid).unwrap().message.signer,
                    "Invalid Proofs-of-Signature signer"
                );
            }

            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use daosign_eip712::daosign_eip712::Signer;
        use hex::FromHex;

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
