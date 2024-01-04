#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
pub mod daosign_app {
    use daosign_eip712::daosign_eip712::{
        DAOsignEIP712, EIP712Domain, EIP712ProofOfAgreement, EIP712ProofOfAuthority,
        EIP712ProofOfSignature, ProofOfAgreement, ProofOfAuthority, ProofOfSignature,
    };
    use ink::prelude::{string::String, vec::Vec};
    use ink::storage::traits::StorageLayout;
    use ink::storage::Mapping;
    use scale::{Decode, Encode};

    const IPFS_CID_LENGTH: usize = 46;
    const ZERO_ADDR: [u8; 32] = [0u8; 32];

    //
    // structs definition
    //

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct SignedProofOfAuthority {
        message: ProofOfAuthority,
        signature: Vec<u8>,
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct SignedProofOfAuthorityMsg {
        message: EIP712ProofOfAuthority,
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct SignedProofOfSignature {
        message: ProofOfSignature,
        signature: Vec<u8>,
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct SignedProofOfSignatureMsg {
        message: EIP712ProofOfSignature,
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct SignedProofOfAgreement {
        message: ProofOfAgreement,
        signature: Vec<u8>,
        proof_cid: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
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
        use ink::env::debug_println;

        fn store_proof_of_authority(instance: &mut DAOsignApp) {
            let timestamp: u64 = 1702609459;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut from_arr: [u8; 32] = [0; 32];
            from_arr[12..].copy_from_slice(&from);

            let signature = <[u8; 65]>::from_hex("130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c").unwrap();
            let proof_cid = String::from("ProofOfAuthority proof cid                    ");

            instance.store_proof_of_authority(SignedProofOfAuthority {
                message: ProofOfAuthority {
                    name: String::from("Proof-of-Authority"),
                    from: from_arr,
                    agreement_cid: String::from("agreement file cid                            "),
                    signers: Vec::from([Signer {
                        addr: from_arr,
                        metadata: String::from("some metadata"),
                    }]),
                    app: String::from("daosign"),
                    timestamp: timestamp_arr,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            });
        }

        fn store_proof_of_signature(instance: &mut DAOsignApp) {
            let timestamp: u64 = 1702609048;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let signer = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut signer_arr: [u8; 32] = [0; 32];
            signer_arr[12..].copy_from_slice(&signer);

            let signature = <[u8; 65]>::from_hex("3873d49c83039d1624ec52ee6f6edbe0d31105a7aebcd1304e8326adc0807c3e692efc2b302370dbc0c7ea44904130e3468ff34ff1eaf65613ad8ba6db9405e31c").unwrap();
            let proof_cid = String::from("ProofOfSignature proof cid                    ");

            instance.store_proof_of_signature(SignedProofOfSignature {
                message: ProofOfSignature {
                    name: String::from("Proof-of-Signature"),
                    signer: signer_arr,
                    agreement_cid: String::from("ProofOfAuthority proof cid                    "),
                    app: String::from("daosign"),
                    timestamp: timestamp_arr,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            });
        }

        fn store_proof_of_agreement(instance: &mut DAOsignApp) {
            let timestamp: u64 = 1702609773;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let signature = <[u8; 65]>::from_hex("4f43008200f6dea8f74ec205d874593885872158406c2ef0f71dbe2459ba9118667d10451069d5015fc005c88b2337240c8f02edf904e08b4abf723dc20998a91b").unwrap();
            let proof_cid = String::from("ProofOfAgreement proof cid                    ");

            instance.store_proof_of_agreement(SignedProofOfAgreement {
                message: ProofOfAgreement {
                    agreement_cid: String::from("ProofOfAuthority proof cid                    "),
                    signature_cids: Vec::from([String::from(
                        "ProofOfSignature proof cid                    ",
                    )]),
                    app: String::from("daosign"),
                    timestamp: timestamp_arr,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            });
        }

        #[ink::test]
        fn test_store_proof_of_authority() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            let timestamp: u64 = 1702609459;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);
            debug_println!("{:?}", timestamp_arr);

            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut from_arr: [u8; 32] = [0; 32];
            from_arr[12..].copy_from_slice(&from);
            debug_println!("{:?}", from_arr);

            let signature = <[u8; 65]>::from_hex("130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c").unwrap();
            debug_println!("{:?}", signature);
            let proof_cid = String::from("ProofOfAuthority proof cid                    ");

            let data = SignedProofOfAuthority {
                message: ProofOfAuthority {
                    name: String::from("Proof-of-Authority"),
                    from: from_arr,
                    agreement_cid: String::from("agreement file cid                            "),
                    signers: Vec::from([Signer {
                        addr: from_arr,
                        metadata: String::from("some metadata"),
                    }]),
                    app: String::from("daosign"),
                    timestamp: timestamp_arr,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            };
            instance.store_proof_of_authority(data.clone());

            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().signature,
                signature
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().proof_cid,
                proof_cid.clone()
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().message.name,
                String::from("Proof-of-Authority")
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().message.from,
                from_arr
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .agreement_cid,
                String::from("agreement file cid                            ")
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signers
                    .len(),
                1
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signers[0]
                    .addr,
                from_arr
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signers[0]
                    .metadata,
                String::from("some metadata")
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().message.app,
                String::from("daosign")
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .timestamp,
                timestamp_arr
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .metadata,
                String::from("proof metadata")
            );

            // Test emitted event
            let mut events = ink::env::test::recorded_events();
            let event = events.next().unwrap();
            let mut ev_data = event.data;
            ev_data.remove(0);
            assert_eq!(data.encode(), ev_data);
        }

        #[ink::test]
        fn test_store_proof_of_signature() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Pre-test
            //

            store_proof_of_authority(&mut instance);

            //
            // Test
            //

            let timestamp: u64 = 1702609048;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let signer = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut signer_arr: [u8; 32] = [0; 32];
            signer_arr[12..].copy_from_slice(&signer);

            let signature = <[u8; 65]>::from_hex("3873d49c83039d1624ec52ee6f6edbe0d31105a7aebcd1304e8326adc0807c3e692efc2b302370dbc0c7ea44904130e3468ff34ff1eaf65613ad8ba6db9405e31c").unwrap();
            let proof_cid = String::from("ProofOfSignature proof cid                    ");

            let data = SignedProofOfSignature {
                message: ProofOfSignature {
                    name: String::from("Proof-of-Signature"),
                    signer: signer_arr,
                    agreement_cid: String::from("ProofOfAuthority proof cid                    "),
                    app: String::from("daosign"),
                    timestamp: timestamp_arr,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            };
            instance.store_proof_of_signature(data.clone());

            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().signature,
                signature
            );
            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().proof_cid,
                proof_cid.clone()
            );

            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().message.name,
                String::from("Proof-of-Signature")
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signer,
                signer_arr
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .agreement_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().message.app,
                String::from("daosign")
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .timestamp,
                timestamp_arr
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .metadata,
                String::from("proof metadata")
            );

            // Test emitted event
            let mut events = ink::env::test::recorded_events();
            events.next(); // skipping NewProofOfAuthority event
            let event = events.next().unwrap();
            let mut ev_data = event.data;
            ev_data.remove(0);
            assert_eq!(data.encode(), ev_data);
        }

        #[ink::test]
        fn test_store_proof_of_agreement() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Pre-test
            //

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);

            //
            // Test
            //

            let timestamp: u64 = 1702609773;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let signature = <[u8; 65]>::from_hex("4f43008200f6dea8f74ec205d874593885872158406c2ef0f71dbe2459ba9118667d10451069d5015fc005c88b2337240c8f02edf904e08b4abf723dc20998a91b").unwrap();
            let proof_cid = String::from("ProofOfAgreement proof cid                    ");

            let data = SignedProofOfAgreement {
                message: ProofOfAgreement {
                    agreement_cid: String::from("ProofOfAuthority proof cid                    "),
                    signature_cids: Vec::from([String::from(
                        "ProofOfSignature proof cid                    ",
                    )]),
                    app: String::from("daosign"),
                    timestamp: timestamp_arr,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            };
            instance.store_proof_of_agreement(data.clone());

            assert_eq!(
                instance.poags.get(proof_cid.clone()).unwrap().signature,
                signature
            );
            assert_eq!(
                instance.poags.get(proof_cid.clone()).unwrap().proof_cid,
                proof_cid.clone()
            );

            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .agreement_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signature_cids
                    .len(),
                1
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signature_cids[0],
                String::from("ProofOfSignature proof cid                    ")
            );
            assert_eq!(
                instance.poags.get(proof_cid.clone()).unwrap().message.app,
                String::from("daosign")
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .timestamp,
                timestamp_arr
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .metadata,
                String::from("proof metadata")
            );

            // Test emitted event
            let mut events = ink::env::test::recorded_events();
            events.next(); // skipping NewProofOfAuthority event
            events.next(); // skipping NewProofOfSignature event
            let event = events.next().unwrap();
            let mut ev_data = event.data;
            ev_data.remove(0);
            assert_eq!(data.encode(), ev_data);
        }

        #[ink::test]
        fn test_get_proof_of_authority() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Pre-test. Store Proof-of-Authority
            //
            let timestamp: u64 = 1702609459;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut from_arr: [u8; 32] = [0; 32];
            from_arr[12..].copy_from_slice(&from);

            let signature = <[u8; 65]>::from_hex("130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c").unwrap();
            let proof_cid = String::from("ProofOfAuthority proof cid                    ");

            store_proof_of_authority(&mut instance);

            //
            // Get Proof-of-Authority
            //
            let proof = instance.get_proof_of_authority(proof_cid.clone());

            assert_eq!(proof.signature, signature);
            assert_eq!(proof.proof_cid, proof_cid.clone());
            assert_eq!(proof.message.name, String::from("Proof-of-Authority"));
            assert_eq!(proof.message.from, from_arr);
            assert_eq!(
                proof.message.agreement_cid,
                String::from("agreement file cid                            ")
            );
            assert_eq!(proof.message.signers.len(), 1);
            assert_eq!(proof.message.signers[0].addr, from_arr);
            assert_eq!(
                proof.message.signers[0].metadata,
                String::from("some metadata")
            );
            assert_eq!(proof.message.app, String::from("daosign"));
            assert_eq!(proof.message.timestamp, timestamp_arr);
            assert_eq!(proof.message.metadata, String::from("proof metadata"));
        }

        #[ink::test]
        fn test_get_proof_of_signature() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Pre-test. Store Proof-of-Signature
            //
            let timestamp: u64 = 1702609048;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let signer = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut signer_arr: [u8; 32] = [0; 32];
            signer_arr[12..].copy_from_slice(&signer);

            let signature = <[u8; 65]>::from_hex("3873d49c83039d1624ec52ee6f6edbe0d31105a7aebcd1304e8326adc0807c3e692efc2b302370dbc0c7ea44904130e3468ff34ff1eaf65613ad8ba6db9405e31c").unwrap();
            let proof_cid = String::from("ProofOfSignature proof cid                    ");

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);

            //
            // Get Proof-of-Signature
            //
            let proof = instance.get_proof_of_signature(proof_cid.clone());

            assert_eq!(proof.signature, signature);
            assert_eq!(proof.proof_cid, proof_cid.clone());

            assert_eq!(proof.message.name, String::from("Proof-of-Signature"));
            assert_eq!(proof.message.signer, signer_arr);
            assert_eq!(
                proof.message.agreement_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(proof.message.app, String::from("daosign"));
            assert_eq!(proof.message.timestamp, timestamp_arr);
            assert_eq!(proof.message.metadata, String::from("proof metadata"));
        }

        #[ink::test]
        fn test_get_proof_of_agreement() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            //
            // Pre-test. Store Proof-of-Agreement
            //
            let timestamp: u64 = 1702609773;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);
            store_proof_of_agreement(&mut instance);

            //
            // Get Proof-of-Agreement
            //
            let timestamp: u64 = 1702609773;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let signature = <[u8; 65]>::from_hex("4f43008200f6dea8f74ec205d874593885872158406c2ef0f71dbe2459ba9118667d10451069d5015fc005c88b2337240c8f02edf904e08b4abf723dc20998a91b").unwrap();
            let proof_cid = String::from("ProofOfAgreement proof cid                    ");

            let proof = instance.get_proof_of_agreement(proof_cid.clone());

            assert_eq!(proof.signature, signature);
            assert_eq!(proof.proof_cid, proof_cid.clone());

            assert_eq!(
                proof.message.agreement_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(proof.message.signature_cids.len(), 1);
            assert_eq!(
                proof.message.signature_cids[0],
                String::from("ProofOfSignature proof cid                    ")
            );
            assert_eq!(proof.message.app, String::from("daosign"));
            assert_eq!(proof.message.timestamp, timestamp_arr);
            assert_eq!(proof.message.metadata, String::from("proof metadata"));
        }
    }
}
