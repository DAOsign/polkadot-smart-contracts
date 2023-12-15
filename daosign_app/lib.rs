#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
pub mod daosign_app {
    use daosign_eip712::daosign_eip712::{
        DAOsignEIP712, EIP712Domain, EIP712ProofOfAgreement, EIP712ProofOfAuthority,
        EIP712ProofOfSignature, ProofOfAgreement, ProofOfAuthority, ProofOfSignature,
    };
    use ink::prelude::string::String;
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

            // TODO: emit event
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

            // TODO: emit event
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

            // TODO: emit event
        }

        #[ink(message)]
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

        #[ink(message)]
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
        fn store_proof_of_authority() {
            let mut instance = DAOsignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0; 32],
                verifying_contract: [0; 32].into(),
            });

            let timestamp: u64 = 1702607225;
            let timestamp_bytes = timestamp.to_be_bytes();
            let mut timestamp_arr: [u8; 32] = [0; 32];
            timestamp_arr[24..].copy_from_slice(&timestamp_bytes);

            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let mut from_arr: [u8; 32] = [0; 32];
            from_arr[12..].copy_from_slice(&from);

            let signature = <[u8; 65]>::from_hex("c3a39ec8c1a6512af4691ff38f085c3e7409c59fa890c71f64303eee0f91a962383ec70c7df38790b1cc82ee13447f44a24abf8affbb806cf5e883f286facf611b").unwrap();
            let proof_cid = String::from("QmbuRibrtidhy9rJuFUjafKG7dDhwDEctc2oWr3NGVxKrd");

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
        }
    }
}
