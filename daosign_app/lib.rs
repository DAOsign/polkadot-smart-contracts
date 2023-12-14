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
        pub fn plus3(&self, x: u128) -> u128 {
            self.eip712.plus1(x) + 2
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
