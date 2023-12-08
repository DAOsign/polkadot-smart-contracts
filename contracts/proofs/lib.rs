#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs {
    use ink::prelude::string::String;
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use proofs_metadata::proofs_metadata::ProofsMetadata;
    use scale::{Decode, Encode};

    /// The Proofs error types
    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ProofsError {
        EmptyAddress,
        EmptySigners,
        EmptyString,
    }

    #[derive(Debug, PartialEq, Eq, Copy, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ProofTypes {
        Proof1, // Define your specific proof types here.
    }

    #[ink(storage)]
    pub struct Proofs {
        proofs_metadata_addr: AccountId,
        proofs_data: Mapping<(AccountId, Vec<AccountId>, String, String), String>,
        final_proofs: Mapping<(String, String), String>,
    }

    impl Proofs {
        #[ink(constructor)]
        pub fn new(proofs_metadata_addr: AccountId) -> Self {
            if proofs_metadata_addr == Self::zero_address() {
                panic!("Zero address provided");
            }
            Self {
                proofs_metadata_addr,
                final_proofs: Default::default(),
                proofs_data: Default::default(),
            }
        }

        #[ink(message)]
        pub fn get_proofs_metadata_addr(&self) -> AccountId {
            self.proofs_metadata_addr
        }

        #[ink(message)]
        pub fn fetch_proof_of_authority(
            &mut self,
            creator: AccountId,
            signers: Vec<AccountId>,
            file_cid: String,
            version: String,
        ) -> Result<String, ProofsError> {
            let data = self
                .proofs_data
                .get((creator, signers.clone(), file_cid.clone(), version.clone()))
                .unwrap_or_default();
            if data.len() > 0 {
                return Ok(data);
            }

            assert_ne!(creator, Self::zero_address(), "Zero address");
            assert!(!signers.is_empty(), "No signers");
            assert!(!file_cid.is_empty(), "No Agreement File CID");
            assert!(!version.is_empty(), "No version");

            let proofs_metadata_contract: ProofsMetadata =
                ink_env::call::FromAccountId::from_account_id(self.proofs_metadata_addr);

            // let proofs_metadata_contract = ContractId<ProofsMetadataTrait>

            // let metadata = self
            //     .store
            //     .get(&self.slot_proof_metadata(ProofTypes::ProofOfAuthority, &version))
            //     .unwrap_or_default();

            // let mut message = format!(
            //     "    \"from\": \"{}\",\n\
            //  \"agreementFileCID\": \"{}\",\n\
            //  \"signers\": {},\n\
            //  \"app\": \"daosign\",\n\
            //  \"timestamp\": {},\n\
            //  \"metadata\": {{}},\n",
            //     creator.to_string(),
            //     file_cid,
            //     addrs_to_str(&signers),
            //     Self::current_epoch(),
            // );

            // let data = format!("{}  \"message\": {{\n{}}}\n}}", metadata, message);

            // self.store.insert(slot, data.clone());
            // proofsData[_agreementFileCID][ProofTypes.Proofs.ProofOfAuthority][_creator] = proofData;

            Ok(String::from("data"))
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
