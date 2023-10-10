#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proofs_metadata {
    use ink::prelude::string::String;
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use scale::{Decode, Encode};

    /// The ProofsMetadata error types
    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ProofsMetadataError {
        EmptyInputParams, // Input params cannot be empty
        MetadataExists,   // Metadata already exists
        NoMetadata,       // Metadata does not exist
    }

    #[derive(Debug, Encode, Decode, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub enum ProofTypes {
        ProofOfAuthority,
        ProofOfSignature,
        ProofOfAgreement,
    }

    /// ProofsMetadata result type
    pub type Result<T> = core::result::Result<T, ProofsMetadataError>;

    #[ink(storage)]
    #[derive(Default)]
    pub struct ProofsMetadata {
        // proof type -> version -> metadata
        proofs_metadata: Mapping<(ProofTypes, String), String>,
        // proof type -> history of versions
        metadata_versions: Mapping<ProofTypes, Vec<String>>,
    }

    /// Trait for ProofsMetadata
    #[ink::trait_definition]
    pub trait ProofsMetadataTrait {
        #[ink(message)]
        fn proofs_metadata(&self, _type: ProofTypes, _version: String) -> String;

        #[ink(message)]
        fn metadata_versions(&self, _type: ProofTypes, _index: u32) -> String;

        #[ink(message)]
        fn get_metadata_num_of_versions(&self, _type: ProofTypes) -> u32;

        #[ink(message)]
        fn add_metadata(&mut self, _type: ProofTypes, _version: String, _metadata: String) -> Result<()>;

        #[ink(message)]
        fn force_update_metadata(&mut self, _type: ProofTypes, _version: String, _metadata: String) -> Result<()>;
    }

    // Events
    #[ink(event)]
    pub struct MetadataAdded {
        #[ink(topic)]
        proof_type: ProofTypes,
        #[ink(topic)]
        version: String,
        metadata: String,
    }

    impl ProofsMetadata {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                proofs_metadata: Default::default(),
                metadata_versions: Default::default(),
            }
        }
    }

    impl ProofsMetadataTrait for ProofsMetadata {
        #[ink(message)]
        fn proofs_metadata(&self, _type: ProofTypes, _version: String) -> String {
            self.proofs_metadata.get((_type, _version)).unwrap_or_default()
        }

        #[ink(message)]
        fn metadata_versions(&self, _type: ProofTypes, _index: u32) -> String {
            self.metadata_versions.get(_type).unwrap_or_default()[_index as usize].clone()
        }

        #[ink(message)]
        fn get_metadata_num_of_versions(&self, _type: ProofTypes) -> u32 {
            self.metadata_versions.get(_type).unwrap_or_default().len() as u32
        }

        #[ink(message)]
        fn add_metadata(&mut self, _type: ProofTypes, _version: String, _metadata: String) -> Result<()> {
            if _version.len() == 0 || _metadata.len() == 0 {
                return Err(ProofsMetadataError::EmptyInputParams)
            }
            if self.proofs_metadata.get((_type.clone(), _version.clone())).unwrap_or_default().len() > 0 {
                return Err(ProofsMetadataError::MetadataExists)
            }

            self.proofs_metadata.insert((_type.clone(), _version.clone()), &_metadata.clone());
            self.metadata_versions.get(_type.clone()).unwrap_or_default().push(_version.clone());
            
            Self::env().emit_event(MetadataAdded {
                proof_type: _type.clone(),
                version: _version.clone(),
                metadata: _metadata.clone(),
            });

            Ok(())
        }

        #[ink(message)]
        fn force_update_metadata(&mut self, _type: ProofTypes, _version: String, _metadata: String) -> Result<()> {
            if _version.len() == 0 || _metadata.len() == 0 {
                return Err(ProofsMetadataError::EmptyInputParams)
            }
            if self.proofs_metadata.get((_type.clone(), _version.clone())).unwrap_or_default().len() == 0 {
                return Err(ProofsMetadataError::NoMetadata)
            }

            self.proofs_metadata.insert((_type.clone(), _version.clone()), &_metadata.clone());

            Self::env().emit_event(MetadataAdded {
                proof_type: _type.clone(),
                version: _version.clone(),
                metadata: _metadata.clone(),
            });

            Ok(())
        }
    }

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    // #[ink(storage)]
    // pub struct DaosignInk {
    //     /// Stores a single `bool` value on the storage.
    //     value: bool,
    // }

    // impl DaosignInk {
    //     /// Constructor that initializes the `bool` value to the given `init_value`.
    //     #[ink(constructor)]
    //     pub fn new(init_value: bool) -> Self {
    //         Self { value: init_value }
    //     }

    //     /// Constructor that initializes the `bool` value to `false`.
    //     ///
    //     /// Constructors can delegate to other constructors.
    //     #[ink(constructor)]
    //     pub fn default() -> Self {
    //         Self::new(Default::default())
    //     }

    //     /// A message that can be called on instantiated contracts.
    //     /// This one flips the value of the stored `bool` from `true`
    //     /// to `false` and vice versa.
    //     #[ink(message)]
    //     pub fn flip(&mut self) {
    //         self.value = !self.value;
    //     }

    //     /// Simply returns the current value of our `bool`.
    //     #[ink(message)]
    //     pub fn get(&self) -> bool {
    //         self.value
    //     }
    // }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn constructor() {
            let proofs_metadata = ProofsMetadata::default();
            assert_eq!(proofs_metadata.proofs_metadata.get((ProofTypes::ProofOfAuthority, "")).unwrap_or_default(), "");
            assert_eq!(proofs_metadata.metadata_versions.get(ProofTypes::ProofOfSignature).unwrap_or_default().len(), 0);
        }

        // /// We test a simple use case of our contract.
        // #[ink::test]
        // fn it_works() {
        //     let mut daosign_ink = DaosignInk::new(false);
        //     assert_eq!(daosign_ink.get(), false);
        //     daosign_ink.flip();
        //     assert_eq!(daosign_ink.get(), true);
        // }

        #[ink::test]
        fn only_owner() {
            let mut proofs_metadata = ProofsMetadata::default();
            // Simulate the owner and anyone else
            // let owner = AccountId::from([0x01; 32]);
            // let anyone = AccountId::from([0x02; 32]);

            // // Set the contract caller to 'anyone'
            // set_sender(anyone);
            // assert_eq!(
            //     proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "0.1.0".into(), "{}".into()),
            //     Err(ProofsMetadataError::NotOwner)
            // );

            // Set the contract caller to 'owner'
            // set_sender(owner);
            assert_eq!(
                proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "0.1.0".into(), "{}".into()),
                Ok(())
            );
        }

        #[ink::test]
        fn empty_input_params() {
            let mut proofs_metadata = ProofsMetadata::default();
            assert_eq!(
                proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "".into(), "{}".into()),
                Err(ProofsMetadataError::EmptyInputParams)
            );
            assert_eq!(
                proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "0.1.0".into(), "".into()),
                Err(ProofsMetadataError::EmptyInputParams)
            );
        }

        #[ink::test]
        fn metadata_already_exists() {
            let mut proofs_metadata = ProofsMetadata::default();
            assert_eq!(
                proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "0.1.0".into(), "{}".into()),
                Ok(())
            );
            assert_eq!(
                proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "0.1.0".into(), "{}".into()),
                Err(ProofsMetadataError::MetadataExists)
            );
        }

        #[ink::test]
        fn success_emits_an_event() {
            let mut proofs_metadata = ProofsMetadata::default();
            assert_eq!(
                proofs_metadata.add_metadata(ProofTypes::ProofOfAuthority, "0.1.0".into(), "{}".into()),
                Ok(())
            );
            // TODO: Check emitted event (you'll need to implement event checking)
        }
    }

    /// This is how you'd write end-to-end (E2E) or integration tests for ink! contracts.
    ///
    /// When running these you need to make sure that you:
    /// - Compile the tests with the `e2e-tests` feature flag enabled (`--features e2e-tests`)
    /// - Are running a Substrate node which contains `pallet-contracts` in the background
    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// A helper function used for calling contract messages.
        use ink_e2e::build_message;

        /// The End-to-End test `Result` type.
        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        /// We test that we can upload and instantiate the contract using its default constructor.
        #[ink_e2e::test]
        async fn default_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let constructor = DaosignInkRef::default();

            // When
            let contract_account_id = client
                .instantiate("daosign_ink", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // Then
            let get = build_message::<DaosignInkRef>(contract_account_id.clone())
                .call(|daosign_ink| daosign_ink.get());
            let get_result = client.call_dry_run(&ink_e2e::alice(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), false));

            Ok(())
        }

        /// We test that we can read and write a value from the on-chain contract contract.
        #[ink_e2e::test]
        async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let constructor = DaosignInkRef::new(false);
            let contract_account_id = client
                .instantiate("daosign_ink", &ink_e2e::bob(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let get = build_message::<DaosignInkRef>(contract_account_id.clone())
                .call(|daosign_ink| daosign_ink.get());
            let get_result = client.call_dry_run(&ink_e2e::bob(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), false));

            // When
            let flip = build_message::<DaosignInkRef>(contract_account_id.clone())
                .call(|daosign_ink| daosign_ink.flip());
            let _flip_result = client
                .call(&ink_e2e::bob(), flip, 0, None)
                .await
                .expect("flip failed");

            // Then
            let get = build_message::<DaosignInkRef>(contract_account_id.clone())
                .call(|daosign_ink| daosign_ink.get());
            let get_result = client.call_dry_run(&ink_e2e::bob(), &get, 0, None).await;
            assert!(matches!(get_result.return_value(), true));

            Ok(())
        }
    }
}