#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod daosign_ink {
    // use ink::prelude::string::String;

    /// The ProofsMetadata error types
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        EmptyInputParams, // Input params cannot be empty
        MetadataExists,   // Metadata already exists
        NoMetadata,       // Metadata does not exist
    }

    #[derive(scale::Encode, scale::Decode)]
    pub enum ProofTypes {
        ProofOfAuthority,
        ProofOfSignature,
        ProofOfAgreement,
    }

    /// ProofsMetadata result type
    pub type Result<T> = core::result::Result<T, Error>;

    /// Trait for ProofsMetadata
    #[ink::trait_definition]
    pub trait ProofsMetadata {
        #[ink(message)]
        fn get_metadata_num_of_versions(&self, _type: ProofTypes) -> u128;

        #[ink(message)]
        fn add_metadata(&mut self, _type: ProofTypes, _version: String, _metadata: String) -> Result<()>;

        #[ink(message)]
        fn force_update_metadata(&mut self, _type: ProofTypes, _version: String, _metadata: String) -> Result<()>;
    }

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct DaosignInk {
        /// Stores a single `bool` value on the storage.
        value: bool, 
    }

    impl DaosignInk {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(init_value: bool) -> Self {
            Self { value: init_value }
        }

        /// Constructor that initializes the `bool` value to `false`.
        ///
        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new(Default::default())
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        #[ink(message)]
        pub fn flip(&mut self) {
            self.value = !self.value;
        }

        /// Simply returns the current value of our `bool`.
        #[ink(message)]
        pub fn get(&self) -> bool {
            self.value
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {
            let daosign_ink = DaosignInk::default();
            assert_eq!(daosign_ink.get(), false);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            let mut daosign_ink = DaosignInk::new(false);
            assert_eq!(daosign_ink.get(), false);
            daosign_ink.flip();
            assert_eq!(daosign_ink.get(), true);
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
