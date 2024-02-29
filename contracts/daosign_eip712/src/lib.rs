#![cfg_attr(not(feature = "std"), no_std, no_main)]

//! # DAOsign EIP-712 Contract
//!
//! This is a helper contract that is used by `daosign_app` which helps to verify EIP-712 signatures,
//! and is tailored specifically to `daosign_app` contract.
#[ink::contract]
pub mod daosign_eip712 {
    use ink::prelude::{
        string::{String, ToString},
        vec::Vec,
    };
    use scale::{Decode, Encode};
    use tiny_keccak::{Hasher, Keccak};

    //
    // Structs definitions
    //

    /// EIP-712 Domain struct representing the domain-specific parameters for signature verification.
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

    /// Signer struct representing an address and associated metadata.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Signer {
        pub addr: [u8; 32],
        pub metadata: String,
    }

    /// ProofOfAuthority struct representing the Proof-of-Authority parameters.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfAuthority {
        pub name: String,
        pub from: [u8; 32],
        pub agreement_cid: String,
        pub signers: Vec<Signer>,
        // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
        pub timestamp: [u8; 32],
        pub metadata: String,
    }

    /// ProofOfSignature struct representing the Proof-of-Signature parameters.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfSignature {
        pub name: String,
        pub signer: [u8; 32],
        pub authority_cid: String,
        // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
        pub timestamp: [u8; 32],
        pub metadata: String,
    }

    /// ProofOfAgreement struct representing the Proof-of-Agreement parameters.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ProofOfAgreement {
        pub authority_cid: String,
        pub signature_cids: Vec<String>,
        // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
        pub timestamp: [u8; 32],
        pub metadata: String,
    }

    /// EIP712PropertyType struct representing the structure of EIP-712 properties.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712PropertyType {
        name: String,
        kind: String,
    }

    /// EIP712ProofOfAuthorityTypes struct representing the types for EIP-712 Proof-of-Authority.
    #[derive(Default, Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfAuthorityTypes {
        pub eip712_domain: Vec<EIP712PropertyType>,
        pub signer: Vec<EIP712PropertyType>,
        pub proof_of_authority: Vec<EIP712PropertyType>,
    }

    /// EIP712ProofOfSignatureTypes struct representing the types for EIP-712 Proof-of-Signature.
    #[derive(Default, Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfSignatureTypes {
        pub eip712_domain: Vec<EIP712PropertyType>,
        pub proof_of_signature: Vec<EIP712PropertyType>,
    }

    /// EIP712ProofOfAgreementTypes struct representing the types for EIP-712 Proof-of-Agreement.
    #[derive(Default, Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct EIP712ProofOfAgreementTypes {
        pub eip712_domain: Vec<EIP712PropertyType>,
        pub proof_of_agreement: Vec<EIP712PropertyType>,
    }

    /// EIP712ProofOfAuthority struct representing the EIP-712 message for Proof-of-Authority.
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

    /// EIP712ProofOfSignature struct representing the EIP-712 message for Proof-of-Signature.
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

    /// EIP712ProofOfAgreement struct representing the EIP-712 message for Proof-of-Agreement.
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

    /// Contract Storage struct
    #[ink(storage)]
    #[derive(Debug)]
    pub struct DAOsignEIP712 {
        pub domain: EIP712Domain,
        pub domain_hash: [u8; 32],
        pub eip712domain_typehash: [u8; 32],
        pub signer_typehash: [u8; 32],
        pub proof_of_authority_typehash: [u8; 32],
        pub proof_of_signature_typehash: [u8; 32],
        pub proof_of_agreement_typehash: [u8; 32],
        pub proof_of_authority_types: EIP712ProofOfAuthorityTypes,
        pub proof_of_signature_types: EIP712ProofOfSignatureTypes,
        pub proof_of_agreement_types: EIP712ProofOfAgreementTypes,
    }

    /// DAOsignEIP712 contract implementation.
    impl DAOsignEIP712 {
        /// # Ink! constructor for creating a new DAOsignEIP712 instance.
        ///
        /// This constructor initializes a new DAOsignEIP712 contract instance with the provided EIP712 domain.
        /// It sets up the domain hash, type hashes, and EIP712 types needed for hashing proofs.
        ///
        /// # Arguments
        ///
        /// * `domain` - EIP712Domain struct representing the domain of the contract.
        ///
        /// # Returns
        ///
        /// A new instance of DAOsignEIP712.
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

        /// # Ink! function to get the hash of an EIP712Domain struct.
        ///
        /// This function takes an EIP712Domain struct and calculates its hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - EIP712Domain struct to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the hash of the EIP712Domain.
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

        /// # Ink! function to get the hash of a Signer struct.
        ///
        /// This function takes a Signer struct and calculates its hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - Signer struct to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the hash of the Signer.
        #[ink(message)]
        pub fn hash_signer(&self, data: Signer) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.signer_typehash.as_slice());
            encoded_data.extend_from_slice(data.addr.encode().as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata.as_str()));

            Self::keccak_hash_bytes(&encoded_data)
        }

        /// # Ink! function to get the hash of an array of Signer structs.
        ///
        /// This function takes an array of Signer structs and calculates their collective hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - Array of Signer structs to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the collective hash of the array of Signers.
        #[ink(message)]
        pub fn hash_signers(&self, data: Vec<Signer>) -> [u8; 32] {
            let mut encoded_data = Vec::new();
            for signer in data.iter() {
                encoded_data.extend_from_slice(&self.hash_signer(signer.clone()));
            }
            Self::keccak_hash_bytes(&encoded_data)
        }

        /// # Ink! function to get the hash of an array of strings.
        ///
        /// This function takes an array of strings and calculates their collective hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - Array of strings to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the collective hash of the array of strings.
        #[ink(message)]
        pub fn hash_strings(&self, data: Vec<String>) -> [u8; 32] {
            let mut encoded_data = Vec::new();
            for string in data.iter() {
                encoded_data.extend_from_slice(&Self::keccak_hash(string));
            }
            Self::keccak_hash_bytes(&encoded_data)
        }

        /// # Ink! function to get the hash of a ProofOfAuthority struct.
        ///
        /// This function takes a ProofOfAuthority struct and calculates its hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - ProofOfAuthority struct to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the hash of the ProofOfAuthority.
        #[ink(message)]
        pub fn hash_proof_of_authority(&self, data: ProofOfAuthority) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.proof_of_authority_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.name));
            encoded_data.extend_from_slice(data.from.encode().as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
            encoded_data.extend_from_slice(&self.hash_signers(data.signers));
            encoded_data.extend_from_slice(data.timestamp.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

            Self::keccak_hash_bytes(&encoded_data)
        }

        /// # Ink! function to get the hash of a ProofOfSignature struct.
        ///
        /// This function takes a ProofOfSignature struct and calculates its hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - ProofOfSignature struct to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the hash of the ProofOfSignature.
        #[ink(message)]
        pub fn hash_proof_of_signature(&self, data: ProofOfSignature) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.proof_of_signature_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.name));
            encoded_data.extend_from_slice(data.signer.encode().as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.authority_cid));
            encoded_data.extend_from_slice(data.timestamp.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

            Self::keccak_hash_bytes(&encoded_data)
        }

        /// # Ink! function to get the hash of a ProofOfAgreement struct.
        ///
        /// This function takes a ProofOfAgreement struct and calculates its hash using the specified encoding rules.
        ///
        /// # Arguments
        ///
        /// * `data` - ProofOfAgreement struct to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the hash of the ProofOfAgreement.
        #[ink(message)]
        pub fn hash_proof_of_agreement(&self, data: ProofOfAgreement) -> [u8; 32] {
            let mut encoded_data = Vec::new();

            encoded_data.extend_from_slice(self.proof_of_agreement_typehash.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.authority_cid));
            encoded_data.extend_from_slice(&self.hash_strings(data.signature_cids));
            encoded_data.extend_from_slice(data.timestamp.as_slice());
            encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

            Self::keccak_hash_bytes(&encoded_data)
        }

        /// # Recover function for retrieving the Ethereum address from an EIP-712 signature.
        ///
        /// This function takes an EIP-712 message hash and its corresponding signature,
        /// then performs ECDSA recovery to obtain the uncompressed public key.
        /// The recovered public key is then converted to an Ethereum address,
        /// and the 20-byte address is returned.
        ///
        /// # Arguments
        ///
        /// * `message` - A 32-byte hash representing the EIP-712 message.
        /// * `sig` - A 65-byte signature obtained from signing the EIP-712 message.
        ///
        /// # Returns
        ///
        /// A 20-byte array representing the Ethereum address recovered from the signature.
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

        /// # Recover function for Proof of Authority, retrieving the Ethereum address from a signature.
        ///
        /// This function takes a ProofOfAuthority struct, computes its hash, and uses it to create a
        /// compound message for ECDSA recovery. The signature and message are then passed to the recover
        /// function to obtain the Ethereum address.
        ///
        /// # Arguments
        ///
        /// * `data` - ProofOfAuthority struct containing information about the authority proof.
        /// * `signature` - A 65-byte signature obtained from signing the ProofOfAuthority message.
        ///
        /// # Returns
        ///
        /// A 20-byte array representing the Ethereum address recovered from the ProofOfAuthority signature.
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

        /// # Recover function for Proof of Signature, retrieving the Ethereum address from a signature.
        ///
        /// Similar to recover_proof_of_authority, this function takes a ProofOfSignature struct,
        /// computes its hash, and uses it to create a compound message for ECDSA recovery. The signature
        /// and message are then passed to the recover function to obtain the Ethereum address.
        ///
        /// # Arguments
        ///
        /// * `data` - ProofOfSignature struct containing information about the signature proof.
        /// * `signature` - A 65-byte signature obtained from signing the ProofOfSignature message.
        ///
        /// # Returns
        ///
        /// A 20-byte array representing the Ethereum address recovered from the ProofOfSignature signature.
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

        /// # Recover function for Proof of Agreement, retrieving the Ethereum address from a signature.
        ///
        /// Similar to the previous recover functions, this one takes a ProofOfAgreement struct, computes
        /// its hash, and uses it to create a compound message for ECDSA recovery. The signature and message
        /// are then passed to the recover function to obtain the Ethereum address.
        ///
        /// # Arguments
        ///
        /// * `data` - ProofOfAgreement struct containing information about the agreement proof.
        /// * `signature` - A 65-byte signature obtained from signing the ProofOfAgreement message.
        ///
        /// # Returns
        ///
        /// A 20-byte array representing the Ethereum address recovered from the ProofOfAgreement signature.
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

        /// # Convert ProofOfAuthority struct to EIP-712 formatted message.
        ///
        /// This function takes a ProofOfAuthority struct and creates an EIP-712 formatted message.
        ///
        /// # Arguments
        ///
        /// * `message` - ProofOfAuthority struct to be converted to the EIP-712 message format.
        ///
        /// # Returns
        ///
        /// An EIP712ProofOfAuthority struct representing the EIP-712 formatted message for ProofOfAuthority.
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

        /// # Convert ProofOfSignature struct to EIP-712 formatted message.
        ///
        /// Similar to the previous function, this one takes a ProofOfSignature struct and creates
        /// an EIP-712 formatted message.
        ///
        /// # Arguments
        ///
        /// * `message` - ProofOfSignature struct to be converted to the EIP-712 message format.
        ///
        /// # Returns
        ///
        /// An EIP712ProofOfSignature struct representing the EIP-712 formatted message for ProofOfSignature.
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

        /// # Convert ProofOfAgreement struct to EIP-712 formatted message.
        ///
        /// Similar to the previous functions, this one takes a ProofOfAgreement struct and creates
        /// an EIP-712 formatted message.
        ///
        /// # Arguments
        ///
        /// * `message` - ProofOfAgreement struct to be converted to the EIP-712 message format.
        ///
        /// # Returns
        ///
        /// An EIP712ProofOfAgreement struct representing the EIP-712 formatted message for ProofOfAgreement.
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

        /// # Helper function to initialize `domain_hash` variable with DAOsign proofs `domain`.
        ///
        /// This function takes the provided EIP712 domain and calculates its hash, which is then stored in the `domain_hash` variable.
        ///
        /// # Arguments
        ///
        /// * `domain` - EIP712Domain struct representing the domain of the contract.
        fn init_domainhash(&mut self, domain: EIP712Domain) -> () {
            self.domain_hash = self.hash_domain(domain);
        }

        /// # Helper function to initialize hashes of all EIP-712-styled structs. This will be needed
        /// # later on to hash proofs.
        ///
        /// This function initializes the type hashes for EIP712Domain, Signer, Proof-of-Authority, Proof-of-Signature, and Proof-of-Agreement.
        fn init_typehashes(&mut self) -> () {
            self.eip712domain_typehash = Self::keccak_hash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
            self.signer_typehash = Self::keccak_hash("Signer(address addr,string metadata)");
            self.proof_of_authority_typehash = Self::keccak_hash("ProofOfAuthority(string name,address from,string agreementCID,Signer[] signers,uint256 timestamp,string metadata)Signer(address addr,string metadata)");
            self.proof_of_signature_typehash = Self::keccak_hash("ProofOfSignature(string name,address signer,string authorityCID,uint256 timestamp,string metadata)");
            self.proof_of_agreement_typehash = Self::keccak_hash("ProofOfAgreement(string authorityCID,string[] signatureCIDs,uint256 timestamp,string metadata)");
        }

        /// # Helper function to initialize EIP-712, Signer, Proof-of-Authority, Proof-of-Signature, and
        /// # Proof-of-Agreement domain types.
        ///
        /// This function sets up the EIP712 types needed for hashing proofs and stores them in the contract's storage.
        fn init_eip712_types(&mut self) -> () {
            // Initialize EIP712Domain types
            let domain_types = Vec::from([
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
            ]);

            // Initialize Signer types
            let signer_types = Vec::from([
                EIP712PropertyType {
                    name: "addr".to_string(),
                    kind: "address".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ]);

            // Initialize ProofOfAuthority types
            let proof_of_authority_types = Vec::from([
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
                    name: "timestamp".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ]);

            // Initialize ProofOfSignature types
            let proof_of_signature_types = Vec::from([
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
                    name: "timestamp".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ]);

            // Initialize ProofOfAgreement types
            let proof_of_agreement_types = Vec::from([
                EIP712PropertyType {
                    name: "agreementCID".to_string(),
                    kind: "string".to_string(),
                },
                EIP712PropertyType {
                    name: "signatureCIDs".to_string(),
                    kind: "string[]".to_string(),
                },
                EIP712PropertyType {
                    name: "timestamp".to_string(),
                    kind: "uint256".to_string(),
                },
                EIP712PropertyType {
                    name: "metadata".to_string(),
                    kind: "string".to_string(),
                },
            ]);

            // Set the types in the contract's storage
            self.proof_of_authority_types.eip712_domain = domain_types.clone();
            self.proof_of_authority_types.signer = signer_types.clone();
            self.proof_of_authority_types.proof_of_authority = proof_of_authority_types.clone();

            self.proof_of_signature_types.eip712_domain = domain_types.clone();
            self.proof_of_signature_types.proof_of_signature = proof_of_signature_types.clone();

            self.proof_of_agreement_types.eip712_domain = domain_types;
            self.proof_of_agreement_types.proof_of_agreement = proof_of_agreement_types;
        }

        /// # Helper function to get Keccak-256 hash of any given string.
        ///
        /// This function takes a string input and calculates its Keccak-256 hash.
        ///
        /// # Arguments
        ///
        /// * `input` - String to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the Keccak-256 hash of the input string.
        fn keccak_hash(input: &str) -> [u8; 32] {
            let mut keccak = Keccak::v256();
            let mut output = [0u8; 32];
            keccak.update(input.as_bytes());
            keccak.finalize(&mut output);
            output
        }

        /// # Helper function to get Keccak-256 hash of any given array of bytes.
        ///
        /// This function takes an array of bytes as input and calculates its Keccak-256 hash.
        ///
        /// # Arguments
        ///
        /// * `input` - Array of bytes to be hashed.
        ///
        /// # Returns
        ///
        /// A 32-byte array representing the Keccak-256 hash of the input array of bytes.
        fn keccak_hash_bytes(input: &[u8]) -> [u8; 32] {
            let mut keccak = Keccak::v256();
            let mut output = [0u8; 32];
            keccak.update(input);
            keccak.finalize(&mut output);
            output
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hex::FromHex;

        #[ink::test]
        fn constructor() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            // Test domain hash
            assert_eq!(
                instance.domain_hash,
                <[u8; 32]>::from_hex(
                    "539b8d1a49d3e1df5cd1ec2de6d228ec3761b476af73124fc376d18b195b1f27",
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
                    "9df0ee64347e4578b3e7590181636eead390a59d23b34a6feb90a6b4af18f47c",
                )
                .unwrap()
            );
            assert_eq!(
                instance.proof_of_signature_typehash,
                <[u8; 32]>::from_hex(
                    "791bd946d94dde6a664503c9063241c8c0cb714fc7e1c5728d17a9f6b5a6a326",
                )
                .unwrap()
            );
            assert_eq!(
                instance.proof_of_agreement_typehash,
                <[u8; 32]>::from_hex(
                    "b91b0c334bd6cfb546713bbeb8e9f8771c40e1186e761f37fd348ebfc6412a96",
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
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            //
            // Fisrt Proof-of-Authority
            //

            // prepare timestamp
            let timestamp1: u64 = 1709208045;
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
                agreement_cid: String::from("agreementCID"),
                signers: Vec::from([Signer {
                    addr: signer1_arr,
                    metadata: String::from("metadata"),
                }]),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
            };

            let expected_hash1 = <[u8; 32]>::from_hex(
                "eb5cbe215215ca8fea249f7663f5e26eef7420e100d1e0ac89230135d15f2ab9",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_authority(data1), expected_hash1);
        }

        #[ink::test]
        fn hash_proof_of_signature() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1709208045;
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
                authority_cid: String::from("authorityCID"),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
            };

            let expected_hash1 = <[u8; 32]>::from_hex(
                "58431423bc79767532b5b518c61709bf3e1cf7d1b1afd0a647b9974762ce8ae2",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_signature(data1), expected_hash1);
        }

        #[ink::test]
        fn hash_proof_of_agreement() {
            let instance = DAOsignEIP712::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            //
            // Simple Proof-of-Agreement
            //

            // prepare timestamp
            let timestamp1: u64 = 1709208861;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            let data1 = ProofOfAgreement {
                authority_cid: String::from("authorityCID"),
                signature_cids: Vec::from([
                    String::from("signatureCID0"),
                    String::from("signatureCID1"),
                ]),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
            };

            let expected_hash1: [u8; 32] = <[u8; 32]>::from_hex(
                "5d367478f814ca2cc0f4ceb8436e589920e26a686d39b11bddbe1d394129242f",
            )
            .unwrap();
            assert_eq!(instance.hash_proof_of_agreement(data1), expected_hash1);
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
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1709209688;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signer & signature
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let signature1 = <[u8; 65]>::from_hex("fdf143b80877f368ad603c12dab88180073f9280402e4039b25f8e54b59ad155745551ada4608a459a314222429baa38b6e2256ea349b9fe24e4e4e231bcc2b81c").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let message1 = ProofOfAuthority {
                name: String::from("Proof-of-Authority"),
                from: signer1_arr,
                agreement_cid: String::from("agreementCID"),
                signers: Vec::from([Signer {
                    addr: signer1_arr,
                    metadata: String::from("metadata"),
                }]),
                timestamp: timestamp1_arr,
                metadata: String::from("metadata"),
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
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1709209688;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signer & signature
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let signature1 = <[u8; 65]>::from_hex("5aed194680800d8021580d421c94c6656cd5638aee676ea2809e96298a9ff57748741083cb45da3fe45357634a3f1ad1102d4496c3c90ba82d46d462a49595b11b").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let message1 = ProofOfSignature {
                name: String::from("Proof-of-Signature"),
                signer: signer1_arr,
                authority_cid: String::from("authorityCID"),
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
                chain_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                verifying_contract: [0; 32].into(),
            });

            // prepare timestamp
            let timestamp1: u64 = 1709209688;
            let timestamp1_bytes = timestamp1.to_be_bytes();
            let mut timestamp1_arr: [u8; 32] = [0; 32];
            timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

            // prepare signer & signature
            let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
            let signature1 = <[u8; 65]>::from_hex("9efc900ff62d72005edf05d1c7aace1db71e0667f5c6a7198b644d0d99a693250456d7f9b98714ec873e63f7ca47abe3c30a1f1d5ed3c0a9642a5c07d15fa8a41b").unwrap();
            let mut signer1_arr: [u8; 32] = [0; 32];
            signer1_arr[12..].copy_from_slice(&signer1);

            let message1 = ProofOfAgreement {
                authority_cid: String::from("authorityCID"),
                signature_cids: Vec::from([
                    String::from("signatureCID0"),
                    String::from("signatureCID1"),
                ]),
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
