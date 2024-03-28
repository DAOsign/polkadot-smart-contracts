#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::env;
use ink::env::hash;
use ink::env::hash_bytes;
use ink::prelude::collections::hash_map::HashMap;
use ink::prelude::vec::Vec;

static EIP712DOMAIN_TYPEHASH: [u8; 32] = [
    139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159, 123, 23,
    155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15,
];

pub trait Packable {
    fn pack(&self) -> Vec<u8>;
}

/// EIP712PropertyType struct representing the structure of EIP-712 properties.
#[derive(Debug, Clone, PartialEq, Eq)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
pub struct EIP712PropertyType {
    pub name: String,
    pub r#type: String,
}

/// EIP-712 Domain struct representing the domain-specific parameters for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(
    feature = "std",
    derive(ink::storage::traits::StorageLayout)
)]
pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

impl Packable for EIP712Domain {
    fn pack(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&EIP712DOMAIN_TYPEHASH.clone());
        encoded.extend_from_slice(&sha3(self.name.as_bytes()));
        encoded.extend_from_slice(&sha3(self.version.as_bytes()));
        encoded.extend_from_slice(<[u8; 24]>::default().as_slice());
        encoded.extend_from_slice(&self.chain_id.to_be_bytes());
        encoded.extend_from_slice(<[u8; 12]>::default().as_slice());
        encoded.extend_from_slice(&self.verifying_contract.clone());
        encoded
    }
}

pub fn sha3(input: &[u8]) -> [u8; 32] {
    let mut output = <hash::Keccak256 as hash::HashOutput>::Type::default();
    hash_bytes::<hash::Keccak256>(input, &mut output);
    output
}

pub fn hash(message: &dyn Packable) -> [u8; 32] {
    sha3(&message.pack())
}

pub fn recover(
    domain: &EIP712Domain,
    message: &dyn Packable,
    signature: &[u8; 65],
) -> Result<[u8; 20], env::Error> {
    let mut public_key = [0; 33];
    let mut msg = Vec::new();
    msg.extend_from_slice(b"\x19\x01");
    msg.extend_from_slice(&hash(domain));
    msg.extend_from_slice(&hash(message));
    match env::ecdsa_recover(signature, &sha3(&msg), &mut public_key) {
        Ok(_) => {
            let mut address = [0; 20];
            match env::ecdsa_to_eth_address(&public_key, &mut address) {
                Ok(_) => Ok(address),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EIP712Message<T: Packable> {
    pub types: HashMap<String, Vec<EIP712PropertyType>>,
    pub domain: EIP712Domain,
    pub primary_type: String,
    pub message: T,
}

pub fn eip712_domain_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("version"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("chainId"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("verifyingContract"),
            r#type: String::from("address"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    fn domain() -> EIP712Domain {
        EIP712Domain {
            name: String::from("daosign"),
            version: String::from("0.1.0"),
            chain_id: 1,
            verifying_contract: <[u8; 20]>::from_hex("0000000000000000000000000000000000000000")
                .expect("bad address"),
        }
    }

    #[ink::test]
    fn check_typehash() {
        assert_eq!(EIP712DOMAIN_TYPEHASH, sha3(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
    }

    #[ink::test]
    fn check_hash() {
        let struct_hash = hash(&domain());
        let expected: [u8; 32] = <[u8; 32]>::from_hex(
            "539b8d1a49d3e1df5cd1ec2de6d228ec3761b476af73124fc376d18b195b1f27",
        )
        .expect("bad hash value");
        assert_eq!(expected, struct_hash);
    }
}
