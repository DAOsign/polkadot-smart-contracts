#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::env;
use ink::env::hash;
use ink::env::hash_bytes;
use ink::prelude::collections::HashMap;
use ink::prelude::string::String;
use ink::prelude::vec;
use ink::prelude::vec::Vec;

pub struct EIP712PropertyType {
    pub name: String,
    pub r#type: String,
}

static EIP712DOMAIN_TYPEHASH: [u8; 32] = [
    139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159, 123, 23,
    155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15,
];

fn eip712_domain_type() -> Vec<EIP712PropertyType> {
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

pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

static SIGNER_TYPEHASH: [u8; 32] = [
    103, 170, 64, 210, 111, 136, 159, 68, 236, 95, 236, 210, 27, 129, 43, 67, 175, 9, 116, 187,
    197, 231, 66, 131, 176, 30, 54, 206, 178, 114, 150, 111,
];

fn signer_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("addr"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("string"),
        },
    ]
}

pub struct Signer {
    pub addr: [u8; 20],
    pub metadata: String,
}

static PROOF_OF_AUTHORITY_TYPEHASH: [u8; 32] = [
    157, 240, 238, 100, 52, 126, 69, 120, 179, 231, 89, 1, 129, 99, 110, 234, 211, 144, 165, 157,
    35, 179, 74, 111, 235, 144, 166, 180, 175, 24, 244, 124,
];

fn proof_of_authority_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("from"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("agreementCID"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("signers"),
            r#type: String::from("Signer[]"),
        },
        EIP712PropertyType {
            name: String::from("timestamp"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("string"),
        },
    ]
}

pub struct ProofOfAuthority {
    name: String,
    from: [u8; 20],
    agreement_cid: String,
    signers: Vec<Signer>,
    timestamp: u64,
    metadata: String,
}

static PROOF_OF_SIGNATURE_TYPEHASH: [u8; 32] = [
    121, 27, 217, 70, 217, 77, 222, 106, 102, 69, 3, 201, 6, 50, 65, 200, 192, 203, 113, 79, 199,
    225, 197, 114, 141, 23, 169, 246, 181, 166, 163, 38,
];

fn proof_of_signature_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("signer"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("authorityCID"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("timestamp"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("string"),
        },
    ]
}

pub struct ProofOfSignature {
    name: String,
    signer: [u8; 20],
    authority_cid: String,
    timestamp: u64,
    metadata: String,
}

static PROOF_OF_AGREEMENT_TYPEHASH: [u8; 32] = [
    185, 27, 12, 51, 75, 214, 207, 181, 70, 113, 59, 190, 184, 233, 248, 119, 28, 64, 225, 24, 110,
    118, 31, 55, 253, 52, 142, 191, 198, 65, 42, 150,
];

fn proof_of_agreement_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("authorityCID"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("signatureCIDs"),
            r#type: String::from("string[]"),
        },
        EIP712PropertyType {
            name: String::from("timestamp"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("string"),
        },
    ]
}

pub struct ProofOfAgreement {
    authority_cid: String,
    signature_cids: Vec<String>,
    timestamp: u64,
    metadata: String,
}

fn sha3(input: &[u8]) -> [u8; 32] {
    let mut output = <hash::Keccak256 as hash::HashOutput>::Type::default();
    hash_bytes::<hash::Keccak256>(input, &mut output);
    output
}

enum Packable<'a> {
    U64(&'a u64),
    B20(&'a [u8; 20]),
    String(&'a String),
    Strings(&'a Vec<String>),
    EIP712Domain(&'a EIP712Domain),
    Signers(&'a Vec<Signer>),
    ProofOfAuthority(&'a ProofOfAuthority),
    ProofOfSignature(&'a ProofOfSignature),
    ProofOfAgreement(&'a ProofOfAgreement),
}

fn pack(data: Packable) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    match data {
        Packable::U64(v) => {
            encoded.extend_from_slice(<[u8; 24]>::default().as_slice());
            encoded.extend_from_slice(&v.to_be_bytes());
        }
        Packable::B20(v) => {
            encoded.extend_from_slice(<[u8; 12]>::default().as_slice());
            encoded.extend_from_slice(&v.clone());
        }
        Packable::String(v) => {
            encoded.extend_from_slice(&sha3(v.as_bytes()));
        }
        Packable::Strings(v) => {
            let mut all = Vec::new();
            for string in v.iter() {
                all.extend(pack(Packable::String(&string.clone())))
            }
            encoded.extend_from_slice(&sha3(all.as_slice()))
        }
        Packable::EIP712Domain(v) => {
            encoded.extend_from_slice(&EIP712DOMAIN_TYPEHASH.clone());
            encoded.extend_from_slice(&pack(Packable::String(&v.name)));
            encoded.extend_from_slice(&pack(Packable::String(&v.version)));
            encoded.extend_from_slice(&pack(Packable::U64(&v.chain_id)));
            encoded.extend_from_slice(&pack(Packable::B20(&v.verifying_contract)));
        }
        Packable::Signers(v) => {
            let mut all = Vec::new();
            for signer in v.iter() {
                let mut obj = Vec::new();
                obj.extend_from_slice(&SIGNER_TYPEHASH.clone());
                obj.extend_from_slice(&pack(Packable::B20(&signer.addr)));
                obj.extend_from_slice(&pack(Packable::String(&signer.metadata.clone())));
                all.extend_from_slice(&sha3(obj.as_slice()));
            }
            encoded.extend_from_slice(&sha3(all.as_slice()))
        }
        Packable::ProofOfAuthority(v) => {
            encoded.extend_from_slice(&PROOF_OF_AUTHORITY_TYPEHASH.clone());
            encoded.extend_from_slice(&pack(Packable::String(&v.name)));
            encoded.extend_from_slice(&pack(Packable::B20(&v.from)));
            encoded.extend_from_slice(&pack(Packable::String(&v.agreement_cid)));
            encoded.extend_from_slice(&pack(Packable::Signers(&v.signers)));
            encoded.extend_from_slice(&pack(Packable::U64(&v.timestamp)));
            encoded.extend_from_slice(&pack(Packable::String(&v.metadata)));
        }
        Packable::ProofOfSignature(v) => {
            encoded.extend_from_slice(&PROOF_OF_SIGNATURE_TYPEHASH.clone());
            encoded.extend_from_slice(&pack(Packable::String(&v.name)));
            encoded.extend_from_slice(&pack(Packable::B20(&v.signer)));
            encoded.extend_from_slice(&pack(Packable::String(&v.authority_cid)));
            encoded.extend_from_slice(&pack(Packable::U64(&v.timestamp)));
            encoded.extend_from_slice(&pack(Packable::String(&v.metadata)));
        }
        Packable::ProofOfAgreement(v) => {
            encoded.extend_from_slice(&PROOF_OF_AGREEMENT_TYPEHASH.clone());
            encoded.extend_from_slice(&pack(Packable::String(&v.authority_cid)));
            encoded.extend_from_slice(&pack(Packable::Strings(&v.signature_cids)));
            encoded.extend_from_slice(&pack(Packable::U64(&v.timestamp)));
            encoded.extend_from_slice(&pack(Packable::String(&v.metadata)));
        }
    }
    encoded
}

pub enum Hashable<'a> {
    EIP712Domain(&'a EIP712Domain),
    ProofOfAuthority(&'a ProofOfAuthority),
    ProofOfSignature(&'a ProofOfSignature),
    ProofOfAgreement(&'a ProofOfAgreement),
}

pub fn hash(message: Hashable) -> [u8; 32] {
    match message {
        Hashable::EIP712Domain(v) => sha3(&pack(Packable::EIP712Domain(v))),
        Hashable::ProofOfAuthority(v) => sha3(&pack(Packable::ProofOfAuthority(v))),
        Hashable::ProofOfSignature(v) => sha3(&pack(Packable::ProofOfSignature(v))),
        Hashable::ProofOfAgreement(v) => sha3(&pack(Packable::ProofOfAgreement(v))),
    }
}

pub enum Recoverable<'a> {
    Hash([u8; 32]),
    ProofOfAuthority(&'a ProofOfAuthority),
    ProofOfSignature(&'a ProofOfSignature),
    ProofOfAgreement(&'a ProofOfAgreement),
}

pub fn recover(
    message: Recoverable,
    signature: &[u8; 65],
    domain_hash: &[u8; 32],
) -> Result<[u8; 20], env::Error> {
    match message {
        Recoverable::Hash(hash) => {
            let mut public_key = [0; 33];
            let mut msg = Vec::new();
            msg.extend_from_slice(b"\x19\x01");
            msg.extend_from_slice(domain_hash);
            msg.extend_from_slice(&hash);
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
        Recoverable::ProofOfAuthority(msg) => recover(
            Recoverable::Hash(hash(Hashable::ProofOfAuthority(msg))),
            signature,
            domain_hash,
        ),
        Recoverable::ProofOfSignature(msg) => recover(
            Recoverable::Hash(hash(Hashable::ProofOfSignature(msg))),
            signature,
            domain_hash,
        ),
        Recoverable::ProofOfAgreement(msg) => recover(
            Recoverable::Hash(hash(Hashable::ProofOfAgreement(msg))),
            signature,
            domain_hash,
        ),
    }
}

pub enum EIP712MessageData {
    ProofOfAuthority(ProofOfAuthority),
    ProofOfSignature(ProofOfSignature),
    ProofOfAgreement(ProofOfAgreement),
}

pub struct EIP712Message {
    pub types: HashMap<String, Vec<EIP712PropertyType>>,
    pub domain: EIP712Domain,
    pub primary_type: String,
    pub message: EIP712MessageData,
}

pub fn to_eip712_message(domain: EIP712Domain, data: EIP712MessageData) -> EIP712Message {
    let (types, primary_type) = match data {
        EIP712MessageData::ProofOfAuthority(_) => (
            HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("Signer"), signer_type()),
                (String::from("ProofOfAuthority"), proof_of_authority_type()),
            ]),
            String::from("ProofOfAuthority"),
        ),
        EIP712MessageData::ProofOfSignature(_) => (
            HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("ProofOfSignature"), proof_of_signature_type()),
            ]),
            String::from("ProofOfSignature"),
        ),
        EIP712MessageData::ProofOfAgreement(_) => (
            HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("ProofOfAgreement"), proof_of_agreement_type()),
            ]),
            String::from("ProofOfAgreement"),
        ),
    };
    EIP712Message {
        types,
        domain,
        primary_type,
        message: data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    const SOME_ADDR: [u8; 20] = [
        243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185,
        34, 102,
    ];

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
    fn check_typehashes() {
        assert_eq!(EIP712DOMAIN_TYPEHASH, sha3(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
        assert_eq!(
            SIGNER_TYPEHASH,
            sha3(b"Signer(address addr,string metadata)")
        );
        assert_eq!(PROOF_OF_AUTHORITY_TYPEHASH, sha3(b"ProofOfAuthority(string name,address from,string agreementCID,Signer[] signers,uint256 timestamp,string metadata)Signer(address addr,string metadata)"));
        assert_eq!(PROOF_OF_SIGNATURE_TYPEHASH, sha3(b"ProofOfSignature(string name,address signer,string authorityCID,uint256 timestamp,string metadata)"));
        assert_eq!(PROOF_OF_AGREEMENT_TYPEHASH, sha3(b"ProofOfAgreement(string authorityCID,string[] signatureCIDs,uint256 timestamp,string metadata)"));
    }

    #[ink::test]
    fn check_eip712_domain() {
        let struct_hash = hash(Hashable::EIP712Domain(&domain()));
        let expected: [u8; 32] = <[u8; 32]>::from_hex(
            "539b8d1a49d3e1df5cd1ec2de6d228ec3761b476af73124fc376d18b195b1f27",
        )
        .expect("bad hash value");
        assert_eq!(expected, struct_hash);
    }

    #[ink::test]
    fn check_proof_of_authority() {
        let message = ProofOfAuthority {
            name: String::from("Proof-of-Authority"),
            from: SOME_ADDR.clone(),
            agreement_cid: String::from("agreementCID"),
            signers: vec![Signer {
                addr: SOME_ADDR.clone(),
                metadata: String::from("metadata"),
            }],
            timestamp: 1710330067,
            metadata: String::from("metadata"),
        };

        let expected_hash = <[u8; 32]>::from_hex(
            "63af3c65b875f09665a05dc751138b663dd63cf631a07143e19ba54ff8987358",
        )
        .unwrap();
        assert_eq!(expected_hash, hash(Hashable::ProofOfAuthority(&message)));

        let signature = <[u8; 65]>::from_hex("b2e9a6c6ab877ce682c03d584fa8cae1e88d9ab290febee705b211d5033c885b3d83bce8ab90917c540c9f5367592fbeabc8125e7a75866cab4b99e1c030a6a31b").unwrap();
        let recovered = recover(
            Recoverable::ProofOfAuthority(&message),
            &signature,
            &hash(Hashable::EIP712Domain(&domain())),
        );
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }

    #[ink::test]
    fn check_proof_of_signature() {
        let message = ProofOfSignature {
            name: String::from("Proof-of-Signature"),
            signer: SOME_ADDR.clone(),
            authority_cid: String::from("authorityCID"),
            timestamp: 1710330067,
            metadata: String::from("metadata"),
        };

        let expected_hash: [u8; 32] = <[u8; 32]>::from_hex(
            "2728e05cad9264c189d6efc92cd42288f9ac0d77454d603a24558c35c2192c62",
        )
        .unwrap();
        assert_eq!(expected_hash, hash(Hashable::ProofOfSignature(&message)));

        let signature = <[u8; 65]>::from_hex("77d2146c392a9bbc8ac4a6219f54fa09f26f717acab0334de1430aee8182692e2b546435d1b93e265516cb03375d758af9d9e262d05291e8f00fcd8e70efdc721b").unwrap();
        let recovered = recover(
            Recoverable::ProofOfSignature(&message),
            &signature,
            &hash(Hashable::EIP712Domain(&domain())),
        );
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }

    #[ink::test]
    fn check_proof_of_agreement() {
        let message = ProofOfAgreement {
            authority_cid: String::from("authorityCID"),
            signature_cids: vec![String::from("signatureCID0"), String::from("signatureCID1")],
            timestamp: 1710330067,
            metadata: String::from("metadata"),
        };

        let expected_hash: [u8; 32] = <[u8; 32]>::from_hex(
            "70b7103d5b78c366091856f2051002ec537e2e3279f9364e800322aaa231a28b",
        )
        .unwrap();
        assert_eq!(expected_hash, hash(Hashable::ProofOfAgreement(&message)));

        let signature = <[u8; 65]>::from_hex("f69f89ea63a0289b15089c94a0a1243d8e9815950770652ffc708a0d20419fed1de5406476301fda2e0f073b4a872d7dd63f7b3445f60c1cfe4f8c8c0dabb21c1c").unwrap();
        let recovered = recover(
            Recoverable::ProofOfAgreement(&message),
            &signature,
            &hash(Hashable::EIP712Domain(&domain())),
        );
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
