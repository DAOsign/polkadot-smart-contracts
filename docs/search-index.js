var searchIndex = JSON.parse('{\
"daosign_app":{"doc":"DAOsign App Contract","t":"ADDDNDNDNDDDDDDELLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL","n":["daosign_app","DAOsignApp","DAOsignAppRef","NewProofOfAgreement","NewProofOfAgreement","NewProofOfAuthority","NewProofOfAuthority","NewProofOfSignature","NewProofOfSignature","SignedProofOfAgreement","SignedProofOfAgreementMsg","SignedProofOfAuthority","SignedProofOfAuthorityMsg","SignedProofOfSignature","SignedProofOfSignatureMsg","__ink_EventBase","as_mut","as_ref","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","call","call_mut","clone","clone","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","env","env","eq","eq","eq","eq","eq","eq","eq","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from_account_id","get_proof_of_agreement","get_proof_of_agreement","get_proof_of_authority","get_proof_of_authority","get_proof_of_signature","get_proof_of_signature","hash","into","into","into","into","into","into","into","into","into","into","into","into","layout","layout","layout","layout","layout","layout","layout","layout","new","new","ok","ok","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","store_proof_of_agreement","store_proof_of_agreement","store_proof_of_authority","store_proof_of_authority","store_proof_of_signature","store_proof_of_signature","to_account_id","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","topics","topics","topics","topics","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_get_proof_of_agreement","try_get_proof_of_authority","try_get_proof_of_signature","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_store_proof_of_agreement","try_store_proof_of_authority","try_store_proof_of_signature","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","using_encoded","using_encoded","using_encoded","using_encoded","validate_signed_proof_of_agreement","validate_signed_proof_of_authority","validate_signed_proof_of_signature"],"q":["daosign_app","daosign_app::daosign_app","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"d":["","Main storage structure for DAOsignApp contract.","Main storage structure for DAOsignApp contract.","Event emitted when a new Proof-of-Agreement is added.","","Event emitted when a new Proof-of-Authority is added.","","Event emitted when a new Proof-of-Signature is added.","","Represents a signed Proof-of-Agreement with the message, …","Represents a signed Proof-of-Agreement with the EIP712 …","Represents a signed Proof-of-Authority with the message, …","Represents a signed Proof-of-Authority with the EIP712 …","Represents a signed Proof-of-Signature with the message, …","Represents a signed Proof-of-Signature with the EIP712 …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","Ink! message to retrieve a Proof of Agreement by its CID.","Ink! message to retrieve a Proof of Agreement by its CID.","Ink! message to retrieve a Proof of Authority by its CID.","Ink! message to retrieve a Proof of Authority by its CID.","Ink! message to retrieve a Proof of Signature by its CID.","Ink! message to retrieve a Proof of Signature by its CID.","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","Ink! constructor for creating a new DAOsignApp instance.","Ink! constructor for creating a new DAOsignApp instance.","","","","","","","","","","","","","","Ink! message to store a Proof of Agreement.","Ink! message to store a Proof of Agreement.","Ink! message to store a Proof of Authority.","Ink! message to store a Proof of Authority.","Ink! message to store a Proof of Signature.","Ink! message to store a Proof of Signature.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Ink! message to retrieve a Proof of Agreement by its CID.","Ink! message to retrieve a Proof of Authority by its CID.","Ink! message to retrieve a Proof of Signature by its CID.","","","","","","","","","","","","","Ink! message to store a Proof of Agreement.","Ink! message to store a Proof of Authority.","Ink! message to store a Proof of Signature.","","","","","","","","","","","","","","","","","","","","","","","","","Validates a signed Proof-of-Agreement message.","Validates a signed Proof-of-Authority message.","Validates a signed Proof-of-Signature message."],"i":[0,0,0,0,11,0,11,0,11,0,0,0,0,0,0,0,1,1,8,11,12,13,14,1,2,3,4,5,6,7,8,11,12,13,14,1,2,3,4,5,6,7,1,1,1,2,3,4,5,6,7,1,2,3,4,5,6,7,8,11,11,12,12,13,13,14,14,1,1,2,2,3,3,4,4,5,5,6,6,7,7,11,12,13,14,1,2,3,4,5,6,7,11,12,13,14,1,2,3,4,5,6,7,11,12,13,14,1,2,3,4,5,6,7,8,11,12,12,13,13,14,14,1,1,2,3,4,5,6,7,11,12,13,14,1,2,3,4,5,6,7,8,8,1,2,3,4,5,6,7,1,2,3,4,5,6,7,8,11,11,11,11,12,13,14,1,2,3,4,5,6,7,1,8,1,8,1,8,1,1,8,11,12,13,14,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,8,1,11,12,13,14,1,2,3,4,5,6,7,8,1,8,1,8,1,1,11,12,13,14,1,2,3,4,5,6,7,1,2,3,4,5,6,7,11,12,13,14,8,11,12,13,14,1,2,3,4,5,6,7,1,1,1,8,11,12,13,14,1,2,3,4,5,6,7,1,1,1,8,11,12,13,14,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,12,13,14,1,8,8,8],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[1],[1],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[1],[1],[1,1],[2,2],[3,3],[4,4],[5,5],[6,6],[7,7],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],[[10,[8,9]]]],[[],[[10,[11,9]]]],[[],[[10,[9]]]],[[],[[10,[12,9]]]],[[],[[10,[9]]]],[[],[[10,[13,9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[14,9]]]],[[],[[10,[1,9]]]],[[],[[10,[9]]]],[[],[[10,[2,9]]]],[[],[[10,[9]]]],[[],[[10,[3,9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[4,9]]]],[[],[[10,[5,9]]]],[[],[[10,[9]]]],[[],[[10,[6,9]]]],[[],[[10,[9]]]],[[],[[10,[7,9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[[],[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[15,[[10,[9]]]],[8],[[]],[12,[[17,[16]]]],[[]],[13,[[17,[16]]]],[[]],[14,[[17,[16]]]],[[]],[[]],[1,[[17,[16]]]],[[]],[[]],[[]],[[]],[[]],[[]],[11],[12],[13],[14],[1],[2],[3],[4],[5],[6],[7],[8],[[]],[[1,1],18],[[2,2],18],[[3,3],18],[[4,4],18],[[5,5],18],[[6,6],18],[[7,7],18],[[1,19],20],[[2,19],20],[[3,19],20],[[4,19],20],[[5,19],20],[[6,19],20],[[7,19],20],[[]],[13,11],[12,11],[14,11],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],1],[[8,21],5],[[1,21],5],[[8,21],7],[[1,21],7],[[8,21],6],[[1,21],6],[1],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[22,23],[22,23],[22,23],[22,23],[22,23],[22,23],[22,23],[22,23],[24,8],[24,[[34,[1,25,[25,[26]],25,[31,[[30,[[29,[[27,[24]],28]]]]]],[25,[32]],[31,[[33,[1]]]]]]]],[1],[[]],[11,35],[12,35],[13,35],[14,35],[1,35],[2,35],[3,35],[4,35],[5,35],[6,35],[7,35],[[8,5]],[[1,5]],[[8,7]],[[1,7]],[[8,6]],[[1,6]],[1],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[],[[17,[16,36]]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[11,[38,[37]]]],[[12,[38,[37]]]],[[13,[38,[37]]]],[[14,[38,[37]]]],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[1,21],[[39,[5]]]],[[1,21],[[39,[7]]]],[[1,21],[[39,[6]]]],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[],10],[[1,5],39],[[1,7],39],[[1,6],39],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],41],[[],41],[[],41],[[],41],[[],41],[[],41],[[],41],[[],41],[[12,42]],[[13,42]],[[14,42]],[[1,42]],[[8,5],18],[[8,7],18],[[8,6],18]],"p":[[3,"DAOsignAppRef"],[3,"SignedProofOfAgreementMsg"],[3,"SignedProofOfSignatureMsg"],[3,"SignedProofOfAuthorityMsg"],[3,"SignedProofOfAgreement"],[3,"SignedProofOfSignature"],[3,"SignedProofOfAuthority"],[3,"DAOsignApp"],[3,"Error"],[4,"Result"],[4,"__ink_EventBase"],[3,"NewProofOfAuthority"],[3,"NewProofOfSignature"],[3,"NewProofOfAgreement"],[15,"u32"],[15,"u8"],[3,"Vec"],[15,"bool"],[3,"Formatter"],[6,"Result"],[3,"String"],[6,"Key"],[4,"Layout"],[3,"EIP712Domain"],[3,"Unset"],[15,"u64"],[3,"Argument"],[6,"EmptyArgumentList"],[3,"ArgumentList"],[3,"ExecutionInput"],[3,"Set"],[4,"Salt"],[3,"ReturnType"],[3,"CreateBuilder"],[15,"usize"],[3,"Global"],[4,"Uninit"],[3,"TopicsBuilder"],[6,"MessageResult"],[3,"TypeId"],[3,"Type"],[8,"FnOnce"]]},\
"daosign_eip712":{"doc":"DAOsign EIP-712 Contract","t":"ADDDDDDDDDDDDDDMMLLMMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMMMMMMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMMMMMMMLLLLMMMMMMMMMLLLLLLLLMMMMMLLLLLLLLLLLLLMMMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMM","n":["daosign_eip712","DAOsignEIP712","DAOsignEIP712Ref","EIP712Domain","EIP712ProofOfAgreement","EIP712ProofOfAgreementTypes","EIP712ProofOfAuthority","EIP712ProofOfAuthorityTypes","EIP712ProofOfSignature","EIP712ProofOfSignatureTypes","EIP712PropertyType","ProofOfAgreement","ProofOfAuthority","ProofOfSignature","Signer","addr","agreement_cid","as_mut","as_ref","authority_cid","authority_cid","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","call","call_mut","chain_id","clone","clone","clone","clone","clone","clone","clone","clone","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_all_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","decode_with_depth_limit","default","default","default","domain","domain_hash","eip712_domain","eip712_domain","eip712_domain","eip712domain_typehash","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","encode_to","env","env","eq","eq","eq","eq","eq","eq","eq","eq","eq","eq","eq","eq","eq","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from_account_id","hash","hash_domain","hash_domain","hash_proof_of_agreement","hash_proof_of_agreement","hash_proof_of_authority","hash_proof_of_authority","hash_proof_of_signature","hash_proof_of_signature","hash_signer","hash_signer","hash_signers","hash_signers","hash_strings","hash_strings","into","into","into","into","into","into","into","into","into","into","into","into","into","into","layout","layout","layout","layout","layout","layout","layout","layout","layout","layout","layout","layout","layout","layout","metadata","metadata","metadata","metadata","name","name","name","new","new","ok","ok","proof_of_agreement","proof_of_agreement_typehash","proof_of_agreement_types","proof_of_authority","proof_of_authority_typehash","proof_of_authority_types","proof_of_signature","proof_of_signature_typehash","proof_of_signature_types","recover","recover","recover_proof_of_agreement","recover_proof_of_agreement","recover_proof_of_authority","recover_proof_of_authority","recover_proof_of_signature","recover_proof_of_signature","signature_cids","signer","signer","signer_typehash","signers","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","size_hint","timestamp","timestamp","timestamp","to_account_id","to_eip712_message_proof_of_agreement","to_eip712_message_proof_of_agreement","to_eip712_message_proof_of_authority","to_eip712_message_proof_of_authority","to_eip712_message_proof_of_signature","to_eip712_message_proof_of_signature","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_keyed_vec","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_hash_domain","try_hash_proof_of_agreement","try_hash_proof_of_authority","try_hash_proof_of_signature","try_hash_signer","try_hash_signers","try_hash_strings","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_recover","try_recover_proof_of_agreement","try_recover_proof_of_authority","try_recover_proof_of_signature","try_to_eip712_message_proof_of_agreement","try_to_eip712_message_proof_of_authority","try_to_eip712_message_proof_of_signature","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","type_info","using_encoded","verifying_contract","version"],"q":["daosign_eip712","daosign_eip712::daosign_eip712","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"d":["","Contract Storage struct","Contract Storage struct","EIP-712 Domain struct representing the domain-specific …","EIP712ProofOfAgreement struct representing the EIP-712 …","EIP712ProofOfAgreementTypes struct representing the types …","EIP712ProofOfAuthority struct representing the EIP-712 …","EIP712ProofOfAuthorityTypes struct representing the types …","EIP712ProofOfSignature struct representing the EIP-712 …","EIP712ProofOfSignatureTypes struct representing the types …","EIP712PropertyType struct representing the structure of …","ProofOfAgreement struct representing the …","ProofOfAuthority struct representing the …","ProofOfSignature struct representing the …","Signer struct representing an address and associated …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","","Ink! function to get the hash of an EIP712Domain struct.","Ink! function to get the hash of an EIP712Domain struct.","Ink! function to get the hash of a ProofOfAgreement struct.","Ink! function to get the hash of a ProofOfAgreement struct.","Ink! function to get the hash of a ProofOfAuthority struct.","Ink! function to get the hash of a ProofOfAuthority struct.","Ink! function to get the hash of a ProofOfSignature struct.","Ink! function to get the hash of a ProofOfSignature struct.","Ink! function to get the hash of a Signer struct.","Ink! function to get the hash of a Signer struct.","Ink! function to get the hash of an array of Signer …","Ink! function to get the hash of an array of Signer …","Ink! function to get the hash of an array of strings.","Ink! function to get the hash of an array of strings.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","","","","","","Ink! constructor for creating a new DAOsignEIP712 instance.","Ink! constructor for creating a new DAOsignEIP712 instance.","","","","","","","","","","","","Recover function for retrieving the Ethereum address from …","Recover function for retrieving the Ethereum address from …","Recover function for Proof of Agreement, retrieving the …","Recover function for Proof of Agreement, retrieving the …","Recover function for Proof of Authority, retrieving the …","Recover function for Proof of Authority, retrieving the …","Recover function for Proof of Signature, retrieving the …","Recover function for Proof of Signature, retrieving the …","","","","","","","","","","","","","","","","","","","","","","","Convert ProofOfAgreement struct to EIP-712 formatted …","Convert ProofOfAgreement struct to EIP-712 formatted …","Convert ProofOfAuthority struct to EIP-712 formatted …","Convert ProofOfAuthority struct to EIP-712 formatted …","Convert ProofOfSignature struct to EIP-712 formatted …","Convert ProofOfSignature struct to EIP-712 formatted …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Ink! function to get the hash of an EIP712Domain struct.","Ink! function to get the hash of a ProofOfAgreement struct.","Ink! function to get the hash of a ProofOfAuthority struct.","Ink! function to get the hash of a ProofOfSignature struct.","Ink! function to get the hash of a Signer struct.","Ink! function to get the hash of an array of Signer …","Ink! function to get the hash of an array of strings.","","","","","","","","","","","","","","","Recover function for retrieving the Ethereum address from …","Recover function for Proof of Agreement, retrieving the …","Recover function for Proof of Authority, retrieving the …","Recover function for Proof of Signature, retrieving the …","Convert ProofOfAgreement struct to EIP-712 formatted …","Convert ProofOfAuthority struct to EIP-712 formatted …","Convert ProofOfSignature struct to EIP-712 formatted …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,11,1,1,9,10,14,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,2,3,4,5,6,7,8,9,10,11,12,13,1,1,13,1,2,3,4,5,6,7,8,9,10,11,12,13,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,1,2,3,4,5,6,7,8,9,10,11,12,13,1,2,3,4,5,6,7,8,9,10,11,12,13,1,2,3,4,5,6,7,8,9,10,11,12,13,5,6,7,14,14,5,6,7,14,14,1,1,2,3,4,5,6,7,8,9,10,11,12,13,1,2,3,4,5,6,7,8,9,10,11,12,13,14,14,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,2,3,4,5,6,7,8,9,10,11,12,13,11,1,1,14,1,14,1,14,1,14,1,14,1,14,1,14,1,14,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,2,3,4,5,6,7,8,9,10,11,12,13,9,10,11,12,10,11,13,14,1,14,1,5,14,14,7,14,14,6,14,14,14,1,14,1,14,1,14,1,9,7,10,14,11,1,2,3,4,5,6,7,8,9,10,11,12,13,9,10,11,1,14,1,14,1,14,1,1,2,3,4,5,6,7,8,9,10,11,12,13,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,2,3,4,5,6,7,8,9,10,11,12,13,1,1,1,1,1,1,1,14,1,2,3,4,5,6,7,8,9,10,11,12,13,1,1,1,1,1,1,1,14,1,2,3,4,5,6,7,8,9,10,11,12,13,14,1,2,3,4,5,6,7,8,9,10,11,12,13,1,13,13],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[1],[1],0,0,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[1],[1],0,[1,1],[2,2],[3,3],[4,4],[5,5],[6,6],[7,7],[8,8],[9,9],[10,10],[11,11],[12,12],[13,13],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],[[16,[14,15]]]],[[],[[16,[15]]]],[[],[[16,[1,15]]]],[[],[[16,[2,15]]]],[[],[[16,[15]]]],[[],[[16,[3,15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[4,15]]]],[[],[[16,[5,15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[6,15]]]],[[],[[16,[7,15]]]],[[],[[16,[15]]]],[[],[[16,[8,15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[9,15]]]],[[],[[16,[15]]]],[[],[[16,[10,15]]]],[[],[[16,[15]]]],[[],[[16,[11,15]]]],[[],[[16,[12,15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[13,15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[[],[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[17,[[16,[15]]]],[[],5],[[],6],[[],7],0,0,0,0,0,0,[14],[1,[[19,[18]]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[1],[2],[3],[4],[5],[6],[7],[8],[9],[10],[11],[12],[13],[14],[[]],[[1,1],20],[[2,2],20],[[3,3],20],[[4,4],20],[[5,5],20],[[6,6],20],[[7,7],20],[[8,8],20],[[9,9],20],[[10,10],20],[[11,11],20],[[12,12],20],[[13,13],20],[[14,21],22],[[1,21],22],[[2,21],22],[[3,21],22],[[4,21],22],[[5,21],22],[[6,21],22],[[7,21],22],[[8,21],22],[[9,21],22],[[10,21],22],[[11,21],22],[[12,21],22],[[13,21],22],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],0,[[],1],[1],[[14,13]],[[1,13]],[[14,9]],[[1,9]],[[14,11]],[[1,11]],[[14,10]],[[1,10]],[[14,12]],[[1,12]],[[14,[19,[12]]]],[[1,[19,[12]]]],[[14,[19,[23]]]],[[1,[19,[23]]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],[24,25],0,0,0,0,0,0,0,[13,14],[13,[[35,[1,26,[26,[27]],26,[32,[[31,[[30,[[28,[13]],29]]]]]],[26,[33]],[32,[[34,[1]]]]]]]],[1],[[]],0,0,0,0,0,0,0,0,0,[14],[1],[[14,9]],[[1,9]],[[14,11]],[[1,11]],[[14,10]],[[1,10]],0,0,0,0,0,[1,36],[2,36],[3,36],[4,36],[5,36],[6,36],[7,36],[8,36],[9,36],[10,36],[11,36],[12,36],[13,36],0,0,0,[1],[[14,9],2],[[1,9],2],[[14,11],4],[[1,11],4],[[14,10],3],[[1,10],3],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[],[[19,[18,37]]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[1,13],38],[[1,9],38],[[1,11],38],[[1,10],38],[[1,12],38],[[1,[19,[12]]],38],[[1,[19,[23]]],38],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[[],16],[1,38],[[1,9],38],[[1,11],38],[[1,10],38],[[1,9],[[38,[2]]]],[[1,11],[[38,[4]]]],[[1,10],[[38,[3]]]],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],39],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[],40],[[1,41]],0,0],"p":[[3,"DAOsignEIP712Ref"],[3,"EIP712ProofOfAgreement"],[3,"EIP712ProofOfSignature"],[3,"EIP712ProofOfAuthority"],[3,"EIP712ProofOfAgreementTypes"],[3,"EIP712ProofOfSignatureTypes"],[3,"EIP712ProofOfAuthorityTypes"],[3,"EIP712PropertyType"],[3,"ProofOfAgreement"],[3,"ProofOfSignature"],[3,"ProofOfAuthority"],[3,"Signer"],[3,"EIP712Domain"],[3,"DAOsignEIP712"],[3,"Error"],[4,"Result"],[15,"u32"],[15,"u8"],[3,"Vec"],[15,"bool"],[3,"Formatter"],[6,"Result"],[3,"String"],[6,"Key"],[4,"Layout"],[3,"Unset"],[15,"u64"],[3,"Argument"],[6,"EmptyArgumentList"],[3,"ArgumentList"],[3,"ExecutionInput"],[3,"Set"],[4,"Salt"],[3,"ReturnType"],[3,"CreateBuilder"],[15,"usize"],[3,"Global"],[6,"MessageResult"],[3,"TypeId"],[3,"Type"],[8,"FnOnce"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
