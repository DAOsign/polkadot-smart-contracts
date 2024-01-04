import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import DAOsignAppFactory from "../../typedContracts/daosign_app/constructors/daosign_app";
import DAOsignApp from "../../typedContracts/daosign_app/contracts/daosign_app";
import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";
import { EIP712Domain, ProofOfAuthority } from "../../typedContracts/daosign_app/types-arguments/daosign_app";

use(chaiAsPromised);

// Create a new instance of contract
const wsProvider = new WsProvider("ws://127.0.0.1:9944");
// Create a keyring instance
const keyring = new Keyring({ type: "sr25519" });

describe("DAOsignApp Tests", () => {
  let appFactory: DAOsignAppFactory;
  let api: ApiPromise;
  let deployer: KeyringPair;
  let contract: DAOsignApp;

  const eip712Domain: EIP712Domain = {
      name: "daosign",
      version: "0.1.0",
      chainId: new Array(32).fill(0),
      verifyingContract: new Array(32).fill(0),
  };

  before(async function setup(): Promise<void> {
    api = await ApiPromise.create({ provider: wsProvider });
    deployer = keyring.addFromUri("//Alice");

    appFactory = new DAOsignAppFactory(api, deployer);

    contract = new DAOsignApp(
      (await appFactory.new(eip712Domain)).address,
      deployer,
      api
    );
  });

  after(async function tearDown() {
    await api.disconnect();
  });

  it.only("lifecycle", async () => {
    // expect(await contract.methods.storeProofOfAgreement())

      //
      // Fisrt Proof-of-Authority
      //

      // prepare timestamp
      // let timestamp1: u64 = 1701975136;
      // let timestamp1_bytes = timestamp1.to_be_bytes();
      // let mut timestamp1_arr: [u8; 32] = [0; 32];
      // timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

      // // prepare signers
      // let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
      // let mut signer1_arr: [u8; 32] = [0; 32];
      // signer1_arr[12..].copy_from_slice(&signer1);

      // const msg: ProofOfAuthority = {
      //   name: 'Proof-of-Authority',
      //   from: mocks.signer.address,
      //   agreementCID: paddRigthStr('agreement file cid'),
      //   signers: [{ addr: mocks.signer.address, metadata: 'some metadata' }],
      //   app: 'daosign',
      //   timestamp: Math.floor(Date.now() / 1000),
      //   metadata: 'proof metadata',
      // };
      // const sig = signMessage(mocks.privateKey, 'ProofOfAuthority', msg);
      // console.log(
      //   util.inspect(
      //     {
      //       message: msg,
      //       signature: sig,
      //       proofCID: paddRigthStr('ProofOfAuthority proof cid'),
      //     },
      //     true,
      //     null,
      //     true,
      //   ),
      // );

      const signer1 = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
      const signer1_arr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102];

      let data1: ProofOfAuthority = {
          name: "Proof-of-Authority",
          from: signer1_arr,
          agreementCid: "agreement file cid                            ",
          signers: [{
              addr: signer1_arr,
              metadata: "{}",
          }],
          app: "daosign",
          timestamp: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 114, 20, 96],
          metadata: "proof metadata",
      };
      const sig = signMessage(mocks.privateKey, 'ProofOfAuthority', msg);
      console.log(
        util.inspect(
          {
            message: msg,
            signature: sig,
            proofCID: paddRigthStr('ProofOfAuthority proof cid'),
          },
          true,
          null,
          true,
        ),
      );

      // let expected_hash1 = "982eeb361acc7f0d6402a812683b34e53f1e59f239fb32156e8b0bd2f9dfd039";
      
      // const { gasRequired } = await contract.withSigner(deployer).query.storeProofOfAuthority(data1);

      // await contract.withSigner(deployer).tx.flip({
      //   gasLimit: gasRequired,
      // });

      // expect((await contract.query.get()).value.ok).to.be.equal(!initialState);

      // //
      // // Second Proof-of-Authority
      // //
      // // prepare timestamp
      // let timestamp2: u64 = 1701975136;
      // let timestamp2_bytes = timestamp2.to_be_bytes();
      // let mut timestamp2_arr: [u8; 32] = [0; 32];
      // timestamp2_arr[24..].copy_from_slice(&timestamp2_bytes);

      // // prepare signers
      // let signer2 = <[u8; 20]>::from_hex("70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
      // let mut signer2_arr: [u8; 32] = [0; 32];
      // signer2_arr[12..].copy_from_slice(&signer2);

      // let data2 = ProofOfAuthority {
      //     name: String::from("Proof-of-Authority"),
      //     from: signer1_arr,
      //     agreement_cid: String::from("QmbuRibrtidhy9rJuFUjafKG7dDhwDEctc2oWr3NGVxKrd"),
      //     signers: Vec::from([
      //         Signer {
      //             addr: signer1_arr,
      //             metadata: String::from("custom metadata #1"),
      //         },
      //         Signer {
      //             addr: signer2_arr,
      //             metadata: String::from("metadata #2"),
      //         },
      //     ]),
      //     app: String::from("daosign"),
      //     timestamp: timestamp2_arr,
      //     metadata: String::from("proof metadata"),
      // };

      // let expected_hash2 = <[u8; 32]>::from_hex(
      //     "7764e27376e6d1a8e28583b6bda4bdabce356f493348688fe3ec5d0344700935",
      // )
      // .unwrap();
      // assert_eq!(instance.hash_proof_of_authority(data2), expected_hash2);
  })

  it("Get 5", async () => {
    expect((await contract.query.get5()).value.ok?.toString()).to.equal('5');
  });

  //   it("Sets the initial state", async () => {
//     expect((await contract.query.get()).value.ok).to.equal(initialState);
//   });

//   it("Can flip the state", async () => {
//     const { gasRequired } = await contract.withSigner(deployer).query.flip();

//     await contract.withSigner(deployer).tx.flip({
//       gasLimit: gasRequired,
//     });

//     expect((await contract.query.get()).value.ok).to.be.equal(!initialState);
//   });
});
