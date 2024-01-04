import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import DAOsignAppFactory from "../../typedContracts/daosign_app/constructors/daosign_app";
import DAOsignApp from "../../typedContracts/daosign_app/contracts/daosign_app";
import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";
import { EIP712Domain, ProofOfAuthority, SignedProofOfAuthority } from "../../typedContracts/daosign_app/types-arguments/daosign_app";

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

  it("lifecycle", async () => {
    const timestamp = 1702609459;
    const timestampArr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 123, 194, 51];
    const from = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    const fromArr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102];
    const signature = '0x130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c';
    const signatureArr = [19, 5, 97, 250, 85, 205, 167, 142, 90, 154, 192, 203, 150, 231, 100, 9, 250, 81, 18, 163, 148, 34, 96, 75, 4, 53, 128, 165, 89, 162, 163, 82, 100, 31, 113, 254, 39, 140, 116, 25, 37, 148, 194, 125, 61, 124, 91, 127, 121, 149, 230, 59, 208, 221, 201, 97, 36, 174, 133, 50, 254, 81, 217, 17, 28];

    let proofCID = "ProofOfAuthority proof cid                    ";

    let data: SignedProofOfAuthority = {
        message: {
            name: "Proof-of-Authority",
            from: fromArr,
            agreementCid: "agreement file cid                            ",
            signers: [{
                addr: fromArr,
                metadata: "some metadata",
            }],
            app: "daosign",
            timestamp: timestampArr,
            metadata: "proof metadata",
        },
        signature: signatureArr,
        proofCid: proofCID,
    };

    const { gasRequired } = await contract.withSigner(deployer).query.storeProofOfAuthority(data);

    await contract.withSigner(deployer).tx.storeProofOfAuthority(data, {
      gasLimit: gasRequired,
    });

    console.log((await contract.query.getProofOfAuthority(proofCID)).value.ok);

    // @ts-ignore
    data.signature = signature;
    // @ts-ignore
    data.message.from = '0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266';
    // @ts-ignore
    data.message.signers[0].addr = '0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266';
    // @ts-ignore
    data.message.timestamp = '0x00000000000000000000000000000000000000000000000000000000657bc233';

    expect((await contract.query.getProofOfAuthority(proofCID)).value.ok).eql(data);
  });
});
