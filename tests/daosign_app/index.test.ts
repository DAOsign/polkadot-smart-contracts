import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import DAOsignAppFactory from "../../typedContracts/daosign_app/constructors/daosign_app";
import DAOsignApp from "../../typedContracts/daosign_app/contracts/daosign_app";
import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";
import { EIP712Domain } from "../../typedContracts/daosign_app/types-arguments/daosign_app";

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

  // it.only("lifecycle", async () => {
  //   expect(await contract.methods.storeProofOfAgreement())
  // })

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
