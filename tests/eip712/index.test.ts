import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import Eip712Factory from "./typedContract/constructors/eip712";
import Eip712 from "./typedContract/contracts/eip712";
import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";

use(chaiAsPromised);

// Create a new instance of contract
const wsProvider = new WsProvider("ws://127.0.0.1:9944");
// Create a keyring instance
const keyring = new Keyring({ type: "sr25519" });

describe("eip712 test", () => {
  let eip712Factory: Eip712Factory;
  let api: ApiPromise;
  let deployer: KeyringPair;
  
  let contract: Eip712;
  const initialState = true;

  before(async function setup(): Promise<void> {
    api = await ApiPromise.create({ provider: wsProvider });
    deployer = keyring.addFromUri("//Alice");

    eip712Factory = new Eip712Factory(api, deployer);

    contract = new Eip712(
      (await eip712Factory.new(initialState)).address,
      deployer,
      api
    );
  });

  after(async function tearDown() {
    await api.disconnect();
  });
});
