import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import AppFactory from "./typedContract/constructors/app";
import App from "./typedContract/contracts/app";
import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";

use(chaiAsPromised);

// Create a new instance of contract
const wsProvider = new WsProvider("ws://127.0.0.1:9944");
// Create a keyring instance
const keyring = new Keyring({ type: "sr25519" });

describe("app test", () => {
  let appFactory: AppFactory;
  let api: ApiPromise;
  let deployer: KeyringPair;
  
  let contract: App;
  const initialState = true;

  before(async function setup(): Promise<void> {
    api = await ApiPromise.create({ provider: wsProvider });
    deployer = keyring.addFromUri("//Alice");

    appFactory = new AppFactory(api, deployer);

    contract = new App(
      (await appFactory.new(initialState)).address,
      deployer,
      api
    );
  });

  after(async function tearDown() {
    await api.disconnect();
  });
});
