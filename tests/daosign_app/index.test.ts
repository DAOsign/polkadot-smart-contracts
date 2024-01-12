import { expect, use } from 'chai';
import util from 'util';
import chaiAsPromised from 'chai-as-promised';
import { SignTypedDataVersion, signTypedData } from '@metamask/eth-sig-util';
import DAOsignAppFactory from '../../typedContracts/daosign_app/constructors/daosign_app';
import DAOsignApp from '../../typedContracts/daosign_app/contracts/daosign_app';
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { KeyringPair } from '@polkadot/keyring/types';
import { EIP712Domain, ProofOfAgreement, ProofOfAuthority, ProofOfSignature, SignedProofOfAgreement, SignedProofOfAuthority, SignedProofOfSignature } from '../../typedContracts/daosign_app/types-arguments/daosign_app';

use(chaiAsPromised);

function signMessage(
  pkey: Buffer,
  primaryType: 'ProofOfAuthority' | 'ProofOfSignature' | 'ProofOfAgreement',
  message: ProofOfAuthority | ProofOfSignature | ProofOfAgreement,
): string {
  return signTypedData({
    privateKey: pkey,
    version: SignTypedDataVersion.V4,
    data: {
      domain: {
        name: 'daosign',
        version: '0.1.0',
        chainId: 0,
        verifyingContract: '0x0000000000000000000000000000000000000000',
      },
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Signer: [
          { name: 'addr', type: 'address' },
          { name: 'metadata', type: 'string' },
        ],
        ProofOfAuthority: [
          { name: 'name', type: 'string' },
          { name: 'from', type: 'address' },
          { name: 'agreementCID', type: 'string' },
          { name: 'signers', type: 'Signer[]' },
          { name: 'app', type: 'string' },
          { name: 'timestamp', type: 'uint256' },
          { name: 'metadata', type: 'string' },
        ],
        ProofOfSignature: [
          { name: 'name', type: 'string' },
          { name: 'signer', type: 'address' },
          { name: 'agreementCID', type: 'string' },
          { name: 'app', type: 'string' },
          { name: 'timestamp', type: 'uint256' },
          { name: 'metadata', type: 'string' },
        ],
        ProofOfAgreement: [
          { name: 'agreementCID', type: 'string' },
          { name: 'signatureCIDs', type: 'string[]' },
          { name: 'app', type: 'string' },
          { name: 'timestamp', type: 'uint256' },
          { name: 'metadata', type: 'string' },
        ],
      },
      primaryType,
      message,
    },
  });
}

const numberToArray = (timestamp: number) => Array.from({ length: 32 }, (_, i) => i < 28 ? 0 : (timestamp >> ((31 - i) * 8)) & 255);
const arrayToNumber = arr => arr.reduce((acc, val, i) => acc + val * Math.pow(256, arr.length - 1 - i), 0);

const hexStringToArray = (hexString, totalLength = 0) => {
    const byteArray = Array.from(hexString.slice(2).match(/.{1,2}/g), (byte: string) => parseInt(byte, 16));
    const paddingSize = Math.max(totalLength - byteArray.length, 0);
    return Array(paddingSize).fill(0).concat(byteArray);
};
const arrayToHexString = arr => '0x' + arr.map(byte => byte.toString(16).padStart(2, '0')).join('');

const numberToPaddedHexString = (num: number) => '0x' + num.toString(16).padStart(64, '0');
const addrToPaddedAddr = (addr: string) => `0x${addr.substring(2).padStart(64, '0')}`

// Create a new instance of contract
const wsProvider = new WsProvider('ws://127.0.0.1:9944');
// Create a keyring instance
const keyring = new Keyring({ type: 'sr25519' });

describe('DAOsignApp Tests', () => {
  let appFactory: DAOsignAppFactory;
  let api: ApiPromise;
  let deployer: KeyringPair;
  let contract: DAOsignApp;

  const eip712Domain: EIP712Domain = {
      name: 'daosign',
      version: '0.1.0',
      chainId: new Array(32).fill(0),
      verifyingContract: new Array(32).fill(0),
  };

  const assertPoA = async (actual: any, expected: SignedProofOfAuthority) => {
    const data = { ...expected };

    // @ts-ignore
    data.signature = arrayToHexString(expected.signature);
    // @ts-ignore
    data.message.from = arrayToHexString(expected.message.from);
    // @ts-ignore
    data.message.signers[0].addr = arrayToHexString(expected.message.signers[0].addr);
    // @ts-ignore
    data.message.timestamp = numberToPaddedHexString(arrayToNumber(expected.message.timestamp));

    expect(actual).eql(data);
  }

  const assertPoS = async (actual: any, expected: SignedProofOfSignature) => {
    const data = { ...expected };

    // @ts-ignore
    data.signature = arrayToHexString(expected.signature);
    // @ts-ignore
    data.message.signer = arrayToHexString(expected.message.signer);
    // @ts-ignore
    data.message.timestamp = numberToPaddedHexString(arrayToNumber(expected.message.timestamp));

    expect(actual).eql(data);
  }

  const assertPoAg = async (actual: any, expected: SignedProofOfAgreement) => {
    const data = { ...expected };

    // @ts-ignore
    data.signature = arrayToHexString(expected.signature);
    // @ts-ignore
    data.message.timestamp = numberToPaddedHexString(arrayToNumber(expected.message.timestamp));

    expect(actual).eql(data);
  }

  before(async function setup(): Promise<void> {
    api = await ApiPromise.create({ provider: wsProvider });
    deployer = keyring.addFromUri('//Alice');

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

  describe('Store/Get functions', () => {
    it('Proof-of-Authority', async () => {
      const proofCID = 'ProofOfAuthority proof cid                    ';

      let data = {
          message: {
              name: 'Proof-of-Authority',
              from: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
              agreementCid: 'agreement file cid                            ',
              signers: [{
                  addr: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
                  metadata: 'some metadata',
              }],
              app: 'daosign',
              timestamp: numberToArray(1702609459),
              metadata: 'proof metadata',
          },
          signature: hexStringToArray('0x130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c'),
          proofCid: proofCID,
      };
      await contract.withSigner(deployer).tx.storeProofOfAuthority(data);
      await assertPoA(
        (await contract.query.getProofOfAuthority(proofCID)).value.ok,
        data
      );
    });

    it('Proof-of-Signature', async () => {
      // Store Proof-of-Authority
      {
        const proofCID = 'ProofOfAuthority proof cid                    ';

        let data = {
            message: {
                name: 'Proof-of-Authority',
                from: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
                agreementCid: 'agreement file cid                            ',
                signers: [{
                    addr: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
                    metadata: 'some metadata',
                }],
                app: 'daosign',
                timestamp: numberToArray(1702609459),
                metadata: 'proof metadata',
            },
            signature: hexStringToArray('0x130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c'),
            proofCid: proofCID,
        };
        await contract.withSigner(deployer).tx.storeProofOfAuthority(data);
      }

      const proofCID = 'ProofOfSignature proof cid                    ';
      let data: SignedProofOfSignature = {
          message: {
              name: 'Proof-of-Signature',
              signer: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
              agreementCid: 'ProofOfAuthority proof cid                    ',
              app: 'daosign',
              timestamp: numberToArray(1702609048),
              metadata: 'proof metadata',
          },
          signature: hexStringToArray('0x3873d49c83039d1624ec52ee6f6edbe0d31105a7aebcd1304e8326adc0807c3e692efc2b302370dbc0c7ea44904130e3468ff34ff1eaf65613ad8ba6db9405e31c'),
          proofCid: proofCID,
      };

      await contract.withSigner(deployer).tx.storeProofOfSignature(data);
      await assertPoS(
        (await contract.query.getProofOfSignature(proofCID)).value.ok,
        data
      );
    });

    it('Proof-of-Agreement', async () => {
      // Store Proof-of-Authority
      {
        const proofCID = 'ProofOfAuthority proof cid                    ';
        let data = {
            message: {
                name: 'Proof-of-Authority',
                from: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
                agreementCid: 'agreement file cid                            ',
                signers: [{
                    addr: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
                    metadata: 'some metadata',
                }],
                app: 'daosign',
                timestamp: numberToArray(1702609459),
                metadata: 'proof metadata',
            },
            signature: hexStringToArray('0x130561fa55cda78e5a9ac0cb96e76409fa5112a39422604b043580a559a2a352641f71fe278c74192594c27d3d7c5b7f7995e63bd0ddc96124ae8532fe51d9111c'),
            proofCid: proofCID,
        };
        await contract.withSigner(deployer).tx.storeProofOfAuthority(data);
      }

      // Store Proof-of-Signature
      {
        const proofCID = 'ProofOfSignature proof cid                    ';
        let data: SignedProofOfSignature = {
            message: {
                name: 'Proof-of-Signature',
                signer: hexStringToArray('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 32),
                agreementCid: 'ProofOfAuthority proof cid                    ',
                app: 'daosign',
                timestamp: numberToArray(1702609048),
                metadata: 'proof metadata',
            },
            signature: hexStringToArray('0x3873d49c83039d1624ec52ee6f6edbe0d31105a7aebcd1304e8326adc0807c3e692efc2b302370dbc0c7ea44904130e3468ff34ff1eaf65613ad8ba6db9405e31c'),
            proofCid: proofCID,
        };

        await contract.withSigner(deployer).tx.storeProofOfSignature(data);
      }

      const proofCID = 'ProofOfSignature proof cid                    ';
      let data: SignedProofOfAgreement = {
          message: {
              agreementCid: 'ProofOfAuthority proof cid                    ',
              signatureCids: ['ProofOfSignature proof cid                    '],
              app: 'daosign',
              timestamp: numberToArray(1705019531),
              metadata: 'proof metadata',
          },
          signature: hexStringToArray('0xb08e354fbe0f3231dfff0e90a312c8f1c31cb4a307a24432b83beaf374d5e11d58966b3501a7d904468ada29a7d19430e03fcaafe31fb4945c1c389a733de98d1b'),
          proofCid: proofCID,
      };

      await contract.withSigner(deployer).tx.storeProofOfAgreement(data);
      await assertPoAg(
        (await contract.query.getProofOfAgreement(proofCID)).value.ok,
        data
      );
    });

  });
});
