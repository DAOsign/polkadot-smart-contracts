import { SignTypedDataVersion, signTypedData } from '@metamask/eth-sig-util';
import { ProofOfAgreement, ProofOfAuthority, ProofOfSignature } from '../typedContracts/daosign_app/types-arguments/daosign_app';

export function signMessage(
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
