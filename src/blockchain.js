import { ethers } from 'ethers';
import NodeRSA from 'node-rsa';
import crypto from 'crypto';
import { ABICore } from './abiCore.js';
import { checkStringDifferent } from './utils.js';

const PREFIX_RSA_PUE = ':publicEnc';
const PREFIX_RSA_PUS = ':publicSign';
const RSA_KEYS_BITS = 2048;
const BC_CONTRACT_ADDRESS = '0x2900ecb89089ff273c7ffE29C26A1158cEDF24a4';
const BC_RPC = 'http://blockchain.enface.io:59321';

const provider = new ethers.providers.JsonRpcProvider(BC_RPC);
const contract = new ethers.Contract(BC_CONTRACT_ADDRESS, ABICore, provider);

export const publicKeysFromMixedSeed = mixedSeed => {
  mixedSeed = Buffer.from(mixedSeed.substr(2), 'hex');
  return [
    mixedSeed.slice(0, RSA_KEYS_BITS / 8),
    mixedSeed.slice(RSA_KEYS_BITS / 8),
  ].map(componentN => {
    const key = new NodeRSA();
    key.importKey({
      n: componentN,
      e: 65537,
    }, 'components-public');
    return key;
  });
};

export const sha256blockchain = async value => {
  return `0x${crypto.createHash('sha256').update(value).digest('hex')}`;
};

export const getRecordsHashed = async (alias, names) => {
  const aliasHash = await sha256blockchain(alias);
  names = await Promise.all(names.map(x => { return sha256blockchain(x); }));
  return contract.getRecordHashed(aliasHash, names);
};

export const getUserPublicKeys = async alias => {
  const pubKeysSeed = await getRecordsHashed(
    alias,
    [`${alias}${PREFIX_RSA_PUE}`, `${alias}${PREFIX_RSA_PUS}`]
  );
  checkStringDifferent(pubKeysSeed.mixedResult, '0x', 'user not found');
  const [publicKeyEnc, publicKeySign] = await publicKeysFromMixedSeed(pubKeysSeed.mixedResult);
  return { publicKeySign, publicKeyEnc };
};

export const createChallenge = async alias => {
  const { publicKeyEnc, publicKeySign } = await getUserPublicKeys(alias);
  if (!publicKeyEnc || !publicKeySign) {
    throw new Error(`failed to get public keys for alias ${alias}`);
  }
  const randomBytes = Buffer.from(crypto.randomBytes(128));
  const challenge = publicKeyEnc.encrypt(
    randomBytes
  ).toString('hex');
  return { secret: randomBytes, challenge, publicKeySign };
};

export const checkChallenge = async ({ publicKeySign, secret, challengeSigned }) => {
  const [decrypted, sign] = challengeSigned.split('|');
  const equalCheck = Buffer
    .from(secret, 0)
    .equals(Buffer.from(decrypted, 'hex'));
  const signCheck = publicKeySign.verify(secret, Buffer.from(sign, 'hex'));
  return equalCheck && signCheck;
};
