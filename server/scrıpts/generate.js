const secp = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { toHex, utf8ToBytes } = require("ethereum-cryptography/utils");

const generateData = () => {
  const privateKey1 = toHex(secp.utils.randomPrivateKey());
  const publicKey1 = toHex(secp.getPublicKey(privateKey1));
  const wallet1 = toHex(keccak256(utf8ToBytes(publicKey1).slice(1)).slice(-20));

  const privateKey2 = toHex(secp.utils.randomPrivateKey());
  const publicKey2 = toHex(secp.getPublicKey(privateKey2));
  const wallet2 = toHex(keccak256(utf8ToBytes(publicKey2).slice(1)).slice(-20));

  const privateKey3 = toHex(secp.utils.randomPrivateKey());
  const publicKey3 = toHex(secp.getPublicKey(privateKey3));
  const wallet3 = toHex(keccak256(utf8ToBytes(publicKey3).slice(1)).slice(-20));

  return {
    pairKey1: {
      privateKey: privateKey1,
      publicKey: publicKey1,
      wallet: wallet1,
    },
    pairKey2: {
      privateKey: privateKey2,
      publicKey: publicKey2,
      wallet: wallet2,
    },
    pairKey3: {
      privateKey: privateKey3,
      publicKey: publicKey3,
      wallet: wallet3,
    },
  };
};

console.log(generateData());

module.exports = { generateData };