import * as secp from "ethereum-cryptography/secp256k1";
import { keccak256 } from "ethereum-cryptography/keccak";
import { hexToBytes, toHex } from "ethereum-cryptography/utils";

/**
 * Local wallet.
 * Simulate a MetaMask-like wallet which stores private keys safely,
 * and gives access to public key/address.
 * Keys are store in hexadecimal format.
 */

// List of account keys in hexa format
const ACCOUNT_KEYS = new Map([
  [
    "arda",
    {
      private:
        "f906f5ff52331f1ea1dbd4d2981c5f2eb8903e127bf6802ba6f39f8552f29a99",
      public:
        "040b0cc7eaa59316dec6e463fcfd8ffb80cd1b70792f341a6342bbf701066027a4d72cc59a49d8c7a75cf93d236ec3f92637af86d354d2991510bedb3e5131d0fb",
    },
  ],
  [
    "edu",
    {
      private:
        "9a18f818f3c89e52dbb9e75b6f5841b0ab32437ada3dc8222d2154b6d3d44f9d",
      public:
        "041e53f53ec0176ffcde1a988b328a02481b5b6bf95b632558e0f12410b0c19f9ce73964793ab34e56f9d5d3dc1db494c9766a9fa692eb293d6e7c10e8a903ec61",
    },
  ],
  [
    "sam",
    {
      private:
        "e17f36d60851f9a0c641b9d2d9da84ef2d8a4c783c359c233c741a14f5ed412a",
      public:
        "04b5bfe9ff91477e2329296e63f191fc7e109491e588a0b7da42f820d351d5a39dbfb8b534cb0b48cbf76ce2d13ed0c86e1c5aa9ea489fa7e5f63f9b889603823a",
    },
  ],
]);

// user names derived from the list of accounts
const USERS = Array.from(ACCOUNT_KEYS.keys());

/**
 * Hash a message using KECCAK-256
 * @param message the message to hash.
 * @returns the hash of the message.
 */
const hashMessage = (message) => keccak256(Uint8Array.from(message));

/**
 * Get the user public key.
 * @param user the user
 * @returns the public key as a Uint8Array.
 */
const getPublicKey = (user) => {
  if (!user) return null;
  return hexToBytes(ACCOUNT_KEYS.get(user).public);
};

/**
 * Get the user private key.
 * @param user the user.
 * @returns the private key as a Uint8Array.
 */
const getPrivateKey = (user) => {
  if (!user) return null;
  return hexToBytes(ACCOUNT_KEYS.get(user).private);
};

/**
 * Derive the address from the public key of an user.
 * @param user the user.
 * @returns the user address as a hexa string.
 */
const getAddress = (user) => {
  if (!user) return null;
  const pubKey = getPublicKey(user);
  const hash = keccak256(pubKey.slice(1));
  return `0x${toHex(hash.slice(-20))}`;
};

/**
 * Get the public key of an user in hexa format.
 * @param user the user.
 * @returns the public key.
 */
const getHexPubKey = (user) => {
  if (!user) return null;
  return toHex(getPublicKey(user)).toUpperCase();
};

/**
 * Sign a message.
 * @param username name of the user account.
 * @param message message to sign
 * @returns the signature in hexa format with the recovery bit as the first byte.
 */
const sign = async (username, message) => {
  const privateKey = getPrivateKey(username);
  const hash = hashMessage(message);

  const [signature, recoveryBit] = await secp.sign(hash, privateKey, {
    recovered: true,
  });
  const fullSignature = new Uint8Array([recoveryBit, ...signature]);
  return toHex(fullSignature);
};

const wallet = {
  USERS,
  sign,
  getAddress,
  getHexPubKey,
};
export default wallet;