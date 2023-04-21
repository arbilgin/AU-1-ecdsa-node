import { keccak256 } from "ethereum-cryptography/keccak";
import { sign } from "ethereum-cryptography/secp256k1";
import { utf8ToBytes } from "ethereum-cryptography/utils";

export function hashMessage(message) {
  const bytes = utf8ToBytes(JSON.stringify(message));
  const hash = keccak256(bytes);
  return hash;
}

export async function signMessage(hashedMessage, privateKey, recovered = true) {
  return await sign(hashedMessage, privateKey, { recovered });
}