const express = require("express");
const app = express();
const cors = require("cors");
const {
  generateBalances,
  recoverPublicKeyFromSignature,
  getAddress,
} = require("./helpers");
const { toHex } = require("ethereum-cryptography/utils");

const PORT = process.env.PORT || 3042;

app.use(cors());
app.use(express.json());

let balances = [];
app.get("/generate-balances", (req, res) => {
  balances = generateBalances();
  res.json(balances);
});

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances.find((balance) => balance.address === address);
  res.send(balance);
});

app.post("/send", (req, res) => {
  // Receive signature from client
  const { msg, signature, recoveryBit } = req.body;
  const { amount, recipient } = msg;

  const publicKey = recoverPublicKeyFromSignature(msg, signature, recoveryBit);
  const sender = `0x${toHex(getAddress(publicKey))}`; // Get wallet address from public key

  const senderIndex = balances.findIndex(
    (balance) => balance.address === sender
  );
  const recipientIndex = balances.findIndex(
    (balance) => balance.address === recipient
  );

  if (senderIndex < 0 || recipientIndex < 0)
    return res.status(400).send({ message: "Invalid address" });

  if (balances[senderIndex].balance < amount) {
    return res.status(400).send({ message: "Not enough funds!" });
  }

  balances[senderIndex].balance -= amount;
  balances[recipientIndex].balance += amount;

  res.send({ balance: balances[senderIndex].balance });
});

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`);
});