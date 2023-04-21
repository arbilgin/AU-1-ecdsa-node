import Wallet from "./Wallet";
import Transfer from "./Transfer";
import "./App.scss";
import { useState } from "react";
import server from "./server";
import { useEffect } from "react";

const { data: balances } = await server.get("/generate-balances");
const Balance = () => {
  return (
    <div className="container balances">
      <u>
        <h3>Test balances</h3>
      </u>

      <div>
        {balances.map(({ privateKey, publicKey, address, balance }, index) => (
          <div className="balance_container" key={index}>
            <p>
              <b>Private key:</b> {privateKey}
            </p>
            <p>
              <b>Public key:</b> {publicKey}
            </p>
            <p>
              <b>Address: </b>
              {address}
            </p>
            <p>
              <b>Balance: </b>
              {balance}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};

function App() {
  const [balance, setBalance] = useState(0);
  const [address, setAddress] = useState("");
  const [privateKey, setPrivatekey] = useState("");

  useEffect(() => {
    if (address && address.length >= 42) {
      const { privateKey } = balances.find(
        (balance) => balance.address === address
      );
      setPrivatekey(privateKey);
    }
  }, [address]);

  return (
    <div className="app">
      <Wallet
        balance={balance}
        setBalance={setBalance}
        address={address}
        setAddress={setAddress}
      />
      <Transfer
        setBalance={setBalance}
        address={address}
        privateKey={privateKey}
      />
      <Balance />
    </div>
  );
}

export default App;