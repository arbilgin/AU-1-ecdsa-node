import server from "./server";

function Wallet({ address, setAddress, balance, setBalance }) {
  async function onChange(evt) {
    const address = evt.target.value;
    setAddress(address);

    if (address) {
      const {
        data: { balance },
      } = await server.get(`balance/${address}`);
      setBalance(balance);
    } else {
      setBalance(0);
    }
  }

  return (
    <div className="container wallet">
      <h1>Pick your wallet</h1>

      <label>
        Wallet address:
        <input
          placeholder="Wallet address"
          value={address}
          onChange={onChange}
        />
      </label>

      <div className="balance">Balance: {balance}</div>
    </div>
  );
}

export default Wallet;