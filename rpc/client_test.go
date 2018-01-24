package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/inwecrypto/ethgo"
	"github.com/inwecrypto/ethgo/tx"
	"github.com/inwecrypto/neogo/rpc"
	neotx "github.com/inwecrypto/neogo/tx"
	"github.com/stretchr/testify/require"
)

var client = New("http://localhost:14019")

func TestEtherWallet(t *testing.T) {
	wallet, err := client.Create("test", EthWallet, "test")

	require.NoError(t, err)

	printResult(wallet)

	_, err = client.Import(wallet)

	require.NoError(t, err)

	gasLimits := big.NewInt(61000)

	gasPrice := ethgo.NewValue(big.NewFloat(20), ethgo.Shannon)

	amount := ethgo.NewValue(big.NewFloat(0.1), ethgo.Ether)

	tx := &EthTx{
		Nonce:     "0x00",
		Wallet:    wallet.Address,
		Asset:     tx.EthAsset,
		To:        wallet.Address,
		Amount:    hex.EncodeToString(amount.Bytes()),
		GasPrice:  hex.EncodeToString(gasPrice.Bytes()),
		GasLimits: hex.EncodeToString(gasLimits.Bytes()),
		Password:  "test",
	}

	rawtx, err := client.EtherTransfer(tx)

	require.NoError(t, err)

	printResult(rawtx)

	err = client.Delete(wallet.Address)

	require.NoError(t, err)

}

func TestNeoWallet(t *testing.T) {
	wallet, err := client.Create("test", NeoWallet, "test")

	require.NoError(t, err)

	printResult(wallet)

	wallet2, err := client.GetOne(wallet.Address)

	require.NoError(t, err)

	printResult(wallet2)

	require.Equal(t, wallet.Address, wallet2.Address)
	require.Equal(t, wallet.Name, wallet2.Name)
	require.Equal(t, wallet.Type, wallet2.Type)
	require.Equal(t, wallet.PublicKey, wallet2.PublicKey)
	require.Equal(t, wallet2.Mnemonic, "")
	require.Equal(t, wallet2.JSON, wallet.JSON)

	menmonic, err := client.Mnemonic(wallet.Address, "test")

	require.NoError(t, err)

	require.Equal(t, menmonic, wallet.Mnemonic)

	amount := big.NewInt(int64(neotx.MakeFixed8(0.1)))

	utxos := []*rpc.UTXO{}

	unspent, err := json.Marshal(utxos)

	require.NoError(t, err)

	tx := &NeoTx{
		Wallet:   wallet.Address,
		Asset:    tx.EthAsset,
		To:       wallet.Address,
		Amount:   hex.EncodeToString(amount.Bytes()),
		Unspent:  string(unspent),
		Password: "test",
	}

	rawtx, err := client.NEOTransfer(tx)

	require.NoError(t, err)

	printResult(rawtx)

	err = client.Delete(wallet.Address)

	require.NoError(t, err)

}

func TestGetWallet(t *testing.T) {
	wallets, err := client.Get()

	require.NoError(t, err)

	printResult(wallets)
}

func printResult(result interface{}) {

	data, _ := json.MarshalIndent(result, "", "\t")

	fmt.Println(string(data))
}
