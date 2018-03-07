package rpc

import (
	"fmt"

	"github.com/dghubble/sling"
)

// WalletType .
type WalletType string

// Wallet type enum
const (
	NeoWallet WalletType = "neo"
	EthWallet            = "eth"
)

// Wallet .
type Wallet struct {
	ID         int64      `json:"-" xorm:"pk autoincr"`
	Name       string     `json:"name" xorm:""`
	Type       WalletType `json:"type" xorm:"index"`
	Address    string     `json:"address,omitempty" xorm:"index"`
	PublicKey  string     `json:"publickey,omitempty" xorm:""`
	Mnemonic   string     `json:"mnemonic,omitempty" xorm:"-"`
	Password   string     `json:"password,omitempty" xorm:"-"`
	PrivateKey string     `json:"wif,omitempty" xorm:"-"`
	JSON       string     `json:"json" xorm:""`
	Lang       string     `json:"lang"`
}

// EthTx .
type EthTx struct {
	Nonce     string `json:"nonce" binding:"required"`
	Wallet    string `json:"wallet" binding:"required"`
	Asset     string `json:"asset" binding:"required"`
	To        string `json:"to" binding:"required"`
	Amount    string `json:"amount" binding:"required"`
	GasPrice  string `json:"gasprice" binding:"required"`
	GasLimits string `json:"gasLimits" binding:"required"`
	Password  string `json:"password" binding:"required"`
}

// NeoTx .
type NeoTx struct {
	Wallet   string `json:"wallet" binding:"required"`
	Asset    string `json:"asset" binding:"required"`
	To       string `json:"to" binding:"required"`
	Amount   string `json:"amount" binding:"required"`
	Gas      string `json:"gas"`
	Unspent  string `json:"unspent" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// NeoRawTX .
type NeoRawTX struct {
	Data string `json:"data"`
	TxID string `json:"txid"`
}

// Client .
type Client struct {
	*sling.Sling
	rootpath string
}

// New .
func New(url string) *Client {
	return &Client{
		Sling:    sling.New(),
		rootpath: url,
	}
}

// Create create new wallet with provider properties
func (client *Client) Create(name string, walletType WalletType, password string) (*Wallet, error) {
	params := &Wallet{
		Name:     name,
		Type:     walletType,
		Password: password,
	}

	request, err := client.Post(fmt.Sprintf("%s/wallet", client.rootpath)).BodyJSON(params).Request()

	if err != nil {
		return nil, err
	}

	var errmsg interface{}

	var result *Wallet

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return nil, err
	}

	if errmsg != nil {
		return nil, fmt.Errorf("%v", errmsg)
	}

	return result, nil
}

// Import import new wallet with provider properties
func (client *Client) Import(wallet *Wallet) (*Wallet, error) {

	request, err := client.Post(fmt.Sprintf("%s/wallet/import", client.rootpath)).BodyJSON(wallet).Request()

	if err != nil {
		return nil, err
	}

	var errmsg interface{}

	var result *Wallet

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return nil, err
	}

	if errmsg != nil {
		return nil, fmt.Errorf("%v", errmsg)
	}

	return result, nil
}

// Get .
func (client *Client) Get() ([]*Wallet, error) {
	request, err := client.Sling.Get(fmt.Sprintf("%s/wallet/", client.rootpath)).Request()

	var errmsg interface{}

	var result []*Wallet

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return nil, err
	}

	if errmsg != nil {
		return nil, fmt.Errorf("%v", errmsg)
	}

	return result, nil
}

// GetOne get one wallet by address
func (client *Client) GetOne(address string) (*Wallet, error) {
	request, err := client.Sling.Get(fmt.Sprintf("%s/wallet/%s", client.rootpath, address)).Request()

	var errmsg interface{}

	var result *Wallet

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return nil, err
	}

	if errmsg != nil {
		return nil, fmt.Errorf("%v", errmsg)
	}

	return result, nil
}

// Mnemonic get wallet mnemonic
func (client *Client) Mnemonic(address string, password string) (string, error) {
	request, err := client.Sling.Get(fmt.Sprintf("%s/mnemonic/%s/%s", client.rootpath, address, password)).Request()

	var errmsg interface{}

	var result string

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return "", err
	}

	if errmsg != nil {
		return "", fmt.Errorf("%v", errmsg)
	}

	return result, nil
}

// Delete delete wallet by address
func (client *Client) Delete(address string) error {
	request, err := client.Sling.Delete(fmt.Sprintf("%s/wallet/%s", client.rootpath, address)).Request()

	var errmsg interface{}

	var result interface{}

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return err
	}

	if errmsg != nil {
		return fmt.Errorf("%v", errmsg)
	}

	return nil
}

// EtherTransfer create and sign a new eth transaction
func (client *Client) EtherTransfer(tx *EthTx) (string, error) {
	request, err := client.Sling.Post(fmt.Sprintf("%s/eth/tx", client.rootpath)).BodyJSON(tx).Request()

	var errmsg interface{}

	var result string

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return "", err
	}

	if errmsg != nil {
		return "", fmt.Errorf("%v", errmsg)
	}

	return result, nil
}

// NEOTransfer create and sign a new neo transaction
func (client *Client) NEOTransfer(tx *NeoTx) (*NeoRawTX, error) {
	request, err := client.Sling.Post(fmt.Sprintf("%s/neo/tx", client.rootpath)).BodyJSON(tx).Request()

	var errmsg interface{}

	var result *NeoRawTX

	_, err = client.Do(request, &result, &errmsg)

	if err != nil {
		return nil, err
	}

	if errmsg != nil {
		return nil, fmt.Errorf("%v", errmsg)
	}

	return result, nil
}
