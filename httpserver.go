package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dynamicgo/config"
	"github.com/dynamicgo/slf4go"
	"github.com/gin-gonic/gin"
	"github.com/go-xorm/xorm"
	"github.com/inwecrypto/bip39"
	"github.com/inwecrypto/ethgo"
	"github.com/inwecrypto/ethgo/erc20"
	ethkeystore "github.com/inwecrypto/ethgo/keystore"
	ethtx "github.com/inwecrypto/ethgo/tx"
	neokeystore "github.com/inwecrypto/neogo/keystore"
	"github.com/inwecrypto/neogo/nep5"
	neorpc "github.com/inwecrypto/neogo/rpc"
	neotx "github.com/inwecrypto/neogo/tx"
	"github.com/inwecrypto/wallet-service/rpc"
)

// APIServer .
type APIServer struct {
	engine *gin.Engine
	slf4go.Logger
	laddr string
	db    *xorm.Engine
	// keystoredir string
}

func checkDirectory(path string) error {
	_, err := os.Stat(path)

	if err == nil {
		return nil
	}

	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0777)
	}

	return err
}

// NewAPIServer .
func NewAPIServer(appdir string, laddr string, conf *config.Config) (*APIServer, error) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	if conf.GetBool("wallet.debug", false) {
		engine.Use(gin.Logger())
		gin.SetMode(gin.DebugMode)
	}

	localdb := conf.GetString("wallet.db.path", "localdb")

	checkDirectory(filepath.Join(appdir, localdb))

	dbname := filepath.Join(appdir, localdb, conf.GetString("wallet.db.name", "wallet.db"))

	db, err := xorm.NewEngine(
		"sqlite3",
		dbname,
	)

	if err != nil {
		return nil, err
	}

	if err := db.Sync2(new(rpc.Wallet)); err != nil {
		return nil, fmt.Errorf("sync table schema error ")
	}

	// keystoredir := filepath.Join(appdir, conf.GetString("wallet.keystore", "keystore"))

	// checkDirectory(keystoredir)

	server := &APIServer{
		engine: engine,
		Logger: slf4go.Get("wallet-service"),
		laddr:  laddr,
		db:     db,
		// keystoredir: keystoredir,
	}

	server.makeRouter()

	return server, nil
}

// Run run http service
func (server *APIServer) Run() error {
	return server.engine.Run(server.laddr)
}

func (server *APIServer) makeRouter() {
	server.engine.POST("/wallet", func(ctx *gin.Context) {

		var wallet *rpc.Wallet

		if err := ctx.ShouldBindJSON(&wallet); err != nil {
			server.ErrorF("parse wallet error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		if wallet.Password == "" {
			server.ErrorF("create wallet required password params")

			ctx.JSON(http.StatusForbidden, gin.H{"error": "create wallet required password params"})

			return
		}

		if wallet.Lang == "" {
			wallet.Lang = "en_US"
		}

		if wallet.Type == rpc.NeoWallet {
			if err := server.createNEOWallet(wallet); err != nil {
				server.ErrorF("create wallet error :%s", err)

				ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
		} else {
			if err := server.createETHWallet(wallet); err != nil {
				server.ErrorF("create wallet error :%s", err)

				ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
		}

		ctx.JSON(http.StatusOK, wallet)
	})

	server.engine.GET("/mnemonic/:address/:password/:lang", func(ctx *gin.Context) {
		address := ctx.Param("address")
		password := ctx.Param("password")
		lang := ctx.Param("lang")
		var wallet rpc.Wallet
		ok, err := server.db.Where("address = ?", address).Get(&wallet)

		if err != nil {
			server.ErrorF("get wallet by address %s :%s", address, err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if !ok {
			server.ErrorF("get wallet by address %s not found", address)

			ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		if wallet.Type == rpc.EthWallet {
			key, err := neokeystore.ReadKeyStore([]byte(wallet.JSON), password)

			if err != nil {
				server.ErrorF("read keystore of wallet address %s failed %s", address, err)

				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			mnemonic, err := getMnemonic(lang, key.ToBytes())

			if err != nil {
				server.ErrorF("read keystore of wallet address %s failed %s", address, err)

				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			ctx.JSON(http.StatusOK, mnemonic)

			return

		}

		key, err := ethkeystore.ReadKeyStore([]byte(wallet.JSON), password)

		if err != nil {
			server.ErrorF("read keystore of wallet address %s failed %s", address, err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		mnemonic, err := getMnemonic(lang, key.ToBytes())

		if err != nil {
			server.ErrorF("read keystore of wallet address %s failed %s", address, err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, mnemonic)

		return
	})

	server.engine.GET("/wallet/*address", func(ctx *gin.Context) {
		address := ctx.Param("address")

		if address != "/" {
			address = strings.TrimPrefix(address, "/")
			var wallet rpc.Wallet
			ok, err := server.db.Where("address = ?", address).Get(&wallet)

			if err != nil {
				server.ErrorF("get wallet by address %s :%s", address, err)

				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			if !ok {
				server.ErrorF("get wallet by address %s not found", address)

				ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}

			ctx.JSON(http.StatusOK, wallet)
			return
		}

		wallets := make([]*rpc.Wallet, 0)

		if err := server.db.Find(&wallets); err != nil {
			server.ErrorF("get wallet by address %s not found", address)

			ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		ctx.JSON(http.StatusOK, wallets)
	})

	server.engine.DELETE("/wallet/:address", func(ctx *gin.Context) {
		address := ctx.Param("address")

		wallet := &rpc.Wallet{
			Address: address,
		}

		c, err := server.db.Delete(wallet)

		if err != nil {
			server.ErrorF("delete wallet by address %s :%s", address, err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if c == 0 {
			server.ErrorF("delete wallet by address %s not found", address)

			ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		ctx.JSON(http.StatusOK, nil)
	})

	server.engine.GET("/neo/address/encode/:address", func(ctx *gin.Context) {
		address, err := EncodeAddress(ctx.Param("address"))

		if err != nil {
			server.ErrorF("encode neo address %s failed:%s", ctx.Param("address"), err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, address)
	})

	server.engine.GET("/neo/address/decode/:address", func(ctx *gin.Context) {
		address, err := DecodeAddress(ctx.Param("address"))

		if err != nil {
			server.ErrorF("decode neo address %s failed:%s", ctx.Param("address"), err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, address)
	})

	server.engine.POST("/eth/tx", func(ctx *gin.Context) {
		var tx *rpc.EthTx

		if err := ctx.ShouldBindJSON(&tx); err != nil {
			server.ErrorF("parse tx error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		server.DebugF("eth tx :\n%s", printResult(tx))

		codes, err := server.transferEther(tx)

		if err != nil {
			server.ErrorF("create tx error :%s", err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, codes)
	})

	server.engine.POST("/neo/tx", func(ctx *gin.Context) {
		var tx *rpc.NeoTx

		if err := ctx.ShouldBindJSON(&tx); err != nil {
			server.ErrorF("parse tx error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		server.DebugF("eth tx :\n%s", printResult(tx))

		codes, err := server.transferNeo(tx)

		if err != nil {
			server.ErrorF("create tx error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, codes)
	})

	server.engine.POST("/wallet/import", func(ctx *gin.Context) {
		var wallet *rpc.Wallet

		if err := ctx.ShouldBindJSON(&wallet); err != nil {
			server.ErrorF("parse wallet error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		var err error

		if wallet.Mnemonic != "" {
			err = server.ImportFromMnemonic(wallet)
		} else if wallet.PrivateKey != "" {
			err = server.ImportFromPrivateKey(wallet)
		} else if wallet.JSON != "" {
			err = server.ImportFromKeyStore(wallet)
		}

		if err != nil {
			server.ErrorF("import wallet error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})

			return
		}

		_, err = server.db.Delete(wallet)

		if err != nil {
			server.ErrorF("delete wallet by address %s :%s", wallet.Address, err)

			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		_, err = server.db.InsertOne(wallet)

		if err != nil {
			server.ErrorF("import wallet error :%s", err)

			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})

			return
		}

		ctx.JSON(http.StatusOK, wallet)
	})
}

// ImportFromMnemonic .
func (server *APIServer) ImportFromMnemonic(wallet *rpc.Wallet) error {
	if wallet.Type == rpc.EthWallet {
		dic, _ := bip39.GetDict(wallet.Lang)

		data, err := bip39.MnemonicToByteArray(wallet.Mnemonic, dic)

		if err != nil {
			return err
		}

		data = data[1 : len(data)-1]

		println(hex.EncodeToString(data))

		keystore, err := ethkeystore.KeyFromPrivateKey(data)

		if err != nil {
			return err
		}

		keystoreJSON, err := ethkeystore.WriteScryptKeyStore(keystore, wallet.Password)

		if err != nil {
			return err
		}

		wallet.Address = keystore.Address
		wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())
		wallet.JSON = string(keystoreJSON)

		// _, err = server.db.InsertOne(wallet)

		// return err

		return nil

	} else if wallet.Type == rpc.NeoWallet {
		dic, _ := bip39.GetDict(wallet.Lang)

		data, err := bip39.MnemonicToByteArray(wallet.Mnemonic, dic)

		if err != nil {
			return err
		}

		data = data[1 : len(data)-1]

		println(hex.EncodeToString(data))

		keystore, err := neokeystore.KeyFromPrivateKey(data)

		if err != nil {
			return err
		}

		keystoreJSON, err := neokeystore.WriteScryptKeyStore(keystore, wallet.Password)

		if err != nil {
			return err
		}

		wallet.Address = keystore.Address
		wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())
		wallet.JSON = string(keystoreJSON)

		// _, err = server.db.InsertOne(wallet)

		// return err

		return nil
	} else {
		return fmt.Errorf("unknown wallet type :%s", wallet.Type)
	}
}

// ImportFromKeyStore .
func (server *APIServer) ImportFromKeyStore(wallet *rpc.Wallet) error {
	if wallet.Type == rpc.EthWallet {
		keystore, err := ethkeystore.ReadKeyStore([]byte(wallet.JSON), wallet.Password)

		if err != nil {
			return err
		}

		mnemonic, err := getMnemonic("en_US", keystore.ToBytes())

		if err != nil {
			return err
		}

		wallet.Address = keystore.Address
		wallet.Mnemonic = mnemonic
		wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())

		// _, err = server.db.InsertOne(wallet)

		// return err

		return nil
	} else if wallet.Type == rpc.NeoWallet {
		keystore, err := neokeystore.ReadKeyStore([]byte(wallet.JSON), wallet.Password)

		if err != nil {
			return err
		}

		mnemonic, err := getMnemonic("en_US", keystore.ToBytes())

		if err != nil {
			return err
		}

		wallet.Address = keystore.Address
		wallet.Mnemonic = mnemonic
		wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())

		// _, err = server.db.InsertOne(wallet)

		// return err

		return nil
	} else {
		return fmt.Errorf("unknown wallet type :%s", wallet.Type)
	}

}

// ImportFromPrivateKey .
func (server *APIServer) ImportFromPrivateKey(wallet *rpc.Wallet) error {
	if wallet.Type == rpc.EthWallet {

		data, err := hex.DecodeString(strings.TrimPrefix(wallet.PrivateKey, "0x"))

		if err != nil {
			return err
		}

		keystore, err := ethkeystore.KeyFromPrivateKey(data)

		if err != nil {
			return err
		}

		keystoreJSON, err := ethkeystore.WriteScryptKeyStore(keystore, wallet.Password)

		if err != nil {
			return err
		}

		wallet.Address = keystore.Address
		wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())
		wallet.JSON = string(keystoreJSON)

		// _, err = server.db.InsertOne(wallet)

		// return err

		return nil

	} else if wallet.Type == rpc.NeoWallet {
		keystore, err := neokeystore.KeyFromWIF(wallet.PrivateKey)

		if err != nil {
			return err
		}

		keystoreJSON, err := neokeystore.WriteScryptKeyStore(keystore, wallet.Password)

		if err != nil {
			return err
		}

		wallet.Address = keystore.Address
		wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())
		wallet.JSON = string(keystoreJSON)

		// _, err = server.db.InsertOne(wallet)

		// return err
		return nil
	} else {
		return fmt.Errorf("unknown wallet type :%s", wallet.Type)
	}
}

func (server *APIServer) getEtherWallet(address string, password string) (*ethkeystore.Key, error) {
	var wallet rpc.Wallet
	ok, err := server.db.Where("address = ?", address).Get(&wallet)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("wallet %s -- not found", address)
	}

	return ethkeystore.ReadKeyStore([]byte(wallet.JSON), password)

}

func printResult(result interface{}) string {

	data, _ := json.MarshalIndent(result, "", "\t")

	return string(data)
}

func (server *APIServer) getNeoWallet(address string, password string) (*neokeystore.Key, error) {
	var wallet rpc.Wallet
	ok, err := server.db.Where("address = ?", address).Get(&wallet)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("wallet %s -- not found", address)
	}

	return neokeystore.ReadKeyStore([]byte(wallet.JSON), password)

}

func (server *APIServer) transferNeo(tx *rpc.NeoTx) (*rpc.NeoRawTX, error) {
	key, err := server.getNeoWallet(tx.Wallet, tx.Password)

	if err != nil {
		return nil, err
	}

	amount, err := readBigint(tx.Amount)

	if err != nil {
		return nil, err
	}

	var utxos []*neorpc.UTXO

	if err := json.Unmarshal([]byte(tx.Unspent), &utxos); err != nil {
		return nil, err
	}

	if tx.Asset == neotx.NEOAssert || tx.Asset == neotx.GasAssert {

		tansferTx := neotx.NewContractTx()

		vout := []*neotx.Vout{
			&neotx.Vout{
				Asset:   neotx.NEOAssert,
				Value:   neotx.Fixed8(amount.Int64()),
				Address: tx.To,
			},
		}

		if err := tansferTx.CalcInputs(vout, utxos); err != nil {
			return nil, err
		}

		rawtxdata, txid, err := tansferTx.Tx().Sign(key.PrivateKey)

		return &rpc.NeoRawTX{
			Data: hex.EncodeToString(rawtxdata),
			TxID: txid,
		}, err
	}

	scriptHash, err := hex.DecodeString(strings.TrimPrefix(tx.Asset, "0x"))

	if err != nil {
		return nil, err
	}

	scriptHash = reverseBytes(scriptHash)

	from, err := DecodeAddress(key.Address)

	if err != nil {
		server.ErrorF("decode from address %s err %s", key.Address, err)
		return nil, err
	}

	bytesOfFrom, err := hex.DecodeString(from)

	if err != nil {
		return nil, err
	}

	to, err := DecodeAddress(tx.To)

	if err != nil {
		server.ErrorF("decode to address %s err %s", key.Address, err)
		return nil, err
	}

	bytesOfTo, err := hex.DecodeString(to)

	if err != nil {
		return nil, err
	}

	script, err := nep5.Transfer(scriptHash, bytesOfFrom, bytesOfTo, amount)

	gas, err := readBigint(tx.Gas)

	if err != nil {
		return nil, err
	}

	gasFixed8 := neotx.Fixed8(gas.Int64())

	tansferTx := neotx.NewInvocationTx(script, gasFixed8.Float64())

	err = tansferTx.CalcInputs(nil, utxos)

	if err != nil {
		return nil, err
	}

	rawtxdata, txid, err := tansferTx.Tx().Sign(key.PrivateKey)

	return &rpc.NeoRawTX{
		Data: hex.EncodeToString(rawtxdata),
		TxID: "0x" + txid,
	}, err

}

func (server *APIServer) transferEther(tx *rpc.EthTx) (string, error) {

	key, err := server.getEtherWallet(tx.Wallet, tx.Password)

	if err != nil {
		return "", err
	}

	nonce, err := readBigint(tx.Nonce)

	if err != nil {
		return "", err
	}

	amount, err := readBigint(tx.Amount)

	if err != nil {
		return "", err
	}

	gasPrice, err := readBigint(tx.GasPrice)

	if err != nil {
		return "", err
	}

	gasLimits, err := readBigint(tx.GasLimits)

	if err != nil {
		return "", err
	}

	var transferTx *ethtx.Tx

	if tx.Asset == ethtx.EthAsset {
		transferTx = ethtx.NewTx(
			nonce.Uint64(),
			tx.To,
			(*ethgo.Value)(amount),
			(*ethgo.Value)(gasPrice),
			gasLimits,
			nil)
	} else {
		codes, err := erc20.Transfer(tx.Password, tx.Amount)

		if err != nil {
			return "", err
		}

		transferTx = ethtx.NewTx(
			nonce.Uint64(),
			tx.Asset,
			nil,
			(*ethgo.Value)(gasPrice),
			gasLimits,
			codes)

	}

	err = transferTx.Sign(key.PrivateKey)

	key = nil

	if err != nil {
		return "", err
	}

	data, err := transferTx.Encode()

	if err != nil {
		return "", err
	}

	return "0x" + hex.EncodeToString(data), nil
}

func (server *APIServer) createNEOWallet(wallet *rpc.Wallet) error {

	keystore, err := neokeystore.NewKey()

	if err != nil {
		return err
	}

	mnemonic, err := getMnemonic(wallet.Lang, keystore.ToBytes())

	if err != nil {
		return err
	}

	keystoreJSON, err := neokeystore.WriteScryptKeyStore(keystore, wallet.Password)

	if err != nil {
		return err
	}

	wallet.Mnemonic = mnemonic
	wallet.Address = keystore.Address
	wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())
	wallet.JSON = string(keystoreJSON)

	_, err = server.db.InsertOne(wallet)

	return err
}

func (server *APIServer) createETHWallet(wallet *rpc.Wallet) error {

	keystore, err := ethkeystore.NewKey()

	if err != nil {
		return err
	}

	mnemonic, err := getMnemonic(wallet.Lang, keystore.ToBytes())

	if err != nil {
		return err
	}

	keystoreJSON, err := ethkeystore.WriteScryptKeyStore(keystore, wallet.Password)

	if err != nil {
		return err
	}

	wallet.Mnemonic = mnemonic
	wallet.Address = keystore.Address
	wallet.PublicKey = hex.EncodeToString(keystore.PrivateKey.PublicKey.X.Bytes())
	wallet.JSON = string(keystoreJSON)

	_, err = server.db.InsertOne(wallet)

	return err
}

func getMnemonic(lang string, privateKeyBytes []byte) (string, error) {

	dic, _ := bip39.GetDict(lang)

	println(hex.EncodeToString(privateKeyBytes))

	data, err := bip39.NewMnemonic(privateKeyBytes, dic)

	if err != nil {
		return "", err
	}

	return data, nil
}

func readBigint(source string) (*big.Int, error) {
	value := big.NewInt(0)

	if source == "0x0" {
		return value, nil
	}

	source = strings.TrimPrefix(source, "0x")

	if len(source)%2 != 0 {
		source = "0" + source
	}

	data, err := hex.DecodeString(source)

	if err != nil {
		return nil, err
	}

	return value.SetBytes(data), nil
}

// DecodeAddress decode address
func DecodeAddress(address string) (string, error) {
	bytesOfAddress, err := neotx.DecodeAddress(address)

	if err != nil {
		return "", err
	}

	bytesOfAddress = reverseBytes(bytesOfAddress)

	return hex.EncodeToString(bytesOfAddress), nil
}

// EncodeAddress encode address
func EncodeAddress(address string) (string, error) {

	bytesOfAddress, err := hex.DecodeString(strings.TrimPrefix(address, "0x"))

	if err != nil {
		return "", err
	}

	bytesOfAddress = reverseBytes(bytesOfAddress)

	return neotx.EncodeAddress(bytesOfAddress), nil
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}
