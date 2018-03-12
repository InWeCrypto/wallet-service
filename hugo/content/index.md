---
weight: 10
title: API Reference
---



# 钱包接口

## 创建钱包

`POST http://localhost:14019/wallet`


> Body

```json
{
    "name":"",
    "type":"", 
    "password":""
}
```

> 返回值

```json
{
    "name":"",
    "type":"",
    "address":"",
    "mnemonic":"", 
    "privatekey":""
}

```

### 参数说明


Parameter | Type | Description
--------- | ------- | -----------
address| string | 钱包地址
type| string | 钱包类型：eth,neo
mnemonic|string | 助记词
privatekey| string | 私钥


## 导入钱包

`POST http://localhost:14019/wallet/import`


> Body

```json
{
    "name":"",
    "type":"", 
    "mnemonic":"", 
    "privatekey":"",
    "json":""
}
```



### 参数说明


Parameter | Type | Description
--------- | ------- | -----------
name| string | 钱包名称
type| string | 钱包类型：eth,neo
mnemonic|string | 助记词（可选）
privatekey| string | 私钥（可选）
json| string | keystore （可选）

privatekey | json | mnemonic 任选其一


## 获取钱包列表


`GET http://localhost:14019/wallet/`


> 成功应答

```json
{
    "name":"",
    "type":"", 
    "address":"",
    "mnemonic":"", 
    "privatekey":"",
    "json":""
}
```


## 获取指定钱包


`GET http://localhost:14019/wallet/{钱包地址}`


> 成功应答

```json
{
    "name":"",
    "type":"", 
    "address":"",
    "mnemonic":"", 
    "privatekey":"",
    "json":""
}
```

## 获取钱包的助记词


`GET http://localhost:14019/mnemonic/{钱包地址}/{钱包密码}/{语言}`


> 成功应答

```json
{
    "mnemonic":"", 
}
```

## 删除钱包


`DELETE http://localhost:14019/wallet/{钱包地址}`

## eth转账

`POST http://localhost:14019/eth/tx/`


> body

```go
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
```

> 成功响应

tx字符串


## neo转账

`POST http://localhost:14019/neo/tx/`


> body

```go
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
```

> 成功响应

tx字符串

