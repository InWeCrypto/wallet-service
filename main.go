package main

import (
	"flag"
	"path/filepath"

	"github.com/dynamicgo/config"
	"github.com/dynamicgo/slf4go"
	_ "github.com/mattn/go-sqlite3"
)

var logger = slf4go.Get("wallet-service")
var appdir = flag.String("appdir", "./", "wallet app root directory")
var laddr = flag.String("laddr", "localhost:14019", "wallet service listen address")
var sharedkey = flag.String("sharedkey", "./", "shared key for secure communications")

func main() {
	flag.Parse()

	conf, err := config.NewFromFile(filepath.Join(*appdir, "wallet.json"))

	if err != nil {
		logger.ErrorF("load wallet indexer config err , %s", err)
		return
	}

	server, err := NewAPIServer(*appdir, *laddr, conf)

	if err != nil {
		logger.ErrorF("create api server err , %s", err)
		return
	}

	server.Run()
}
