//go:build ignore

package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/database"
	_ "github.com/btcsuite/btcd/database/ffldb"
)

func main() {
	dbPath := filepath.Join("/home/calvin/.btcd/data/signet", "blocks_ffldb")
	db, err := database.Open("ffldb", dbPath, chaincfg.SigNetParams.Net)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	chain, err := blockchain.New(&blockchain.Config{
		DB:               db,
		ChainParams:      &chaincfg.SigNetParams,
		TimeSource:       blockchain.NewMedianTime(),
		UtxoCacheMaxSize: 10 * 1024 * 1024,
	})
	if err != nil {
		log.Fatal(err)
	}

	hash, err := chain.BlockHashByHeight(285205)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Block hash at height 285205: %s\n", hash)
}
