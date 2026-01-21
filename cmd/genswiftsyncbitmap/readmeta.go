//go:build ignore

package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cockroachdb/pebble"
)

func main() {
	db, err := pebble.Open("/home/calvin/.btcd/data/signet/optoindex", &pebble.Options{ReadOnly: true})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Read metadata
	keys := []string{"last_height", "next_bit_index", "bitmap_last_height"}
	for _, key := range keys {
		fullKey := append([]byte{'m'}, key...)
		val, closer, err := db.Get(fullKey)
		if err != nil {
			fmt.Printf("%s: not found\n", key)
			continue
		}
		if len(val) == 8 {
			fmt.Printf("%s: %d\n", key, binary.LittleEndian.Uint64(val))
		}
		closer.Close()
	}
}
