package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"xmr_scanner/levin"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func main() {
	txPubKey := mustHex("b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff")
	privateViewKey := mustHex("7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604")
	pubSpendKey := mustHex("cb7daf66af88f390889517765b175416ebbe384baa92945eb250aff05f30d489")
	index := uint64(1)

	derivedKey, err := levin.DerivePublicKey(txPubKey, privateViewKey, pubSpendKey, index)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Derived public key: %x\n", derivedKey)
	fmt.Println("Expected: f293d8f16ea0dbac4bb71c7c95604d276092dabe0d907609a801cee3692c6e0c")
}
