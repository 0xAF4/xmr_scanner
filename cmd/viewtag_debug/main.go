package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

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
	pubSpend := mustHex("cb7daf66af88f390889517765b175416ebbe384baa92945eb250aff05f30d489")
	txPub := mustHex("b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff")
	privView := mustHex("b605672b04d08b273efddf76a6d5acb106766fdf6e6e5f62bd5b4e6a71daa366")

	if len(os.Args) > 1 && os.Args[1] == "realpriv" {
		// placeholder to pass a real priv from env if needed
	}

	for i := uint64(0); i < 2; i++ {
		fmt.Printf("Index %d:\n", i)
		viewTag := levin.ComputeViewTagForDebug(txPub, privView, i)
		fmt.Printf(" computeViewTag (orig): %02x\n", viewTag)

		// derive key + view tag from DerivePublicKeyWithViewTag
		_, vt, err := levin.DerivePublicKeyWithViewTag(txPub, privView, pubSpend, i)
		if err != nil {
			fmt.Printf(" DerivePublicKeyWithViewTag error: %v\n", err)
		} else {
			fmt.Printf(" DerivePublicKeyWithViewTag view tag: %02x\n", vt)
		}

		pk, err := levin.DerivePublicKey(txPub, privView, pubSpend, i)
		if err != nil {
			fmt.Printf(" DerivePublicKey error: %v\n", err)
		} else {
			fmt.Printf(" derived key: %x\n", pk)
		}

		// Also compute several candidate view-tag schemes
		shared, err := levin.SharedSecret(txPub, privView)
		if err != nil {
			fmt.Printf(" SharedSecret err: %v\n", err)
		} else {
			fmt.Printf(" keccak(shared)       : %02x\n", levin.KeccakByte(shared))

			// "view_tag" + shared
			v := levin.KeccakByte(append([]byte("view_tag"), shared...))
			fmt.Printf(" keccak("+"view_tag"+") : %02x\n", v)

			// shared || 8-byte LE index
			idx := make([]byte, 8)
			for j := 0; j < 8; j++ {
				idx[j] = byte((i >> (8 * j)) & 0xff)
			}
			fmt.Printf(" keccak(shared||idxLE8) : %02x\n", levin.KeccakByte(append(shared, idx...)))

			// shared || single byte index
			fmt.Printf(" keccak(shared||idx1)   : %02x\n", levin.KeccakByte(append(shared, byte(i))))

			// shared || varint(index)
			fmt.Printf(" keccak(shared||varint) : %02x\n", levin.KeccakByte(append(shared, levin.EncodeVarint(i)...)))
		}
		fmt.Println()
	}
}
