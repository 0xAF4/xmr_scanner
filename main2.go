package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"xmr_scanner/levin"
)

var noty = NotifierMock{}

// dump_985 - tx hash 8b891c0352014ea6687a0b51b8128ec238b26c9bd523aa1554def1078d822222
// dump_985_2_1760777348.bin - tx hash 884e56fb693eb5ea008097ebbba5467470827e0771fb652f979aa8a405c2c2e8; tx private key = cf07e4a76b141e7d38cbe1c744bd4c11cac9bb200bfc2216801ef1f44196d600

// dump_985, Output 0, sm: 0.033592475285; dump_985_2_1760777348.bin, Output 0, sm: 0.033438715285
var Address = "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
var PrivateViewKey = "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

// dump_985_2_1760777348.bin, Output 1, sm: 0.000123;
// var Address = "42LPBD4x3hv2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97BRAyDxq"
// var Address = "4C34C1tSeyS2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97GSKXqfqWkxw13Gk6c9"
// var PrivateViewKey = "98540b36f09f5e5439f98f048e81e32fbbf19f836c962fef1510d3af605f0102"

func main() {
	// blockHash, err := os.ReadFile("dump_985.bin")
	blockHash, err := os.ReadFile("dump_985_2_1760777348.bin")
	// blockHash, err := os.ReadFile("dump_985_3.bin")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	storage, err := levin.NewPortableStorageFromBytes(blockHash)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(2)
	}

	var blocksArr []*levin.Block

	for _, entry := range storage.Entries {
		if entry.Name == "blocks" {
			for _, blk := range entry.Entries() {
				block := levin.NewBlock()
				for _, ibl := range blk.Entries() {
					if ibl.Name == "block" {
						block.SetBlockData([]byte(ibl.String()))
					} else {
						for _, itx := range ibl.Entries() {
							block.InsertTx([]byte(itx.String()))
						}
					}
				}
				blocksArr = append(blocksArr, block)
			}
		}
	}

	for i, block := range blocksArr {
		if i != 0 {
			continue
		}

		if err := block.FullfillBlockHeader(); err != nil {
			noty.NotifyWithLevel(fmt.Sprintf("Error processing block header %d: %v", i, err), LevelError)
			continue
		}
		// noty.NotifyWithLevel(fmt.Sprintf("Block %d processed successfully", i), LevelSuccess)
		// data1, _ := json.MarshalIndent(block, "", "  ")
		// noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
		// noty.NotifyWithLevel("=========", LevelSuccess)

		for _, tx := range block.TXs {
			if !slices.Contains([]string{"	", "884e56fb693eb5ea008097ebbba5467470827e0771fb652f979aa8a405c2c2e8"}, fmt.Sprintf("%x", tx.Hash)) {
				continue
			}
			tx.ParseTx()
			tx.ParseRctSig()
			noty.NotifyWithLevel(fmt.Sprintf("  ------- TX Hash: %X", tx.Hash), LevelSuccess)
			data2, _ := json.MarshalIndent(tx, "", "  ")
			noty.NotifyWithLevel("\n"+string(data2), LevelSuccess)

			noty.NotifyWithLevel(fmt.Sprintf("%X", tx.RctRaw), LevelSuccess)
			funds, paymentID, err := tx.CheckOutputs(Address, PrivateViewKey)
			if err != nil {
				noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs error: %s", err), LevelError)
			} else {
				noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs find in tx: %.12f; PaymentID: %d", funds, paymentID), LevelWarning)

			}
		}

	}
}
