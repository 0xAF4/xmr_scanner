package main

import (
	"encoding/json"
	"fmt"
	"os"
	"xmr_scanner/levin"
)

var noty = NotifierMock{}

var Address = "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
var PrivateViewKey = "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

var WrongAddress = "49PkZX7wmMiRpMu1PaVJgLF7h8zCMQrNJ8Rz7W1u5Sc4RU5vphEWwEST8zKWazTxAgPXQAMUryGc6UsQCq3BQ5ChGHMR5sv"
var WrongPrivateViewKey = "3b3cc475da85f718e07a4a1fb33bf16a47ef1a3df2a6d65fcc00a104ed277e0e"

func main() {
	blockHash, err := os.ReadFile("C:\\Users\\Karim\\Desktop\\dump_985.bin")
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
		if err := block.FullfillBlockHeader(); err != nil {
			noty.NotifyWithLevel(fmt.Sprintf("Error processing block header %d: %v", i, err), LevelError)
			continue
		}

		// noty.NotifyWithLevel(fmt.Sprintf("Block %d processed successfully", i), LevelSuccess)
		// data1, _ := json.MarshalIndent(block, "", "  ")
		// noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
		// noty.NotifyWithLevel("=========", LevelSuccess)

		for _, tx := range block.TXs {
			if fmt.Sprintf("%x", tx.Hash) != "8b891c0352014ea6687a0b51b8128ec238b26c9bd523aa1554def1078d822222" {
				continue
			}
			tx.ParseTx()
			tx.ParseRctSig()
			noty.NotifyWithLevel(fmt.Sprintf("  ------- TX Hash: %X", tx.Hash), LevelSuccess)
			data2, _ := json.MarshalIndent(tx, "", "  ")
			noty.NotifyWithLevel("\n"+string(data2), LevelSuccess)

			noty.NotifyWithLevel(fmt.Sprintf("%X", tx.RctRaw), LevelSuccess)
			funds, err := tx.CheckOutputs(Address, PrivateViewKey)
			if err != nil {
				noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs error: %s", err), LevelError)
			} else {
				noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs find in tx: %d", funds), LevelWarning)
			}

			// noty.NotifyWithLevel(fmt.Sprintf("%X", tx.RctRaw), LevelSuccess)
			// funds, err = tx.CheckOutputs(WrongAddress, WrongPrivateViewKey)
			// if err != nil {
			// 	noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs error: %s", err), LevelError)
			// } else {
			// 	noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs find in tx"), LevelWarning)
			// }
			_ = funds
		}

		os.Exit(11)
	}
}
