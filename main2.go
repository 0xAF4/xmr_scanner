package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"xmr_scanner/levin"
)

type Fee struct {
	Hash   string
	Amount float64
}

var noty = NotifierMock{}

// dump_985 - tx hash 8b891c0352014ea6687a0b51b8128ec238b26c9bd523aa1554def1078d822222
// dump_985_2_1760777348.bin - tx hash 884e56fb693eb5ea008097ebbba5467470827e0771fb652f979aa8a405c2c2e8; tx private key = cf07e4a76b141e7d38cbe1c744bd4c11cac9bb200bfc2216801ef1f44196d600
// dump_985, Output 0, sm: 0.033592475285; dump_985_2_1760777348.bin, Output 0, sm: 0.033438715285
// dump_985_2_1760777348.bin, Output 1, sm: 0.000123;
// var Address = "42LPBD4x3hv2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97BRAyDxq"
// var Address = "4C34C1tSeyS2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97GSKXqfqWkxw13Gk6c9"
// var PrivateViewKey = "98540b36f09f5e5439f98f048e81e32fbbf19f836c962fef1510d3af605f0102"
var Address = "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
var PrivateViewKey = "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

var input = levin.TxPrm{
	"txId":            "5a0247682c4170b643150434198a04d73270b98dd4c112c852ee01efaec30c19",
	"vout":            0,
	"address":         "49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
	"privateSpendKey": "e6cb7ec0abf080455ad4b18f68347bf8cd073edb77901319da96d19729064c01",
	"privateViewKey":  "4fd69daf111e62ad6d64bfa3a529751db91eb35ef547e00d58ca1a99aee98209",
	"extra":           "01813441a96044757f93f49d3c8a3631e2da1846857de2184b71e4fe4ec9352dce02090171d6b03c269a91ab",
	"amount":          0.003818238111,
}
var out1 = levin.TxPrm{
	"amount":         0.003787617111,
	"change_address": true,
	"address":        "49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
}
var out2 = levin.TxPrm{
	"amount":         0.000000001000,
	"change_address": false,
	"address":        "46qSj35nZczKMC8FPcCmEPUFJ46egvp1o86CG6QQXbB18HtSwSVWHHzSiE1QY2MCfNKWKQFYre28QhGn9vbe75B1T5Wn3D6",
}

const hexTx = "0200010200108ccdae44abf61e88fc24c6a004e3e118b2eb109f9d0fc7aa02d2a605b40c118a02810ae701df01f90ad3d9619c14e6a53bbcea1bffcf01a41713f0d07396091ca4b43ea05cbaf11021020003acaae9de7e21e7c3d1bb93bb0e2e05a8c7ab89e1fabc34ac0e64a2029f9b623fd4000304433e5edc78ea87e0e2827511051781faa930ca8b2e3056ff06f3c64d147700022c016e23d17014c3ce7548bb56f30ec52e006d91a4417bc619db072fca0ba159fead0209018793b7f5ba2da4b306e0f2cc0e00d01f6f33fc752ff37f8184515d958cbefbf051b7007d4c3fced2ac501a44dd7844ab615ce723e4cee06dcff442193c4066e30b5631a74b19540b62e256a4fe6be6bc1d1f6dd8c532c7a5a5bc40b838012e9eb613da202f23bf85a9bbf6143e344e4f7feff4a865538f96ddb769b1def08c04fcab62ccbdf71298bf1f67146894cefd4dfdeceff9404b3e46afd20b31c7ad9b3a059eb510febdfa778d47b05b34668f3e443c7480e2cfb5de92473db0f8141d508b0a25146bac81dd3df13c53ae5bb6aee7590a98410ca45e094db49e0a438ab34da367d21f8927ee772be95e691c6561529accd0be0a3f099ed873b00acda44dab99fa652c6005ba40077b326c60868a19da2f364d31af13948029fb0f073eb8c3c531082fb113ec7ddbf87a1bd1465f734fe7939858df410ffdf7cda37d4d3026ff9b98ff7e27269bc5dceb90bbfa2c102cc6efac545cf9b73e70a36bb386b1cbb19d3013c144498c36372444c9f4182e4d390e347a5d1b79c83043a6d12dfe0088c90cb829d0395f7bd48d6f6db2fdf7a9ed54c3bb883b3a6b6c5810677d65e713d386646caed30735c453f370cbc773e60a3d550a0b4f53bfaadb87a4dee92099beaecbbc5a568d28fc36173d8783fc3c65551b2deca3a1eb251b972021b909e3bcb73c4bbd76ce57b56255bc3d5ba660c05098cce2b5d4c951fde37107f2f541b4813a5dd4b61a04bb46e2244742943cec7e361b66b1d1811bbd1da3ad116c605a5b8fd1ce5f635bda0ec709c3f08f3a20c01c11ded279c3350d13fa10688b2728eae4c1ad66aab0451ef019dedf37fad86cff1730cc7315ae8e8cb73df313cc674e18fc2a2d1c4657376c16bd15fc448245a062dafc97cfab12e5b13225581c10691b9585b7f64052db3b6354a3d9a245729c1f23baa265ebf7ce29c31a48a50730586d887efdacc79079bfb020847fdcd1395a49fad8fbb895bf69a5d2516221550315d2587c247e19b65efbeca5e55beadeb7de5ec939ccd09827c8010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000d8ae3ec8f4c53c29b7604a2916d32d6c31c42f80ae8f10b1c66d1d006894730bef00fc5ffafcd34101eb757da7984dd9735ae41756e06eedc6c6b91012af810bdf76cd51ae1fe6ab0809d296a8783aa9ea6dcc5dc2e556b28504d5850f10453a08076718e57cabf2b85f676ff1bd9dc12bfc01b08e6fa7bba4d640081390acc6"

var showParsed1 = true
var showParsed2 = true

const currentBlockHeight = 3570154

func main() {
	/*--- TX1 ---*/
	tx1 := levin.Transaction{}
	{
		buff, _ := hex.DecodeString(hexTx)
		tx1.Raw = buff
		tx1.ParseTx()
		tx1.ParseRctSig()
		tx1.CalcHash()
	}

	/*--- TX2 ---*/
	tx2 := levin.NewEmptyTransaction()
	tx2.WriteInput(input)
	tx2.WriteOutput(out2)
	tx2.WriteOutput(out1)

	if err := tx2.CalcExtra(); err != nil {
		panic(err)
	}

	if err := tx2.CalcInputs(); err != nil {
		panic(err)
	}

	if err := tx2.CalcOutputs(); err != nil {
		panic(err)
	}

	{
		tx2.RctSignature.TxnFee = tx1.RctSignature.TxnFee
		if err := tx2.SignTransaction(tx1); err != nil {
			fmt.Println("Error:", err)
			os.Exit(5)
		}
	}

	{
		var tx *levin.Transaction
	again:
		if tx != nil {
			noty.NotifyWithLevel(fmt.Sprintf("Tx Hash: %x", tx.Hash), LevelSuccess)
			data1, _ := json.MarshalIndent(tx, "", "  ")
			noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
			noty.NotifyWithLevel("=========", LevelSuccess)
		}

		if showParsed1 {
			showParsed1 = false
			tx = &tx1
			goto again
		}

		if showParsed2 {
			showParsed2 = false
			tx = tx2
			goto again
		}
	}

	noty.NotifyWithLevel(fmt.Sprintf("TxRaw1: %x", tx1.Serialize()), LevelSuccess)
	noty.NotifyWithLevel(fmt.Sprintf("TxRaw2: %x", tx2.Serialize()), LevelSuccess)

	// keyImage, pubKeys, sig := moneroutil.CreateSignature()
	// fmt.Printf("KeyImage: %s\n", keyImage)
	// fmt.Printf("PubKeys:\n")
	// for i, pk := range pubKeys {
	// 	fmt.Printf("  [%d]: %s\n", i, pk)
	// }
	// fmt.Printf("Signature: %s\n", sig)

	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//

	os.Exit(1)
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

	// fees := []Fee{}
	// for _, block := range blocksArr {
	// 	block.FullfillBlockHeader()
	// 	for _, tx := range block.TXs {
	// 		tx.ParseTx()
	// 		tx.ParseRctSig()
	// 		fees = append(fees, Fee{
	// 			Hash:   fmt.Sprintf("%X", tx.Hash),
	// 			Amount: float64(tx.RctSignature.TxnFee) * 0.000000000001,
	// 		})
	// 	}
	// }

	// for _, fee := range fees {
	// 	noty.NotifyWithLevel(fmt.Sprintf("TxHash: %s; Fee: %0.8f", fee.Hash, fee.Amount), LevelSuccess)
	// }

	// amounts := make([]float64, len(fees))
	// for i, f := range fees {
	// 	amounts[i] = f.Amount
	// }
	// if len(amounts) == 0 {
	// 	noty.NotifyWithLevel("No fees to analyze", LevelWarning)
	// 	os.Exit(998)
	// }

	// slices.Sort(amounts)
	// min := amounts[0]
	// max := amounts[len(amounts)-1]

	// var median float64
	// n := len(amounts)
	// if n%2 == 1 {
	// 	median = amounts[n/2]
	// } else {
	// 	median = (amounts[n/2-1] + amounts[n/2]) / 2
	// }
	// noty.NotifyWithLevel(fmt.Sprintf("Min: %0.12f; Max: %0.12f; Median: %0.12f", min, max, median), LevelSuccess)

	// os.Exit(999)

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
			fmt.Printf("Expected: %x\n", tx.Hash)
			tx.ParseTx()
			tx.ParseRctSig()
			tx.CalcHash()
			fmt.Printf("Got: %x\n", tx.Hash)
			os.Exit(991)
			if !slices.Contains([]string{"8b891c0352014ea6687a0b51b8128ec238b26c9bd523aa1554def1078d822222", "884e56fb693eb5ea008097ebbba5467470827e0771fb652f979aa8a405c2c2e8"}, fmt.Sprintf("%x", tx.Hash)) {
				continue
			}
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
