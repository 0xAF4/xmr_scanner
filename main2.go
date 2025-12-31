package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
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
var Address = "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
var PrivateViewKey = "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

// dump_985_2_1760777348.bin, Output 1, sm: 0.000123;
// var Address = "42LPBD4x3hv2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97BRAyDxq"
// var Address = "4C34C1tSeyS2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97GSKXqfqWkxw13Gk6c9"
// var PrivateViewKey = "98540b36f09f5e5439f98f048e81e32fbbf19f836c962fef1510d3af605f0102"

func hexTo32(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("hex length != 32")
	}
	return b, nil
}

const hexTx = "0200010200108ccdae44abf61e88fc24c6a004e3e118b2eb109f9d0fc7aa02d2a605b40c118a02810ae701df01f90ad3d9619c14e6a53bbcea1bffcf01a41713f0d07396091ca4b43ea05cbaf1102102000383e1d6aa40fa6bfadbab2089e964252197911795f3e680a579037648311ecec978000342d35b239688e846600a29734f6c6ba353acf61c63637ff375de96d1dd726243cd2c01772299cb00fae663173f9aeab9273da82f2500976e6556e16da22bf6ceed1d83020901ed35334b56f0debc06e0f2cc0e16ceedb61624be3e63c748004c87dee058eedb1a1fb752fadd91f9caeb36f99dedcf597161e9d2ee764d6cde04687a9baf0ae7e726da700f4892a79524557fa55a5de70f28a47e9149f83b2eec6dd28f010ae6560caab8fba08474cc1bddb938c29ccc1bf636a1c99fadf5e3612257d90f5ee7426d0c07e7a1b61ade0bac7fb5234151c72a04d61343fe6cfa0a2abe996eed1715927793c44817b844b91b9c09064988c15cbd29d969158f14d09682fb91deb3b8129d18fd849fd28883505177bdd9d550a8f6202fe7026f75217948ad0b9e234dbaa5f47f9697c11841d9955c1075d2caa579c368a8b7cf716cb6bc9b0e222046d7b5b3602d99e583951249d519f8007582b7f85d37b7a329542ba901020752df337b1ae5c779ce63f0dfa5f0fa921361b41165a0571b7a5c18fa18b638f665acdf528a6f895ff4fde7bf2ff28fd00f1c5c5a6c8bc43a7be13c0bb37cc9d03fcc7b7f27e51cd036c6d7ef9aa557691f67931c02a89ea2a7b5f86684be39bcb6c2a5d1232302f596f2084b78e22c1f5b3b0ca1d3dc51f6826a2b94f27872569ab0b48d64ab441327fc4eb88d5a9b96e498730d29ad7a463c7af7deb4e55a447ff79cf1a418aaec91e8172e8161a11d39f9eddac0c69a0b6b45607cd254c18cd85cd92b5d6f14ffe6ec061b62cb62a9d6b5b686b00356bbdcdc3930aac053320710e6d27d12911a2614b2728dc168e18a35aca38fb4ad7ff7b452c25f38a1e7c657ca265f529f89356ae573c7df9674def92026283195fd427d44a5acbe264f4dca1d56329220f27ee3ee4c8a950ff23d7c3f62e44998fa4b3adadd440e745aa2ae0556ecc494b531b0235144e02f88c3a4d58bca31f57802696ac5d495b65265ae067c5e9c03774424062365a6fc0b9b0e3ef187030ee9bf7cc88b5c8c4e67ba0ce6a23ef2b5e5b1220b7bd408c42b1013cd2f6a9ab69004043859352f79fba839867a67b7c708bb3493a19f217d559842ccafc594f60e438d3900ead6f7be3b772c871e2c96e5b05a114f4be29a42a316da581f850863becea7273999611b03b4b0d4100323d51ddda07e5d3132982f9380b73aa11b47f0a84ae546fdf112070bd9b846babaab10cb3f4dd092abd8bdf7e93512e6935c8e5bfa886bdfd6480bf086e294e4614c1914e0126eee0cd5167de92b50fc3c9d618348c5f6802edc0b266ed140e39214a469c74d67ccacd7312170019caa9777ea139c5f21034180042966811eb6dc24a4fe925a1bdbd5d74b4c9d1322272934837a1c6a89597e670ae11bb3d4d672d2cf035db6c4bd6d6bedd79f2bdc0797d6f055e964f081150a02445e76149fcc524582b6592d9c4d982600e28d6890a79c82f551dc9d5a7a6f00c53350b0f3c5355ad26c888d6a832d6d57be6ebc9c126aa08fdab83a65da750a67eb9d1bdac4df209e81d68b0e06495637d2d3cd0bea76e578caebd3fb75ad0523d7d5cdac040c4206f5c19ebdcdff6e1162941b67a22cebb39a13baf9b4b707a8826b9adb5a3fdeb9d7ffe6cc765f8a3e51deb24e0747739e6e511828dea7035b35ac59d8087b3f450d575f51ad7f832aa88b68042cdc6d5fb942c554f4d6010c67b7f728b69e54d81f2cf085b4906e81ee8a4b641d775ebc87e7286cae650474fe0727a390bb108fe6f2aefb0bd5a165e12e815d356067376c88bde7d6fd011930fcf3477e90a519f1dbf5245bf9889ae5832741500e36153801591785ca06be4ec62d9f00f6359c43db27e4910a8090d22f1e0caf58d2279079803a8d100a538506fad368aa9031017ad692c1d3db8b0a11fd01151751d4125a31a0290c241f619a00e56d97b29b0ee244cbc65c20a1a9c9c6e5d505644b255a346ec5394f"
const showParsed = false
const showParsed2 = false
const currentBlockHeight = 3570154

func main() {
	buff, _ := hex.DecodeString(hexTx)
	tx := levin.Transaction{Raw: buff}
	tx.ParseTx()
	tx.ParseRctSig()
	tx.CalcHash()
	noty.NotifyWithLevel(fmt.Sprintf("TxRaw1: %x", tx.Serialize()), LevelSuccess)
	if showParsed {
		noty.NotifyWithLevel(fmt.Sprintf("Tx Hash: %x", tx.Hash), LevelSuccess)
		data1, _ := json.MarshalIndent(tx, "", "  ")
		noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
		noty.NotifyWithLevel("=========", LevelSuccess)
	}

	tx2 := levin.NewEmptyTransaction()

	if err := tx2.WriteInput(levin.TxPrm{
		"txId":            "5a0247682c4170b643150434198a04d73270b98dd4c112c852ee01efaec30c19",
		"vout":            0,
		"address":         "49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
		"privateSpendKey": "e6cb7ec0abf080455ad4b18f68347bf8cd073edb77901319da96d19729064c01",
		"privateViewKey":  "4fd69daf111e62ad6d64bfa3a529751db91eb35ef547e00d58ca1a99aee98209",
		"extra":           "01813441a96044757f93f49d3c8a3631e2da1846857de2184b71e4fe4ec9352dce02090171d6b03c269a91ab",
	}); err != nil {
		fmt.Println("Error:", err)
		os.Exit(3)
	}
	// Decoys ✅
	// Inputs ✅
	// Outputs ✅
	// Extra ❌
	// rct_signature ❌
	// rctsig_prunable ❌
	if err := tx2.WriteOutput(levin.TxPrm{
		"amount":         0.000000001000,
		"change_address": false,
		"address":        "85enMysx1tuZVWPRhjU2ibHnaNLwhDrrZMue3viwaFV4HffTn53Vu4F11waowaY5YsJojyWFX7W42811fiPWjPahNsrQqhP",
	}); err != nil {
		fmt.Println("Error:", err)
		os.Exit(4)
	}
	if err := tx2.WriteOutput(levin.TxPrm{
		"amount":         0.003787617111,
		"change_address": true,
		"address":        "49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
	}); err != nil {
		fmt.Println("Error:", err)
		os.Exit(4)
	}

	tx2.RctSignature.TxnFee = tx.RctSignature.TxnFee

	if showParsed2 {
		noty.NotifyWithLevel(fmt.Sprintf("Tx Hash: %x", tx2.Hash), LevelSuccess)
		data1, _ := json.MarshalIndent(tx2, "", "  ")
		noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
		noty.NotifyWithLevel("=========", LevelSuccess)
	}
	noty.NotifyWithLevel(fmt.Sprintf("TxRaw2: %x", tx2.Serialize()), LevelSuccess)

	for i, _ := range tx.RctSignature.EcdhInfo {
		var str string
		str = fmt.Sprintf("tx1.RctSignature.EcdhInfo[%d].Amount: %x", i, tx.RctSignature.EcdhInfo[i].Amount)
		fmt.Println(str)
		str = fmt.Sprintf("tx2.RctSignature.EcdhInfo[%d].Amount: %x", i, tx2.RctSignature.EcdhInfo[i].Amount)
		fmt.Println(str)
	}

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
