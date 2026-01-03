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
var Address = "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
var PrivateViewKey = "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

// dump_985_2_1760777348.bin, Output 1, sm: 0.000123;
// var Address = "42LPBD4x3hv2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97BRAyDxq"
// var Address = "4C34C1tSeyS2fy2CeYPhyjUjTYSNnkvg1a2zj2F6YuSsSQCWac6Pp22RAfCG7djHbM3imHtizTwwoZW4TwFEdY97GSKXqfqWkxw13Gk6c9"
// var PrivateViewKey = "98540b36f09f5e5439f98f048e81e32fbbf19f836c962fef1510d3af605f0102"

const hexTx = "0200010200108ccdae44abf61e88fc24c6a004e3e118b2eb109f9d0fc7aa02d2a605b40c118a02810ae701df01f90ad3d9619c14e6a53bbcea1bffcf01a41713f0d07396091ca4b43ea05cbaf11021020003e5af389c04fc6c2929aa1a001d0863a0cf5f9a0fcd693013928bea1095fa60cf8900033632d162e08e0e69a6990561acd402789436599d53f2607ec0b226f2d09ccb48392c016e23d17014c3ce7548bb56f30ec52e006d91a4417bc619db072fca0ba159fead0209018793b7f5ba2da4b306e0f2cc0e8a30307fed45e7ae0990f2afc6044318e4ad9e99b294eb01f121455a75fb166f80dc083500881c5b7a6ec825c40a362964afc28a478c35186b43433d9bfb916d2343f0668a54c5ad72a3ba1e7cb8b2da01b2371672443bcf5a875360ed27704a38c7cab9fad720676c9de1277f21300bcc714c8c1c66d426f03c5a60aa1631388c73ebd623694661570a3c80be629deb6718c782f8498e3cc8223a069ef9e0e74a04bfabe7409e41c701700463b26ceed2238093c3ce3520c5779b88d06e18ffc86f59349cc4d5355ce2667b23135a84016707aa3ef70c2b6525afb03fd761b804cfaa96910c57eee5ef829ae71b025d0c82827f59d6605f062cedff28c4013471a6f1b2cf178242a4f3c57fb6243a1e0c07fa8d9d8edbfd4f5bf6bc5ac319041bb5b8f2cd873780ca521979c7323abe398672540fe46d812e1d9c7e72a31b13a1cad95b51244440841cde74a979e3d86401f4dfebf33cf12ed68e4d77d3bf0ff75a8c66a8a93c59c8a41dd751346eecccf2ffb22188042a017fbb5db0ee89fc5a73ae323786dd04a902633709f8b61c432feacaa1262e1c0292da8328d95fa5baac1fed8d5b1f0fada121976432570f67ae1f9d946bd16e89ddc3eb4af880f6e0135b6f03d0e3b34978b03fbaf6f39e00e43e9848245d156e4a20ac81204647a17a4223d00ff8a764dcda385dca63672ae20799b6991c246af31a55f9c92a32a5f54dbfbe23e11037d70c50a768940a12bef26886516251d4829cf96c69076e208a05c495b199488cfc930cd5d11467eaeb7a2982b7f5a5f5164d978ae43f44a4143ed4c162d2852edf7bb440bfba46b089c2504fdd541973b82d4fd5cea5dfad303d2f813339140f0e89ef82e5c70f1080854f0f17109c516b8a1cf159bbee277e51192d400991ba57efbbf855d335c7521a780eab84449e253f453d3ff7af16a9fd45ffb3fccb486feb43c4230f8fb942a878411005dabb26e3e795e267c48c72d4237416b834df55c6f3b572b5f8f5aaaef7e2817215a26af0026456ad6dbd46493b85b851973f4b4d5fbcc6daa453630e4a59b1e9aa43d1c86f50d210e6e89e2604c5e2b74ff53e6755c4502fe27791040fcf14a343c635d31d1769a75520181f85771396be1f47f9346942e9a1386f076d916c6e50b321ea5f7953dbb576d463792a58a614f30df33e60fd8294253305720ed3ab9ba4ebc1e5cee8e7257656ab6864465645c63b786750abac2a389c0ea203b4a1df495f1eac970a3d875c4d5e698d018b25dd45f44c70cac414ab190dfa8487a9c8d46666b635232cd28446bf1e223603fc2ec6d1c80b09cfd615a501b2c2f3d441cbcb3ab0cfb18e3afeaed606109b3e992578074d6e32e48ee78801df541c6ba9fa67b8148b8c95ec44f80801ae067d7e1a7e200ab2bf198961b30407350d0fad53238e42500eb069d548073b7dbef77f8865d7500cdd3998ec3b07933281a1d6e5a41e31a46f6a529eaabf193454107d60ff6a74ff291f1ec615002928c819c808ada4bfe21f57eeef544dd9431195266ac14c98a0092954d01b0d6ba07c64cc99bac6abe5e918b32a279df148fed9b45b027687c778e7588ab40ac21a878526ad041aed4a1cce822e72223176bd937d79d6efbc010f2fb0fa57012c632f248771735d4039d75c8b5801fff6c2f8c277d846b0d9dff26f3b8b9802f803d625620b8195f1cc41d4da14db088cdb38e3af9cd7ec421ca0815c419b045134ef8e238ca65e8b4223e05f05acee6fd35d8fe869fef247795514989214059e83cb18033e415b02e93b5e698e9a35963852e08740767631d611e6dcc424bca06145bac6fee44bcc0f75dc27760325ec458e8b02348b993eb2f0a9f9a2b812"

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
	{
		tx2.WriteInput(levin.TxPrm{
			"txId":            "5a0247682c4170b643150434198a04d73270b98dd4c112c852ee01efaec30c19",
			"vout":            0,
			"address":         "49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
			"privateSpendKey": "e6cb7ec0abf080455ad4b18f68347bf8cd073edb77901319da96d19729064c01",
			"privateViewKey":  "4fd69daf111e62ad6d64bfa3a529751db91eb35ef547e00d58ca1a99aee98209",
			"extra":           "01813441a96044757f93f49d3c8a3631e2da1846857de2184b71e4fe4ec9352dce02090171d6b03c269a91ab",
			"amount":          0.003818238111,
		})
		tx2.WriteOutput(levin.TxPrm{
			"amount":         0.003787617111,
			"change_address": true,
			"address":        "49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
		})
		tx2.WriteOutput(levin.TxPrm{
			"amount":         0.000000001000,
			"change_address": false,
			"address":        "46qSj35nZczKMC8FPcCmEPUFJ46egvp1o86CG6QQXbB18HtSwSVWHHzSiE1QY2MCfNKWKQFYre28QhGn9vbe75B1T5Wn3D6",
		})
	}

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
		if err := tx2.SignTransaction(); err != nil {
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

	for i := range tx1.Outputs {
		noty.NotifyWithLevel(fmt.Sprintf("Tx1_KeyImage: %x", tx1.Outputs[i].Target), LevelInfo)
		noty.NotifyWithLevel(fmt.Sprintf("Tx2_KeyImage: %x", tx2.Outputs[i].Target), LevelInfo)
	}

	noty.NotifyWithLevel(fmt.Sprintf("TxRaw1: %x", tx1.Serialize()), LevelSuccess)
	noty.NotifyWithLevel(fmt.Sprintf("TxRaw2: %x", tx2.Serialize()), LevelSuccess)

	// noty.NotifyWithLevel("Tx1_pseudo_out: 1f619a00e56d97b29b0ee244cbc65c20a1a9c9c6e5d505644b255a346ec5394f", LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_pseudo_out: %x", tx2.RctSigPrunable.PseudoOuts[0]), LevelInfo)

	// noty.NotifyWithLevel(fmt.Sprintf("Tx1_A: %x", tx.RctSigPrunable.Bpp[0].A), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_A: %x", tx2.RctSigPrunable.Bpp[0].A), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx1_A1: %x", tx.RctSigPrunable.Bpp[0].A1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_A1: %x", tx2.RctSigPrunable.Bpp[0].A1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx1_B: %x", tx.RctSigPrunable.Bpp[0].B), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_B: %x", tx2.RctSigPrunable.Bpp[0].B), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx1_R1: %x", tx.RctSigPrunable.Bpp[0].R1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_R1: %x", tx2.RctSigPrunable.Bpp[0].R1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx1_S1: %x", tx.RctSigPrunable.Bpp[0].S1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_S1: %x", tx2.RctSigPrunable.Bpp[0].S1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx1_D1: %x", tx.RctSigPrunable.Bpp[0].D1), LevelInfo)
	// noty.NotifyWithLevel(fmt.Sprintf("Tx2_D1: %x", tx2.RctSigPrunable.Bpp[0].D1), LevelInfo)

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
