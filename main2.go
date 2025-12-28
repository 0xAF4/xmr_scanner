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

const hexTx = "020001020010b9fac744edd448b4a20aa2f60bd3cf01ce80059fa208ce11a206b82ce501f9059f61ae1ac6180cd1e407df543b3d6c8b9421c4600d60fcbfb879f40fa5dbfa8354390e01e07b920200034b6203875e1211e63454269c57f82ba337ab1a9932870846989ebec1706adc4a7500037568d36e10639d7147a7c70878c135ef76de1539f6a9a50772cf70f088dad5b6ce2c01813441a96044757f93f49d3c8a3631e2da1846857de2184b71e4fe4ec9352dce02090171d6b03c269a91ab0680e8bae90197e236adb7497aa8eb42df53507ef6820411f006a9598b79e33867620d91b11c128c15d9f08ca72d1ed70c78ac3512ff551e5cf8fd53819affefc8dc396c2fa7b7459cb6261f0477479a952f0a965a17015a9ba4b5c613eb264bfc60a16aa546aa46726b84c4b2b6db1a0b3bd8b2bd0f9eb75c5ead27cd1ff1327951bad5a5be9753f93401718eb215aec1336b4d98663e8fb9205fdc16bde401a26ab1bba631a12bc1e486e3dd7ebf8a1bdb468f67102b4de293f4b8a3ae3d6cd37c2f2e30279a0ee7f6fc19f93a55d048fcde946bb60010c9ab94e8d3dc1e2df67af9774b6fc93de5894e334910b964f537f5059148076e79e14dc21f97716d57567754f3083b6f78afc58b9d55b9b0bf1835480a710107bd6c99de9392e28c49e501cffff377698175b8900565ac15e92f770a320386b3f65a4a6146dcf8b3e7aa436a79dc309ac327c3231f37ecdabf1042d7f6f7ae07fd83f5d689fde7e97caeae0c2ae52a0f8f1627136e796edec0127374f1cec8970f9d9a52fa6623e22eda8d749059413b2cd3c539714fba500eb4c3101571371575ec50f6d24a99e3794f6bad0890a60de1b1e80d64fa521c392f542bef108185387bda6cf741bcab38c179418b0020a7392c1904db36d400b9981f70c425e7a0adfd11c247884691c3aae2444639ee08cddb94c479fa82ca0fa441e12a1b705c07a2fa349fe395db9e793190b692d63ae174554abe6707075f05491ec9d663878c96f6539e5ab5abdf5bfc976489334796b6b6d7a5f25294a6ddf4193f49ea3fb159794553189c8a05a504899b1c8df0e8aae982d758a8dc4436c0fd2b5334c1a353caff392d30042b5a1835ef775684a40a179148083e8f5ca8b8ca089d3b06a7f3b0ec95084b6c609a5ed4e2e09a60f352d3e57a2b5f167d4a106c8d3c462714c68089801908c1a68762390deddef2e89493b5319dfcace0fa3e81f3ec3c01a04a54ee6a6f00a10c94f5963b283f01ee238b9f6e681adb8c43a84a76a4d4d9fd5756e66576f6b8f916ea318cf4252fcaafc339a9db677e22b1863b11be21440a63a4237337137600e962eb88c43ad0a053a17766e8dccc376d617afd9b3cf80a4a63dada2305423c070f7bb4aced6032ecbbe44aaefbead4c4a201e6dbcda1056ec4233b474c41a4acb64de027ce451f83038b4589eadfd3554456647c874505e7feb2660c54a88e87ed526042c77d30ad2319250bc7905110dea34e957c190da9ef065032a222877059ed7979fd825df6c7ae623f6315e6d42a2768e159330428b2c3b4645fa6dc545081e42992640e562b765a95f296ec97a6685651f8940899bd641eff0a750ca5874ab4111882724d25a53414629351db8d19f2602e960b1c03dc0e137d0c5858142fb461e87fc523c1eeeabfe2324e41b703dc1de986043064fe8cd307976f303486ccff7e2930d6ef06e0ba90d14a5343570aeb0f7c03168eac7a790349d96d94b8cb1d6785b42857e465581f186e4fb52adafaa32206d823e2d2d2f02eaaeeecab3a68253face2820cd60507d08ef9180c5c8846060723ca1abd1041faad733e9abf0f2620181b5e9ad68a553eae9e151e320f81b60332c77c0a7eb748d7610c899734759ef185bd503084fbc306fa3e4d2d3f2eef0dffb1e486db4dd1d7cbcea8b537ed9f522fdf2e0d62c9dd5ccbaa1020406042064476d15e3da5efff09f1e62fe884c12f058aef421ff04802020d1ee5ba72d30e3bf5b6f4c78d9cde633868965becaebc66fc86e9909e33cb8b0290225ad48106c1fd3b4b04a3254c4bea29e718de8e09c5e5f3cdd6b5df2c9187fe268d655842f96ec9ce707a9fa8d982159e455e5eea856d07e57540f922ee80b563a7fc992c"
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

	// funds, paymentID, err := tx.CheckOutputs(
	// 	"49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w",
	// 	"4fd69daf111e62ad6d64bfa3a529751db91eb35ef547e00d58ca1a99aee98209",
	// )
	// if err != nil {
	// 	noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs error: %s", err), LevelError)
	// } else {
	// 	noty.NotifyWithLevel(fmt.Sprintf("  - TX checkOutputs find in tx: %.12f; PaymentID: %d", funds, paymentID), LevelWarning)
	// }

	tx2 := levin.NewEmptyTransaction()

	if err := tx2.WriteInput(levin.InputPrm{
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

	if showParsed2 {
		noty.NotifyWithLevel(fmt.Sprintf("Tx Hash: %x", tx2.Hash), LevelSuccess)
		data1, _ := json.MarshalIndent(tx2, "", "  ")
		noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
		noty.NotifyWithLevel("=========", LevelSuccess)
	}
	noty.NotifyWithLevel(fmt.Sprintf("TxRaw2: %x", tx2.Serialize()), LevelSuccess)

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
