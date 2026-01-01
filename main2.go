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

// const hexTx = "020002020010a3c7f624d8909e1eb5bdb101e88155d1ab1efab7028f800fa4ca02aefb04a9d302d0ca01c3b804963b9d08a70cc61fa63a06cd49455f42c68acf399e7cccac64cc8c2bec78159e7002216350634d790200109dabc74397e299019b8d4bfaab238f8b059fd703c8ba019e34a47b9315ed0ad10596028f08f30794348046f8da789c7467b99543730254483e7d175cfa9c4f8c3663eed4b8ee17cd6c03000324205ac2444a9569461503bfb1f10a7018b32ef843340437842b8deb5ba163706f000334997e681b7016dc210b28bebef116c69205d4b9df1f06aa4d845a20991333feb00003e4e006f40934e00f14e6bb18940778d66399e82340e986fef3e92348e72bd477468301017739e3acc05d5e3abf11ff82d0b4214139918e87ad74031bdaa7dd55f2e71c550403c0bb5ac24da0bf9281472fbee62d1be75331ea724b1e580048c3dbceecb6d24110d6d53538a8bf410d25496bdbcc6814c3d448186c3246d0c9e99f5fd3894b98fae385a8f6d643a540ab6e9095fa9160dc050e8ed2e46709d2d760fdcaf07e800680b4f0bb03c1feb3165295816e2cdc827cc7674d1c49453244387797d4e913d29d4443562e3e2b48dded951b1acb6b090756253bd3a4a14001beecc5b9f90b2dac242eddcc6c82fb6fadb407f7a0cb0c272f91a6ed18d0514353e4cf9d2836f12267b9e48ba62f5259b220f7f74eb51d3fcce114a6dc0c9b80bb6ed601015acd51f340642e499fe5acfb16263560a106f1dde9c2a7ea47b1d7712ddb78d0001b0041aa019cf5bf92945af8e5a8cb26b012b9707f88676e2b4078975f4ec34d8f680ddd09d19561468279e87d1d724be66220b551c415eb94419e9dc6a2a3356d0c0c86de61b4e796b4af6d6d5ec50653c5cd6d3e1343b72b6e2b87d6e3021e477d28964ce30e595700f02284fab6ac71229011938402bd8b1a45a79fb9041d115646ba78a5b6f76801b960a005f0d2de291273839302927caa52f408d105085a68c5a6c4b110787d1c56f5d7179ff6784f5a58a04e05edf37ca871517f6d46564f1645116f09275ed0461e236ec6841031665a5c8ebd3feea83bff62a64397e13f21ef225b2e51802a8b4d5ad421f7e1e0c0c5c13de959037e007cc08aaa1df451e28ef3d6cd873fccaa95754f94c7ee8510c4c4ab7225e92fc0d357550381661358a450147d5a0d4d8c5a3df9a01305371d60551c5a754afac6a191e42d85ec37dba8d96e181ce646dad568a7c5d81f94d880e077d07067bb503c294eb81c9938220ee159598a878b698eec95ed2b0c81bbd57171aea2a886ff2e1c083c8987dbc58cb5201b500efda378fd5bccc32fa14860ef8dcc34ff3a45e94b2e9b7a08b469c7b35f8c25b200f03547f0bf674cd269b91bbc511c7f1722d3a70417f8f240150847af1c85d035c869ea453bff37393d3a7d91c8997bc8524d06e4075f74bd049ff4a88e829dda84fdf7e1ebd6f5bacb37e312137aa745805f15b69f3599d4ddebc7beee27b70eb1912ecb2385a4c9aca0c358af0969bf28097a64c262e96262c3e58f30378ed1eaeab16bd614944f393cde9c71424e277224f92e4d3bc23d139567d5b122f5a17556aca0e83fe6ddea53ef73e60373a7f0feb24bfb5b0c2bc71a56f8b241a534303c6aa6a3d0abbcc8648b3aba3a07b007f79a31ec09b1e356135b775feb780e85164cfc1d4a2a9977ef9ad1c166b91f802561b39369d28edcf4326393ce031d536d6a7cef9bcc506ceaa8e62860689c208a86f1e066054572b9f3f13683aec816edf769b07f8f712bfd88f7fe456e375be4034eab3807a6b57e9b672252a62540b459e33951007c2e64fd109646a2ca766d8f77be3a016aadbfea43f614de4e07a38aa31b71c6ffa43af2f7493e3c7232ae770a98e90a08f711c4edef17f2407d7cec68386e782db070c880c033774cdbdf1887e759022ec8ada3857b29bd2119a3cc80421e3257536df2c56d53f7677e77b5770776015038057cd79ad08aa7ee717e25ca049ce5ad802ade9ba2c014f98e5f67183c011c0ae74bf0e5790e0f44f3e04956a0741025b2e5d78e14877b3888043758a209d0941793849eb8f0d86e80971d3c7d613f679bfc0845f7bd1695e95c3053590caeeb9c977468bc1ac6cdcbb02e4b460822fbccf0de79029ab6ba8902ceeb5c01d6c7e4ac1d715e92d310533221a84dc9965516bc7d024b3fb9012557598c8406aa552a754075ada6b85a71fef3f8a38ae1c1c79f217330aa415bb5143589420881cdcfd260c4ad499cb6456925b5297ddf10c8ef327ef045c36810620b79ab09488fc2dd3afcbd3e96afb42c182865a81612e8cdcecfc1a0a66fb965a8db3c0467bb2f84e710b3837fb4d207014c069c995495e7f76457540fd25bbf8d4e4307042e985680af87683e74f4a93bbd63033173a641abcaa7c8e1cea8dcbc8e1908ebf0d87fdf7f03284d99b4e8b482d6ad5006a4eee8dfc4198c7734dd28ec7f0b14097b11b66e7297865d4e2c7d590ae7d004ccfa54dd38c1e34a5f676ad7807180b97646a51389bf7d45b5c5a933481f83b3f5d14ed45c96a58dce9772a8220cdb409a38de72cd601ba49cef584fb475fc552e8ff5173aeb254aedd3a36fe704ba2356744d85f8e0da0af1d50fce347eddf911012a5199651bcd507206d3740bae47924525c1e3ae5714866bcbc0c1f996de18a328117db7321ad0fda3a5d80944f8014126dfe65d86f8b7e81e8ff4c917757cc3c427602908c4f780b4a0a60d7ad8ba2cbc6193ca9d515e58381fa16d6a419c9c72d7b43a80ab7faf18263f0b44f98635a932cde69c68ec1b51724df190479acc5b7c0c375325ba4f2732330ac5c4cfb815190244438c44468cca412e2d632b1656f449abdef1fc5854d7100af2587b4d72eb6855a843bda41a0af986947fce50d9d68faccdf3f0103935b50b7d527c73b5be38aed19a83ad96af1346e364770e7a51c1994f681b1e07086a0032b5118c71371e9acbaa0d96f1e345e0a56f7923d97eae0da554054006b9210a7a319bb25ae1990207b8a42d1cf38c508d93c01a5a91993954fbea64816caf024e122ba683ca772b24911de9809b30c63449d65d70e32214ad46e397cab08f0c0251f0410e25a6e66b1549b85241112a1f931c291ffb9ee8041447e4660e4f0b55e96ecfbc4506242348363107edbf1096dd2f6816b8540ad2f745e3244e8b086d68910ef36b7dae24aa6f4333ef4b0e44d1faaecccf1e36a5795c40d3471d060c5ccb3cde210675a84bc7a20892c6ef80da5064d3fc65ff0de148d1f990e907cae672301e656c88a2a8496bd49ea2ba42d5c6c3c6768b77816eb97efee7124898a26490753795579c45760f6593398719741675f46a2c30e99e6639b63710d64cb4e45d8f6e265e8136d08f4f90ac5592ab595e526b26e7729c93e459a1fdfd"
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
		"amount":          0.003818238111,
	}); err != nil {
		fmt.Println("Error:", err)
		os.Exit(3)
	}
	// Decoys ✅
	// Inputs ✅
	// Outputs ✅
	// Extra ✅
	// rct_signature ✅
	// rctsig_prunable ❌
	if err := tx2.WriteOutput(levin.TxPrm{
		"amount":         0.003787617111,
		"change_address": true,
		"address":        "85enMysx1tuZVWPRhjU2ibHnaNLwhDrrZMue3viwaFV4HffTn53Vu4F11waowaY5YsJojyWFX7W42811fiPWjPahNsrQqhP",
		// 49AvioLCdkk5gSXww99nEKJV3tsyBxszEZeywa7K3jQi1qcBhz4AJhPU6sroCaEsqDMJg1iG5Sv1z78u6vsa1fQCRaXGb1w
	}); err != nil {
		fmt.Println("Error:", err)
		os.Exit(4)
	}
	if err := tx2.WriteOutput(levin.TxPrm{
		"amount":         0.000000001000,
		"change_address": false,
		"address":        "85enMysx1tuZVWPRhjU2ibHnaNLwhDrrZMue3viwaFV4HffTn53Vu4F11waowaY5YsJojyWFX7W42811fiPWjPahNsrQqhP",
	}); err != nil {
		fmt.Println("Error:", err)
		os.Exit(4)
	}

	tx2.RctSignature.TxnFee = tx.RctSignature.TxnFee
	tx2.SignTransaction()

	if showParsed2 {
		noty.NotifyWithLevel(fmt.Sprintf("Tx Hash: %x", tx2.Hash), LevelSuccess)
		data1, _ := json.MarshalIndent(tx2, "", "  ")
		noty.NotifyWithLevel("\n"+string(data1), LevelSuccess)
		noty.NotifyWithLevel("=========", LevelSuccess)
	}
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
