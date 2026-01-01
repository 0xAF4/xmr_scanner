package levin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	moneroutil "xmr_scanner/moneroutil"
)

type TxPrm map[string]interface{}

const daemonURL = "https://xmr3.doggett.tech:18089/get_transactions"
const currentBlockHeight = 3570154

var mockOffset = []uint64{
	143369868,
	506667,
	605704,
	69702,
	405731,
	275890,
	249503,
	38215,
	86866,
	1588,
	17,
	266,
	1281,
	231,
	223,
	1401,
}

func NewEmptyTransaction() *Transaction {
	// var err error
	tx := &Transaction{
		Version:    2,
		UnlockTime: 0,
		VinCount:   0,
		VoutCount:  0,
		RctSignature: &RctSignature{
			Type: 6,
		},
		RctSigPrunable: &RctSigPrunable{},
	}
	h, _ := hexTo32("772299cb00fae663173f9aeab9273da82f2500976e6556e16da22bf6ceed1d83")
	tx.PublicKey = Hash(h)
	h, _ = hexTo32("fc1415ced071ae7de346a7ca0dd2b0f9b64cd64423d5ea73b971da135c54de05")
	tx.SecretKey = Hash(h)

	// privKey, pubKey := moneroutil.NewKeyPair()
	// tx.SecretKey = Hash(privKey.ToBytes())
	// tx.PublicKey = Hash(pubKey.ToBytes())
	tx.writePubKeyToExtra()

	// encPID, _ := hex.DecodeString("b0fb56db3f6f2882")
	// privViewKey, _ := hexTo32("4fd69daf111e62ad6d64bfa3a529751db91eb35ef547e00d58ca1a99aee98209")
	// id, pidBytes, err := decryptShortPaymentID(tx.PublicKey[:], privViewKey, encPID)
	// if err != nil {
	// 	log.Fatalf("decryptShortPaymentID error: %v", err)
	// }
	// fmt.Println(pidBytes)
	// fmt.Println(id)
	// os.Exit(1)

	return tx
}

func (t *Transaction) WriteInput(prm TxPrm) error {
	vout := prm["vout"].(int)
	indx, err := getOutputIndex(prm["txId"].(string), vout)
	if err != nil {
		return fmt.Errorf("failed to get output index: %w", err)
	}

	maxIndx, err := getMaxGlobalIndex()
	if err != nil {
		return fmt.Errorf("failed to get max global index: %w", err)
	}

	ring, err := SelectDecoys(rand.New(rand.NewSource(time.Now().UnixNano())), indx, maxIndx)
	if err != nil {
		panic(err)
	}

	keyOffset, err := BuildKeyOffsets(ring)
	if err != nil {
		return fmt.Errorf("failed to build key offsets: %w", err)
	}
	_ = keyOffset

	privViewKeyBytes, err := hexTo32(prm["privateViewKey"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode private view key: %w", err)
	}

	pubSpendKey, _, err := DecodeAddress(prm["address"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	extra, err := hex.DecodeString(prm["extra"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode extra: %w", err)
	}

	txPubKey, _, _, _, err := parseTxExtra(extra)
	if err != nil {
		return fmt.Errorf("failed to extract tx public key: %w", err)
	}

	mPrivViewKey := moneroutil.Key(privViewKeyBytes)
	mPubSpendKey := moneroutil.Key(pubSpendKey)
	mTxPubKey := moneroutil.Key(txPubKey)
	mSecSpendKey, err := moneroutil.ParseKeyFromHex(prm["privateSpendKey"].(string))
	keyImage, err := moneroutil.CreateKeyImage(&mPubSpendKey, &mSecSpendKey, &mPrivViewKey, &mTxPubKey, uint64(vout))
	if err != nil {
		return fmt.Errorf("failed to create key image using moneroutil: %w", err)
	}

	t.VinCount += 1
	t.Inputs = append(t.Inputs, TxInput{
		Amount:     0,
		Type:       0x02,
		KeyOffsets: mockOffset, //keyOffset,
		KeyImage:   keyImage.ToBytes(),
	})
	return nil
}

func (t *Transaction) WriteOutput(prm TxPrm) error {
	// Implementation for writing output goes here
	currentIndex := t.VoutCount

	pubSpendKey, pubViewKey, err := DecodeAddress(prm["address"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	viewTag, err := DeriveViewTag(pubViewKey[:], t.SecretKey[:], currentIndex) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to derive view tag: %w", err)
	}

	derivedKey, err := DerivePublicKey(pubViewKey[:], t.SecretKey[:], pubSpendKey[:], currentIndex)
	if err != nil {
		return fmt.Errorf("failed to derive public key for output %d: %w", currentIndex, err)
	}

	if val, ok := prm["change_address"].(bool); !ok || !val {
		paymentId, err := ExtractPaymentID(prm["address"].(string))
		if err != nil {
			return fmt.Errorf("failed to extract payment ID: %w", err)
		}
		if paymentId == nil {
			paymentId = make([]byte, 8)
		}
		if err := t.writePaymentIdToExtra(paymentId, pubViewKey[:]); err != nil {
			return fmt.Errorf("failed to write payment ID to extra: %w", err)
		}
	}

	amnt, err := EncryptRctAmount(prm["amount"].(float64), pubViewKey[:], t.SecretKey[:], currentIndex)
	if err != nil {
		return fmt.Errorf("failed to encrypt amount: %w", err)
	}

	outPk, err := CalcOutPk(prm["amount"].(float64), pubViewKey[:], pubSpendKey[:], t.SecretKey[:], currentIndex)
	if err != nil {
		return fmt.Errorf("failed to calculate output public key: %w", err)
	}

	t.RctSignature.EcdhInfo = append(t.RctSignature.EcdhInfo, Echd{
		Amount: amnt,
		Mask:   Hash{},
	})

	t.RctSignature.OutPk = append(t.RctSignature.OutPk, outPk)

	t.VoutCount += 1
	t.Outputs = append(t.Outputs, TxOutput{
		Amount:  0,
		Target:  Hash(derivedKey),
		Type:    3,
		ViewTag: HByte(viewTag),
	})
	return nil
}

func (t *Transaction) writePubKeyToExtra() {
	var buf bytes.Buffer

	buf.WriteByte(0x01)
	buf.Write(t.PublicKey[:])

	t.Extra = ByteArray(buf.Bytes())
}

func (t *Transaction) writePaymentIdToExtra(paymentId, pubViewKey []byte) error {
	var buf bytes.Buffer

	buf.WriteByte(0x02) // Payment ID tag
	buf.WriteByte(0x09) // Payment ID Length (16 bytes)
	buf.WriteByte(0x01) // Encrypted Payment ID flag

	encryptedPaymentId, err := encryptPaymentID(paymentId, pubViewKey, t.SecretKey[:])
	if err != nil {
		return err
	}
	buf.Write(encryptedPaymentId[:])

	t.Extra = ByteArray(append(t.Extra, buf.Bytes()...))
	return nil
}

func SelectDecoys(rng *rand.Rand, realGlobalIndex uint64, maxGlobalIndex uint64) ([]uint64, error) {

	ringSize := 16

	selected := make(map[uint64]struct{})
	selected[realGlobalIndex] = struct{}{}

	for len(selected) < ringSize {
		// 1. возраст
		ageDays := sampleOutputAgeDays(rng)
		ageBlocks := uint64(ageDays * BlocksPerDay)

		if ageBlocks >= maxGlobalIndex {
			continue
		}

		// 2. перевод возраста → индекс
		target := maxGlobalIndex - ageBlocks

		// 3. uniform смещение (ВАЖНО)
		offset := uint64(rng.Int63n(int64(target + 1)))
		gi := offset

		// 4. проверки
		if gi == realGlobalIndex {
			continue
		}
		if _, exists := selected[gi]; exists {
			continue
		}

		selected[gi] = struct{}{}
	}

	// 5. финальный массив
	ring := make([]uint64, 0, ringSize)
	for gi := range selected {
		ring = append(ring, gi)
	}

	// 6. перемешать кольцо
	rng.Shuffle(len(ring), func(i, j int) {
		ring[i], ring[j] = ring[j], ring[i]
	})

	return ring, nil
}
