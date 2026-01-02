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

const (
	txPublicKeyHex  = "772299cb00fae663173f9aeab9273da82f2500976e6556e16da22bf6ceed1d83"
	txPrivateKeyHex = "fc1415ced071ae7de346a7ca0dd2b0f9b64cd64423d5ea73b971da135c54de05"
)

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
		RctSigPrunable: &RctSigPrunable{
			Nbp: 1,
			Bpp: []Bpp{
				Bpp{},
			},
			CLSAGs:     []CLSAG{},
			PseudoOuts: []Hash{},
		},
	}
	if h, err := hexTo32(txPublicKeyHex); err == nil {
		tx.PublicKey = Hash(h)
	}
	if h, err := hexTo32(txPrivateKeyHex); err == nil {
		tx.SecretKey = Hash(h)
	}

	// privKey, pubKey := moneroutil.NewKeyPair()
	// tx.SecretKey = Hash(privKey.ToBytes())
	// tx.PublicKey = Hash(pubKey.ToBytes())
	tx.writePubKeyToExtra()

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

	val, ok := prm["amount"].(float64)
	if !ok {
		return fmt.Errorf("failed to get amount of input")
	}
	_ = val

	t.VinCount += 1
	t.Inputs = append(t.Inputs, TxInput{
		// Amount:     uint64(val * 1e12),
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

func (t *Transaction) SignTransaction() error {
	Bpp, err := t.signBpp()
	if err != nil {
		return fmt.Errorf("failed to sign bpp: %w", err)
	}

	CLSAGs, err := t.signCLSAGs()
	if err != nil {
		return fmt.Errorf("failed to sign CLSAGs: %w", err)
	}

	PseudoOuts, err := t.calculatePseudoOuts()
	if err != nil {
		return fmt.Errorf("failed to calculate pseudo outputs: %w", err)
	}

	t.RctSigPrunable.Bpp[0] = Bpp
	t.RctSigPrunable.CLSAGs = CLSAGs
	t.RctSigPrunable.PseudoOuts = PseudoOuts
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

func (t *Transaction) PrefixHash() Hash {
	var result []byte
	result = append(moneroutil.Uint64ToBytes(uint64(t.Version)), moneroutil.Uint64ToBytes(t.UnlockTime)...)
	result = append(result, moneroutil.Uint64ToBytes(t.VinCount)...)
	for _, txIn := range t.Inputs {
		result = append(result, txIn.Serialize()...)
	}
	result = append(result, moneroutil.Uint64ToBytes(t.VoutCount)...)
	for _, txOut := range t.Outputs {
		result = append(result, txOut.Serialize()...)
	}
	result = append(result, moneroutil.Uint64ToBytes(uint64(len(t.Extra)))...)
	result = append(result, t.Extra...)

	hash := moneroutil.Keccak256(result)
	return Hash(hash)
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
