package levin

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
)

type Transaction struct {
	Hash [32]byte `json:"-"`
	Raw  []byte   `json:"-"`

	Version        uint64          `json:"version"`
	UnlockTime     uint64          `json:"unlock_time"`
	VinCount       uint64          `json:"-"`
	Inputs         []TxInput       `json:"vin"`
	VoutCount      uint64          `json:"-"`
	Outputs        []TxOutput      `json:"vout"`
	Extra          ByteArray       `json:"extra"`
	RctRaw         []byte          `json:"-"`
	RctSignature   *RctSignature   `json:"rct_signature"`
	RctSigPrunable *RctSigPrunable `json:"rctsig_prunable"`
}

type TxInput struct {
	Type       uint8    `json:"-"`
	Height     uint64   `json:"-"`
	Amount     uint64   `json:"amount"`
	KeyOffsets []uint64 `json:"key_offsets"`
	KeyImage   Hash     `json:"k_image"`
}

type TxOutput struct {
	Amount  uint64 `json:"amount"`
	Target  Hash   `json:"key"`
	ViewTag HByte  `json:"view_tag"`
}

type Echd struct {
	Amount HAmount `json:"amount"`
}

type RctSignature struct {
	Type     uint64 `json:"type"`
	TxnFee   uint64 `json:"txn_fee"`
	EcdhInfo []Echd `json:"ecdhInfo"`
	OutPk    []Hash `json:"outPk"`
}

type Bpp struct {
	A  Hash   `json:"A"`
	A1 Hash   `json:"A1"`
	B  Hash   `json:"B"`
	R1 Hash   `json:"r1"`
	S1 Hash   `json:"s1"`
	D1 Hash   `json:"d1"`
	L  []Hash `json:"L"`
	R  []Hash `json:"R"`
}

type CLSAG struct {
	S  []Hash `json:"s"`
	C1 Hash   `json:"c1"`
	D  Hash   `json:"D"`
}

type RctSigPrunable struct {
	Nbp        uint64  `json:"nbp"`
	Bpp        []Bpp   `json:"bpp"`
	CLSAGs     []CLSAG `json:"CLSAGs"`
	PseudoOuts []Hash  `json:"pseudoOuts"`
}

func (tx *Transaction) ParseTx() {
	reader := bytes.NewReader(tx.Raw)

	// 1. Версия транзакции
	tx.Version, _ = ReadVarint(reader)
	tx.UnlockTime, _ = ReadVarint(reader)

	// 3. Inputs
	tx.VinCount, _ = ReadVarint(reader)
	for i := 0; i < int(tx.VinCount); i++ {
		var in TxInput
		// тип входа (0xff = coinbase)
		in.Type, _ = reader.ReadByte()

		if in.Type == 0xff { // Coinbase input
			in.Height, _ = ReadVarint(reader)
		} else if in.Type == 0x02 {
			in.Amount, _ = ReadVarint(reader)
			ofsCount, _ := ReadVarint(reader)
			for j := 0; j < int(ofsCount); j++ {
				ofs, _ := ReadVarint(reader)
				in.KeyOffsets = append(in.KeyOffsets, ofs)
			}
			reader.Read(in.KeyImage[:])
		} else {
			fmt.Printf("⚠️ Unknown TxInput type: 0x%X\n", in.Type)
		}
		tx.Inputs = append(tx.Inputs, in)
	}

	// 4. Outputs
	tx.VoutCount, _ = ReadVarint(reader)
	for i := 0; i < int(tx.VoutCount); i++ {
		var out TxOutput
		out.Amount, _ = ReadVarint(reader)

		// читаем target (обычно один байт типа и 32 байта ключа)
		targetType, _ := reader.ReadByte()
		if targetType != 0x02 {
			// 0x02 = TXOUT_TO_KEY (обычный output Monero)
			fmt.Printf("⚠️ Unknown TxOut target type: 0x%X\n", targetType)
		}
		reader.Read(out.Target[:])
		b, _ := reader.ReadByte()
		out.ViewTag = HByte(b)
		tx.Outputs = append(tx.Outputs, out)
	}

	// 5. Extra
	extraLen, _ := ReadVarint(reader)
	extra := make([]byte, extraLen)
	reader.Read(extra)
	tx.Extra = extra

	rest := make([]byte, reader.Len())
	reader.Read(rest)
	tx.RctRaw = rest
}

func (tx *Transaction) ParseRctSig() {
	if len(tx.RctRaw) == 0 {
		return
	}

	RctSignature := &RctSignature{}
	RctSigPrunable := &RctSigPrunable{}

	reader := bytes.NewReader(tx.RctRaw)
	RctSignature.Type, _ = ReadVarint(reader)
	RctSignature.TxnFee, _ = ReadVarint(reader)

	for i := 0; i < len(tx.Outputs); i++ {
		ecdh := Echd{}
		reader.Read(ecdh.Amount[:])
		RctSignature.EcdhInfo = append(RctSignature.EcdhInfo, ecdh)
	}

	for i := 0; i < len(tx.Outputs); i++ {
		var outPk Hash
		reader.Read(outPk[:])
		RctSignature.OutPk = append(RctSignature.OutPk, outPk)
	}

	RctSigPrunable.Nbp, _ = ReadVarint(reader)
	for i := 0; i < int(RctSigPrunable.Nbp); i++ {
		bpp := Bpp{}
		reader.Read(bpp.A[:])
		reader.Read(bpp.A1[:])
		reader.Read(bpp.B[:])
		reader.Read(bpp.R1[:])
		reader.Read(bpp.S1[:])
		reader.Read(bpp.D1[:])

		c, _ := ReadVarint(reader)
		for j := 0; j < int(c); j++ {
			var l Hash
			reader.Read(l[:])
			bpp.L = append(bpp.L, l)
		}

		c, _ = ReadVarint(reader)
		for j := 0; j < int(c); j++ {
			var r Hash
			reader.Read(r[:])
			bpp.R = append(bpp.R, r)
		}

		RctSigPrunable.Bpp = append(RctSigPrunable.Bpp, bpp)
	}

	// CLSAGs
	for i := 0; i < int(tx.VinCount); i++ {
		CLSAG := CLSAG{}
		for j := 0; j < len(tx.Inputs[i].KeyOffsets); j++ {
			var s Hash // Скаляр — 32 байта
			reader.Read(s[:])
			CLSAG.S = append(CLSAG.S, s)
		}

		reader.Read(CLSAG.C1[:])
		reader.Read(CLSAG.D[:])

		RctSigPrunable.CLSAGs = append(RctSigPrunable.CLSAGs, CLSAG)
	}

	for i := 0; i < int(tx.VinCount); i++ {
		var s Hash // Скаляр — 32 байта
		reader.Read(s[:])
		RctSigPrunable.PseudoOuts = append(RctSigPrunable.PseudoOuts, s)
	}

	tx.RctSignature = RctSignature
	tx.RctSigPrunable = RctSigPrunable

	rest := make([]byte, reader.Len())
	reader.Read(rest)
	tx.RctRaw = rest
}

func (tx *Transaction) CheckOutputs(address string, privateViewKey string) (uint64, error) {
	pubSpendKey, pubViewKey, err := DecodeAddress(address) // correct ✅
	if err != nil {
		return 0, fmt.Errorf("failed to decode address: %w", err)
	}
	fmt.Printf("Public Spend Key: %x\n", pubSpendKey) //Public Spend Key: cb7daf66af88f390889517765b175416ebbe384baa92945eb250aff05f30d489
	fmt.Printf("Public View Key: %x\n", pubViewKey)   //Public View Key: b605672b04d08b273efddf76a6d5acb106766fdf6e6e5f62bd5b4e6a71daa366

	privViewKeyBytes, err := hexTo32(privateViewKey) // correct ✅
	if err != nil {
		return 0, fmt.Errorf("failed to decode private view key: %w", err)
	}

	if !verifyViewKeyPair(privViewKeyBytes, pubViewKey[:]) { // correct ✅
		return 0, fmt.Errorf("private view key does not match address")
	}

	txPubKey, err := extractTxPubKey(tx.Extra) // хз
	if err != nil {
		return 0, fmt.Errorf("failed to extract tx public key: %w", err)
	}
	fmt.Printf("Transaction Public Key: %x\n", txPubKey) //Transaction Public Key: b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff

	// Check each output
	var totalAmount uint64
	var foundOutputs int

	for outputIndex, output := range tx.Outputs {
		fmt.Println("Output Index:", outputIndex)
		fmt.Printf("Output Target Key: %x\n", output.Target)
		fmt.Printf("Output View Tag: %x\n", output.ViewTag)

		// Derive the one-time public key and view tag
		derivedKey, viewTagByte, err := DerivePublicKeyWithViewTag(txPubKey, privViewKeyBytes, pubSpendKey[:], uint64(outputIndex))
		if err != nil {
			continue
		}

		// If view tag exists and doesn't match, log it but don't immediately skip — fall back to full derived-key check
		if output.ViewTag != 0 {
			if byte(output.ViewTag) != viewTagByte {
				fmt.Printf("Output %d: View tag mismatch (expected %02x, got %02x), will still check derived key\n", outputIndex, viewTagByte, byte(output.ViewTag))
				continue
			} else {
				fmt.Println("Output view_tag is match✅")
			}
		}

		// Compare derived key with output target (this is authoritative)
		if !equalBytes(derivedKey, output.Target[:]) {
			fmt.Printf("Output %d: Derived key %x does not match output target %x\n", outputIndex, derivedKey, output.Target)
			continue // Not our output
		}

		// This output belongs to us!
		foundOutputs++
		var amount uint64

		// If it's an RCT transaction, decode the amount
		if tx.RctSignature != nil && tx.RctSignature.Type > 0 {
			if outputIndex < len(tx.RctSignature.EcdhInfo) {
				amount, err = decodeRctAmount(
					txPubKey,
					privViewKeyBytes,
					uint64(outputIndex),
					tx.RctSignature.EcdhInfo[outputIndex].Amount[:],
				)
				if err != nil {
					return 0, fmt.Errorf("failed to decode RCT amount for output %d: %w", outputIndex, err)
				}
			}
		} else {
			// For non-RCT transactions, amount is plaintext
			amount = output.Amount
		}

		totalAmount += amount
	}

	if foundOutputs == 0 {
		return 0, fmt.Errorf("no outputs found for this address")
	}

	return totalAmount, nil
}

func DerivePublicKeyWithViewTag(txPubKey []byte, privateViewKey []byte, pubSpendKey []byte, index uint64) ([]byte, byte, error) {
	if len(txPubKey) != 32 || len(privateViewKey) != 32 || len(pubSpendKey) != 32 {
		return nil, 0, fmt.Errorf("invalid key lengths")
	}
	// Compute shared secret (a * R). Use the shared secret for view tag.
	sharedSecret, err := SharedSecret(txPubKey, privateViewKey)
	if err != nil {
		return nil, 0, err
	}

	// Compute view tag per Monero: H[salt||derivation||varint(index)], salt is 8 bytes "view_tag"
	data := make([]byte, 0, 8+len(sharedSecret)+10)
	data = append(data, []byte("view_tag")...) // 8 bytes without null terminator
	data = append(data, sharedSecret...)
	data = append(data, encodeVarint(index)...)
	viewTagHash := keccak256(data)
	viewTag := viewTagHash[0]

	// Reuse existing DerivePublicKey to compute the one-time public key
	fmt.Printf("txPubKey: %x, privateViewKey: %x, pubSpendKey: %x, index: %d\n",
		txPubKey, privateViewKey, pubSpendKey, index)

	derivedKey, err := DerivePublicKey(txPubKey, privateViewKey, pubSpendKey, index)
	if err != nil {
		return nil, 0, err
	}

	return derivedKey, viewTag, nil
}

// verifyViewKeyPair checks if a private view key corresponds to a public view key
func verifyViewKeyPair(privViewKey []byte, pubViewKey []byte) bool {
	// Import edwards25519
	var scalar edwards25519.Scalar
	if _, err := scalar.SetCanonicalBytes(privViewKey); err != nil {
		return false
	}

	// Compute public key: P = a*G
	derivedPubKey := new(edwards25519.Point).ScalarBaseMult(&scalar)
	return equalBytes(derivedPubKey.Bytes(), pubViewKey)
}

// computeViewTag computes the view tag for an output
func computeViewTag(txPubKey []byte, privateViewKey []byte, outputIndex uint64) byte {
	// Compute shared secret
	sharedSecret, err := SharedSecret(txPubKey, privateViewKey)
	if err != nil {
		return 0
	}

	// Create derivation data: "view_tag" (8 bytes) + shared_secret + output_index (varint)
	data := make([]byte, 0, 8+len(sharedSecret)+10)
	data = append(data, []byte("view_tag")...)
	data = append(data, sharedSecret...)
	data = append(data, encodeVarint(outputIndex)...)

	// Hash and take first byte
	hash := keccak256(data)
	return hash[0]
}

// ComputeViewTagForDebug is an exported wrapper for computeViewTag used by debug tools/tests.
func ComputeViewTagForDebug(txPubKey []byte, privateViewKey []byte, outputIndex uint64) byte {
	return computeViewTag(txPubKey, privateViewKey, outputIndex)
}

// extractTxPubKey extracts the transaction public key from the Extra field
// Format: 0x01 (tag) + 32 bytes (public key)
func extractTxPubKey(extra []byte) ([]byte, error) {
	if len(extra) < 33 {
		return nil, fmt.Errorf("extra field too short")
	}

	// Look for tag 0x01 (TX_EXTRA_TAG_PUBKEY)
	for i := 0; i < len(extra)-32; i++ {
		if extra[i] == 0x01 {
			// Found the tag, next 32 bytes are the public key
			pubKey := make([]byte, 32)
			copy(pubKey, extra[i+1:i+33])
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("tx public key not found in extra field")
}

// decodeRctAmount decodes an encrypted RCT amount
func decodeRctAmount(txPubKey []byte, privateViewKey []byte, outputIndex uint64, encryptedAmount []byte) (uint64, error) {
	if len(encryptedAmount) != 8 {
		return 0, fmt.Errorf("invalid encrypted amount length: %d", len(encryptedAmount))
	}

	// Compute shared secret
	sharedSecret, err := SharedSecret(txPubKey, privateViewKey)
	if err != nil {
		return 0, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Create derivation data: "amount" + shared_secret + output_index (varint)
	derivationData := append([]byte("amount"), sharedSecret...)

	// Add output index as varint for small values (< 128), it's just one byte
	if outputIndex < 128 {
		derivationData = append(derivationData, byte(outputIndex))
	} else {
		// For larger indices, use proper varint encoding
		indexBytes := encodeVarint(outputIndex)
		derivationData = append(derivationData, indexBytes...)
	}

	// Hash to get decryption key
	decryptionKey := keccak256(derivationData)

	// XOR the encrypted amount with first 8 bytes of decryption key
	var amount uint64
	for i := 0; i < 8; i++ {
		decrypted := encryptedAmount[i] ^ decryptionKey[i]
		amount |= uint64(decrypted) << (8 * i)
	}

	return amount, nil
}

// encodeVarint encodes a uint64 as a varint (used in Monero)
func encodeVarint(n uint64) []byte {
	var buf []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if n == 0 {
			break
		}
	}
	return buf
}

// EncodeVarint is an exported wrapper for encodeVarint for debugging/tests
func EncodeVarint(n uint64) []byte {
	return encodeVarint(n)
}
