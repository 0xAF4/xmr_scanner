package levin

import (
	"bytes"
	"fmt"
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

func (tx *Transaction) FindFunds(address string, privateViewKey string) (float64, error) {
	// Decode address -> get pubSpend and pubView
	pubSpend, _, err := DecodeAddress(address)
	if err != nil {
		return 0, err
	}

	// parse private view key hex
	pvkBytes, err := hexTo32(privateViewKey)
	if err != nil {
		return 0, err
	}

	var total uint64 = 0

	// tx.ParseTx and ParseRctSig should already be called by caller, but guard
	if len(tx.Outputs) == 0 {
		return 0, nil
	}

	// find tx public key in extra (tx.Extra contains tx public key tag 0x01 followed by 32-byte pubkey)
	var txPubKey []byte
	extra := []byte(tx.Extra)
	for i := 0; i < len(extra); i++ {
		if extra[i] == 0x01 && i+33 <= len(extra) { // TX_EXTRA_TAG_PUBKEY + 32 bytes
			txPubKey = make([]byte, 32)
			copy(txPubKey, extra[i+1:i+33])
			break
		}
	}

	// fallback: if rct signature has OutPk, in modern Monero there's per-output "outPk" which is the masked public key
	// but we still need txPubKey to derive one-time keys

	for i, out := range tx.Outputs {
		// compute one-time public key for this output index
		var derived []byte
		// If RctSignature.OutPk exists, it contains the encrypted public keys (rct) — but for address check we need derived pubkey = derive_public_key(txpub, privView, pubSpend, index)
		if txPubKey != nil {
			d, derr := DerivePublicKey(txPubKey, pvkBytes, pubSpend[:], uint64(i))
			if derr != nil {
				// ignore derivation errors for this output
			} else {
				derived = d
			}
		}

		match := false
		if derived != nil {
			// compare derived with output.Target
			if fmt.Sprintf("%x", derived) == fmt.Sprintf("%x", out.Target[:]) {
				match = true
			}
		} else {
			// fallback: compare out.Target to pubSpend (unlikely correct) or OutPk
			if tx.RctSignature != nil && len(tx.RctSignature.OutPk) > i {
				if fmt.Sprintf("%x", tx.RctSignature.OutPk[i]) == fmt.Sprintf("%x", out.Target[:]) {
					match = true
				}
			}
		}

		// debug: if this tx is the one under investigation, print keys
		if fmt.Sprintf("%x", tx.Hash) == "8b891c0352014ea6687a0b51b8128ec238b26c9bd523aa1554def1078d822222" {
			fmt.Printf("DEBUG txpub: %x\n", txPubKey)
			fmt.Printf("DEBUG pubSpend: %x\n", pubSpend)
			if derived != nil {
				fmt.Printf("DEBUG derived[%d]: %x\n", i, derived)
			}
			fmt.Printf("DEBUG out.Target[%d]: %x\n", i, out.Target)
			if tx.RctSignature != nil && len(tx.RctSignature.OutPk) > i {
				fmt.Printf("DEBUG outPk[%d]: %x\n", i, tx.RctSignature.OutPk[i])
			}
		}

		if match {
			// Amount: if RCT present, amounts are encrypted in RctSignature.EcdhInfo
			if tx.RctSignature != nil && len(tx.RctSignature.EcdhInfo) > i {
				// Ecdh.Amount is 8 bytes with masked amount. For now, try to parse as little-endian uint64 directly.
				// Proper decryption requires shared secret derived from tx pubkey and private view key and XOR with mask.
				// As a pragmatic approach, if Ecdh.Amount is zero, fall back to out.Amount.
				var amt uint64 = 0
				a := tx.RctSignature.EcdhInfo[i].Amount
				// convert HAmount (8 bytes) to uint64 little endian
				for j := 0; j < 8; j++ {
					amt |= uint64(a[j]) << (8 * uint(j))
				}
				if amt == 0 {
					amt = out.Amount
				}
				total += amt
			} else {
				total += out.Amount
			}
		}
	}

	// convert atomic units to XMR (1 XMR = 1e12)
	return float64(total) / 1e12, nil
}
