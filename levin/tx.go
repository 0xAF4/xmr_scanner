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

func (tx *Transaction) CheckOutputs(address string, privateViewKey string) error {
	// вообщем твоя задача написать реализацию данной функции
}
