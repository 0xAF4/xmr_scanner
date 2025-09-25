package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"xmr_scanner/levin"
)

type ProcessingBlock struct {
	block []byte
	tx    [][]byte

	MajorVersion      uint8
	MinorVersion      uint8
	BlockHeight       uint64
	Timestamp         uint64
	PreviousBlockHash [32]byte
	Nonce             uint32
	MinerTx           MinerTransaction
	TxsCount          uint64

	TXs []*Transaction
}

type MinerTransaction struct {
	Version    uint64
	UnlockTime uint64
	VinCount   uint64
	InputType  byte
	Height     uint64
	OutputNum  uint64
	Outs       []TxOutput
	ExtraSize  uint8
	Extra      []byte
}

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

type RctSignature struct {
	Type     uint64
	TxnFee   uint64
	EcdhInfo []struct {
		Amount [8]byte
	}
	OutPk [][32]byte
}

type RctSigPrunable struct {
	Nbp uint64
	Bpp []struct {
		A  [32]byte
		A1 [32]byte
		B  [32]byte
		R1 [32]byte
		S1 [32]byte
		D1 [32]byte
		L  [][32]byte
		R  [][32]byte
	}
	CLSAGs []struct {
		S  [][32]byte
		C1 [32]byte
		D  [32]byte
	}
	PseudoOuts [][32]byte
}

var noty = NotifierMock{}

var Address = "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
var PrivateViewKey = "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

func main() {
	blockHash, err := os.ReadFile("C:\\Users\\Karim\\Desktop\\dump_985.bin")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	storage, err := levin.NewPortableStorageFromBytes(blockHash)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(2)
	}

	var blocksArr []*ProcessingBlock

	for _, entry := range storage.Entries {
		if entry.Name == "blocks" {
			// fmt.Println("Blocks")
			for _, blk := range entry.Entries() {
				// fmt.Println(" - Block")
				_block := &ProcessingBlock{}
				_TXs := []*Transaction{}

				for _, ibl := range blk.Entries() {
					// fmt.Println(" --", ibl.Name)
					if ibl.Name == "block" {
						_block.block = []byte(ibl.String())
						// fmt.Printf("% X\n", _block.block)
					} else {
						for _, itx := range ibl.Entries() {
							_block.tx = append(_block.tx, []byte(itx.String()))
							// fmt.Printf("% X\n", []byte(itx.String()))
						}
					}
				}
				_block.TXs = _TXs
				blocksArr = append(blocksArr, _block)
			}
		}
	}

	for i, block := range blocksArr {
		noty.NotifyWithLevel(fmt.Sprintf("Processing block %d", i), LevelInfo)

		if err := block.FullfillBlockHeader(); err != nil {
			noty.NotifyWithLevel(fmt.Sprintf("Error processing block header %d: %v", i, err), LevelError)
			continue
		}

		// if err := block.FullfillBlockTransactions(); err != nil {
		// 	noty.NotifyWithLevel(fmt.Sprintf("Error processing block transactions %d: %v", i, err), LevelError)
		// 	continue
		// }

		noty.NotifyWithLevel(fmt.Sprintf("Block %d processed successfully", i), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Major Version: %d", block.MajorVersion), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Minor Version: %d", block.MinorVersion), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Block Height: %d", block.BlockHeight), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Timestamp: %d", block.Timestamp), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Previous Block Hash: %X", block.PreviousBlockHash), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Nonce: %d", block.Nonce), LevelSuccess)
		noty.NotifyWithLevel("=========", LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx Version: %d", block.MinerTx.Version), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx UnlockTime: %d", block.MinerTx.UnlockTime), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx VinCount: %d", block.MinerTx.VinCount), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx Input Type: %X", block.MinerTx.InputType), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx Height: %d", block.MinerTx.Height), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx OutputNum: %d", block.MinerTx.OutputNum), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx Extra size: %d", block.MinerTx.ExtraSize), LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  MinerTx Extra: %X", block.MinerTx.Extra), LevelSuccess)
		for _, tx := range block.MinerTx.Outs {
			noty.NotifyWithLevel("  ------", LevelSuccess)
			noty.NotifyWithLevel(fmt.Sprintf("  - MinerTx Amount: %d", tx.Amount), LevelSuccess)
			noty.NotifyWithLevel(fmt.Sprintf("  - MinerTx Public Key: %X", tx.Target), LevelSuccess)
		}
		noty.NotifyWithLevel("=========", LevelSuccess)
		noty.NotifyWithLevel(fmt.Sprintf("  Transaction count: %d", block.TxsCount), LevelSuccess)
		for _, tx := range block.TXs {
			if fmt.Sprintf("%x", tx.Hash) != "8b891c0352014ea6687a0b51b8128ec238b26c9bd523aa1554def1078d822222" {
				continue
			}
			tx.ParseTx()
			noty.NotifyWithLevel("  ------", LevelSuccess)
			noty.NotifyWithLevel(fmt.Sprintf("  - TX Hash: %X", tx.Hash), LevelSuccess)
			data, err := json.MarshalIndent(tx, "", "  ")
			if err != nil {
				panic(err)
			}
			noty.NotifyWithLevel("\n"+string(data), LevelSuccess)
			// noty.NotifyWithLevel(fmt.Sprintf("  - TX Extra: %X", tx.Extra), LevelSuccess)
			// noty.NotifyWithLevel(fmt.Sprintf("  --- TX Extra: %v", tx.Extra), LevelInfo)
			
			// funds, err := tx.FindFunds(Address, PrivateViewKey)
			// if err != nil {
			// 	noty.NotifyWithLevel(fmt.Sprintf("  - TX Find funds error: %s", err), LevelError)
			// } else {
			// 	noty.NotifyWithLevel(fmt.Sprintf("  - TX Find funds amount: %.8f", funds), LevelWarning)
			// }

		}

		os.Exit(11)
	}
}

func (block *ProcessingBlock) FullfillBlockHeader() error {
	if len(block.block) < 43 {
		return fmt.Errorf("block data too short: %d bytes", len(block.block))
	}

	reader := bytes.NewReader(block.block)
	//----
	block.MajorVersion, _ = readUint8(reader)
	block.MinorVersion, _ = readUint8(reader)
	//----
	timestamp, _ := readVarint(reader)
	block.Timestamp = timestamp
	//----
	reader.Read(block.PreviousBlockHash[:])
	binary.Read(reader, binary.LittleEndian, &block.Nonce)
	//----
	block.MinerTx.Version, _ = readVarint(reader)
	block.MinerTx.UnlockTime, _ = readVarint(reader)
	block.MinerTx.VinCount, _ = readVarint(reader)
	block.MinerTx.InputType, _ = reader.ReadByte()
	block.MinerTx.Height, _ = readVarint(reader)
	block.MinerTx.OutputNum, _ = readVarint(reader)
	//----
	outs := []TxOutput{}
	for i := 1; i <= int(block.MinerTx.OutputNum); i++ {
		out := TxOutput{}
		out.Amount, _ = readVarint(reader)
		reader.Seek(1, io.SeekCurrent)
		reader.Read(out.Target[:])
		outs = append(outs, out)
	}
	block.MinerTx.Outs = outs
	//----
	reader.Seek(1, io.SeekCurrent)
	block.MinerTx.ExtraSize, _ = readUint8(reader)
	block.MinerTx.ExtraSize += 1
	tempExtra := make([]byte, block.MinerTx.ExtraSize)
	reader.Read(tempExtra[:])
	block.MinerTx.Extra = tempExtra
	//----
	block.TxsCount, _ = readVarint(reader)
	for i := 0; i <= int(block.TxsCount)-1; i++ {
		tx := &Transaction{
			Raw: block.tx[i],
		}
		reader.Read(tx.Hash[:])
		block.TXs = append(block.TXs, tx)
	}

	return nil
}

func (tx *Transaction) ParseTx() {
	reader := bytes.NewReader(tx.Raw)

	// 1. Версия транзакции
	tx.Version, _ = readVarint(reader)
	tx.UnlockTime, _ = readVarint(reader)

	// 3. Inputs
	tx.VinCount, _ = readVarint(reader)
	for i := 0; i < int(tx.VinCount); i++ {
		var in TxInput
		// тип входа (0xff = coinbase)
		in.Type, _ = reader.ReadByte()

		if in.Type == 0xff { // Coinbase input
			in.Height, _ = readVarint(reader)
		} else if in.Type == 0x02 {
			in.Amount, _ = readVarint(reader)
			ofsCount, _ := readVarint(reader)
			for j := 0; j < int(ofsCount); j++ {
				ofs, _ := readVarint(reader)
				in.KeyOffsets = append(in.KeyOffsets, ofs)
			}
			reader.Read(in.KeyImage[:])
		} else {
			fmt.Printf("⚠️ Unknown TxInput type: 0x%X\n", in.Type)
		}
		tx.Inputs = append(tx.Inputs, in)
	}

	// 4. Outputs
	tx.VoutCount, _ = readVarint(reader)
	for i := 0; i < int(tx.VoutCount); i++ {
		var out TxOutput
		out.Amount, _ = readVarint(reader)

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
	extraLen, _ := readVarint(reader)
	extra := make([]byte, extraLen)
	reader.Read(extra)
	tx.Extra = extra

	rest := make([]byte, reader.Len())
	reader.Read(rest)
	tx.RctRaw = rest

	return
}

// readVarint читает varint из reader
func readVarint(reader *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint

	for {
		if shift >= 64 {
			return 0, fmt.Errorf("varint too long")
		}

		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}

		result |= uint64(b&0x7F) << shift

		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, nil
}

func readUint8(reader *bytes.Reader) (uint8, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	return b, nil
}
