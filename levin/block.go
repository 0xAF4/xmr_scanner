package levin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type Block struct {
	block []byte   `json:"-"`
	tx    [][]byte `json:"-"`

	MajorVersion      uint8  `json:"major_version"`
	MinorVersion      uint8  `json:"minor_version"`
	BlockHeight       uint64 `json:"height"`
	Timestamp         uint64 `json:"timestamp"`
	PreviousBlockHash Hash   `json:"prev_id"`
	Nonce             uint32 `json:"nonce"`
	MinerTx           struct {
		Version    uint64     `json:"version"`
		UnlockTime uint64     `json:"unlock_time"`
		VinCount   uint64     `json:"-"`
		InputType  byte       `json:"input_type"`
		Height     uint64     `json:"height"`
		OutputNum  uint64     `json:"-"`
		Outs       []TxOutput `json:"vout"`
		ExtraSize  uint8      `json:"-"`
		Extra      ByteArray  `json:"extra"`
	} `json:"miner_tx"`

	TxsCount uint64         `json:"txs_count"`
	TXs      []*Transaction `json:"-"`
}

func NewBlock() *Block {
	return &Block{}
}

func (b *Block) SetBlockData(data []byte) {
	b.block = data
}

func (b *Block) InsertTx(data []byte) {
	b.tx = append(b.tx, data)
}

func (block *Block) FullfillBlockHeader() error {
	if len(block.block) < 43 {
		return fmt.Errorf("block data too short: %d bytes", len(block.block))
	}

	reader := bytes.NewReader(block.block)
	//----
	block.MajorVersion, _ = ReadUint8(reader)
	block.MinorVersion, _ = ReadUint8(reader)
	//----
	timestamp, _ := ReadVarint(reader)
	block.Timestamp = timestamp
	//----
	reader.Read(block.PreviousBlockHash[:])
	binary.Read(reader, binary.LittleEndian, &block.Nonce)
	//----
	block.MinerTx.Version, _ = ReadVarint(reader)
	block.MinerTx.UnlockTime, _ = ReadVarint(reader)
	block.MinerTx.VinCount, _ = ReadVarint(reader)
	block.MinerTx.InputType, _ = reader.ReadByte()
	block.MinerTx.Height, _ = ReadVarint(reader)
	block.MinerTx.OutputNum, _ = ReadVarint(reader)
	//----
	outs := []TxOutput{}
	for i := 1; i <= int(block.MinerTx.OutputNum); i++ {
		out := TxOutput{}
		out.Amount, _ = ReadVarint(reader)
		reader.Seek(1, io.SeekCurrent)
		reader.Read(out.Target[:])
		outs = append(outs, out)
	}
	block.MinerTx.Outs = outs
	//----
	reader.Seek(1, io.SeekCurrent)
	block.MinerTx.ExtraSize, _ = ReadUint8(reader)
	block.MinerTx.ExtraSize += 1
	tempExtra := make([]byte, block.MinerTx.ExtraSize)
	reader.Read(tempExtra[:])
	block.MinerTx.Extra = tempExtra
	//----
	block.TxsCount, _ = ReadVarint(reader)
	for i := 0; i <= int(block.TxsCount)-1; i++ {
		tx := &Transaction{
			Raw: block.tx[i],
		}
		reader.Read(tx.Hash[:])
		block.TXs = append(block.TXs, tx)
	}

	return nil
}
