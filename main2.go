package main

import (
	"bytes"
	"encoding/binary"
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
	ExtraSize  uint64
	Extra      []byte
}

type Transaction struct {
	Hash    [32]byte
	Raw     []byte
	Version uint64
	Inputs  []TxInput
	Outputs []TxOutput
	Extra   []byte
}

type TxInput struct {
	Type   uint8
	Height uint64 // Для coinbase input
}

type TxOutput struct {
	Amount uint64
	Target [32]byte
}

var noty = NotifierMock{}
var hash = [32]byte{}

func main() {
	blockHash, err := os.ReadFile("C:\\Users\\Karim\\Desktop\\dump.bin")
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
			tx.ParseTx()
			noty.NotifyWithLevel("  ------", LevelSuccess)
			noty.NotifyWithLevel(fmt.Sprintf("  - TX Hash: %X", tx.Hash), LevelSuccess)
			noty.NotifyWithLevel(fmt.Sprintf("  - TX Raw: %X...", tx.Raw[:31]), LevelSuccess)
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
	majorVersion, _ := readVarint(reader)
	block.MajorVersion = uint8(majorVersion)
	//----
	minorVersion, _ := readVarint(reader)
	block.MinorVersion = uint8(minorVersion)
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
	block.MinerTx.ExtraSize, _ = readVarint(reader)
	tempExtra := make([]byte, block.MinerTx.ExtraSize/2)
	reader.Read(tempExtra[:])
	block.MinerTx.Extra = tempExtra
	reader.Seek(11, io.SeekCurrent)
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

/*
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 0, val: 93d7b6de7644e8a623ee52c9d60fa2ae5d89d395af41db8213c8cc09758fa1c2
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 1, val: ee07c8d0686160e20368d7b585fcde31090920a759fa57e01250553ac2c89261
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 2, val: d25506e2272bc703548f5f8e5fb376b2ff16b5e609f7af03b2f2d8114cbc668c
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 3, val: 085ea3f566adfdeabe92656b2f02772013d5ef068def036ef490005b485fec2c
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 4, val: b93a08bc34c54892487b1d94d78c16cdc87bbbedd93dc54a0b15cf018e83a644
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 5, val: f5460b49d2fac85c03890e692c82d14be5176f68fd9825e09199d34357fefa98
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 6, val: f2a7c13578f7850111f9e4775a5b04e3c29dfb21c069af0c4daf6f69ca3791bd
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 7, val: 15898c9be24bda562fe6fe7dd0ae34dc4b9c6f3e6ef8c6f3bc43d85b9b8f52a7
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 8, val: 0c144535185b1926729881fe800db696d9e48d8805c2209b4c69c52869288818
[20:42:55 09.09.2025] [NOTIFY] ⚫INFO⚫: I: 9, val: 831f23d2d99d1bcda321760b0d4ce69a5243ba9fea3bc08fcf8a48b4ebc5196b
*/
