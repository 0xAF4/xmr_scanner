package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"xmr_scanner/levin"
)

func (p *ScannerXMR) WriteBlockToDBLoop() {
	for !p.destroy {
		time.Sleep(time.Second * 1)
		var hashkey string
		p.blocks.Range(func(key string, value *Block) bool {
			if !value.received || value.PreviousHash != p.lastBlockHash {
				return true
			}

			err2 := p.n.NotifyWithLevel(fmt.Sprintf("4 WriteBlockToDB Init: %s", key), LevelInfo)
			if err2 != nil {
				fmt.Println(fmt.Sprintf("4 WriteBlockToDB Init: %s", key))
			}

			if err := p.db.ProcessBlock(value.GetChainName(), value.ConvertToDBBlock()); err == nil {
				err2 = p.n.NotifyWithLevel(fmt.Sprintf("4 WriteBlockToDB Success: %s", key), LevelSuccess)
				if err2 != nil {
					fmt.Println(fmt.Sprintf("4 WriteBlockToDB Success: %s", key))
				}
				p.lastBlockHash = value.Hash
				p.lastBlockHeight++
				p.uptime = value.Timestamp
				hashkey = key
			} else {
				err2 = p.n.NotifyWithLevel(fmt.Sprintf("4 WriteBlockToDB Error: %s; %s", key, err.Error()), LevelError)
				if err2 != nil {
					fmt.Println(fmt.Sprintf("4 WriteBlockToDB Error: %s; %s", key, err.Error()))
				}
			}
			return false
		})
		if hashkey != "" { //Это нужно вытащить сюда иначи мы сами себя заблокируем
			p.blocks.Delete(hashkey)
		}
	}
}

func (p *ScannerXMR) showHeader(header *levin.Header) {
	p.n.NotifyWithLevel(fmt.Sprintf("Message received:"), LevelInfo)
	p.n.NotifyWithLevel(fmt.Sprintf(" - Length: %d", header.Length), LevelInfo)
	p.n.NotifyWithLevel(fmt.Sprintf(" - ExpectsResponse: %t", header.ExpectsResponse), LevelInfo)
	p.n.NotifyWithLevel(fmt.Sprintf(" - Command: %d", header.Command), LevelInfo)
	p.n.NotifyWithLevel(fmt.Sprintf(" - ReturnCode: %d", header.ReturnCode), LevelInfo)
	if header.Flags == levin.LevinPacketRequest {
		p.n.NotifyWithLevel(fmt.Sprintf(" - Flags: %s", "Request"), LevelInfo)
	} else {
		p.n.NotifyWithLevel(fmt.Sprintf(" - Flags: %s", "Response"), LevelInfo)
	}
}

func ProcessBlockIds(value interface{}) ([]string, error) {
	// Сначала приводим к []byte
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return nil, fmt.Errorf("unexpected type for block_ids: %T", value)
	}

	// В Monero хеши блоков обычно 32 байта каждый
	const HASH_SIZE = 32

	if len(bytes)%HASH_SIZE != 0 {
		return nil, fmt.Errorf("invalid block_ids length: %d, expected multiple of %d", len(bytes), HASH_SIZE)
	}

	numHashes := len(bytes) / HASH_SIZE
	blockIds := make([]string, numHashes)

	for i := 0; i < numHashes; i++ {
		start := i * HASH_SIZE
		end := start + HASH_SIZE
		hash := bytes[start:end]

		// Конвертируем в hex строку
		blockIds[i] = hex.EncodeToString(hash)
	}

	return blockIds, nil
}

func (p *ScannerXMR) purple(header *levin.Header) {
	switch header.Command {
	case levin.CommandHandshake:
		p.n.NotifyWithLevel("CommandHandshake", "🟣")
	case levin.CommandTimedSync:
		p.n.NotifyWithLevel("CommandTimedSync", "🟣")
	case levin.CommandPing:
		p.n.NotifyWithLevel("CommandPing", "🟣")
	case levin.CommandStat:
		p.n.NotifyWithLevel("CommandStat", "🟣")
	case levin.CommandNetworkState:
		p.n.NotifyWithLevel("CommandNetworkState", "🟣")
	case levin.CommandPeerID:
		p.n.NotifyWithLevel("CommandPeerID", "🟣")
	case levin.CommandSupportFlags:
		p.n.NotifyWithLevel("CommandSupportFlags", "🟣")

	// --- P2P notify commands ---
	case levin.NotifyNewBlock:
		p.n.NotifyWithLevel("NotifyNewBlock", "🟣")
	case levin.NotifyNewTransaction:
		p.n.NotifyWithLevel("NotifyNewTransaction", "🟣")
	case levin.NotifyRequestGetObjects:
		p.n.NotifyWithLevel("NotifyRequestGetObjects", "🟣")
	case levin.NotifyResponseGetObjects:
		p.n.NotifyWithLevel("NotifyResponseGetObjects", "🟣")
	case levin.NotifyRequestChain:
		p.n.NotifyWithLevel("NotifyRequestChain", "🟣")
	case levin.NotifyResponseChainEntry:
		p.n.NotifyWithLevel("NotifyResponseChainEntry", "🟣")
	case levin.NotifyNewFluffyBlock:
		p.n.NotifyWithLevel("NotifyNewFluffyBlock", "🟣")
	case levin.NotifyRequestFluffyMissing:
		p.n.NotifyWithLevel("NotifyRequestFluffyMissing", "🟣")
	}
}

func (p *ScannerXMR) requestGetNextBlock() error {
	payload := (&levin.PortableStorage{
		Entries: []levin.Entry{
			{
				Name:         "start_height",
				Serializable: levin.BoostUint64(uint64(p.lastBlockHeight + 1)), // Request next block
			},
		},
	}).Bytes()
	p.n.NotifyWithLevel("Request block data", LevelInfo)
	//NotifyNewBlock             uint32 = 2001
	return p.conn.SendRequest(levin.NotifyRequestChain, payload)
}

func (p *ScannerXMR) requestBlockData(hash string) error {
	// msgGetData := wire.NewMsgGetData()
	// hashstruct, _ := chainhash.NewHashFromStr(hash)
	// msgGetData.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, hashstruct))
	// return p.sendMsg(msgGetData)
	return nil
}
