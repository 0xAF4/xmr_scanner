package main

import (
	"fmt"
	"time"

	"github.com/cirocosta/go-monero/pkg/levin"
)

type ScannerXMR struct {
	nodelist        *Nodelist
	node            string
	lastBlockHeight int32
	lastBlockHash   string

	connected bool
	destroy   bool
	uptime    time.Time
	blocks    *Pool

	n  Notifier
	db DBWrapper

	peerVersion int32
	serviceInfo string

	conn      *levin.Client
	chainName string
}

/*--- Basic Methods ---*/
func NewScannerXMR(nl *Nodelist, startHeight int32, hash string, n Notifier, d DBWrapper, c string) *ScannerXMR { //1
	return &ScannerXMR{
		nodelist:        nl,
		lastBlockHeight: startHeight,
		lastBlockHash:   hash,
		uptime:          time.Now(),
		connected:       false,
		destroy:         false,
		blocks:          NewPool(),
		n:               n,
		db:              d,
		chainName:       c,
	}
}

func (p *ScannerXMR) Connect() error {
	p.node = p.nodelist.GetRandomNode()
	p.n.NotifyWithLevel(fmt.Sprintf("Nodes count: %d; Connecting to the node: %s", len(*p.nodelist), p.node), LevelWarning)

	conn, err := levin.NewClient(p.node)
	if err != nil {
		p.n.NotifyWithLevel("Connecting to the node, error: "+p.node, LevelError)
		return err
	}
	p.conn = conn

	pl, err := p.conn.Handshake()
	if err != nil {
		p.n.NotifyWithLevel("Handshake error: "+err.Error(), LevelError)
		return err
	}
	p.n.NotifyWithLevel(fmt.Sprintf("Connected to host: %s; Current Height: %d; Peers count: %d", p.node, pl.CurrentHeight, len(pl.GetPeers())), LevelSuccess)
	p.SetPeers(pl.GetPeers())

	p.connected = true
	// go func() {
	// 	for p.connected {
	p.n.NotifyWithLevel("Request Timed Sync", LevelSuccess)
	p.conn.SendRequest(levin.CommandTimedSync, levin.NewRequestTimedSync(uint64(p.lastBlockHeight), p.lastBlockHash).Bytes())
	// 		time.Sleep(time.Second * 40)
	// 	}
	// }()

	return nil
}

/*--- Loop Methods ---*/
func (p *ScannerXMR) MainLoop() { //3
	// go p.GetBlockDataLoop()
	// go p.WriteBlockToDBLoop()
	go p.KeepConnectionLoop()
	go p.ReadStreamLoop()
	go p.KeepTimeSync()
}

/*--- Message Handlers ---*/
func (p *ScannerXMR) handleMessage(header *levin.Header, raw *levin.PortableStorage) error { //msg wire.Message
	ping := func(header *levin.Header) error {
		if header.Flags == levin.LevinPacketReponse {
			if levin.IsValidReturnCode(header.ReturnCode) {
				// pong := levin.NewPingFromPortableStorage(raw)
				p.n.NotifyWithLevel("GET PONG WITH SUCCESS", LevelSuccess)
			} else {
				p.n.NotifyWithLevel(fmt.Sprintf("GET PONG WITH ERROR::%d", header.ReturnCode), LevelError)
			}
		} else {
			if header.ExpectsResponse {
				p.conn.SendResponse(levin.CommandPing, levin.NilPayload())
			}
		}
		return nil
	}
	_ = ping

	timedsync := func(header *levin.Header, raw *levin.PortableStorage) error {
		if header.Flags == levin.LevinPacketReponse {
			if levin.IsValidReturnCode(header.ReturnCode) {
				p.n.NotifyWithLevel("GET TIMED SYNC RESPONSE SUCCESS", LevelSuccess)
			} else {
				p.n.NotifyWithLevel(fmt.Sprintf("GET TIMED SYNC RESPONSE ERROR::%d", header.ReturnCode), LevelError)
			}
		} else {
			p.n.NotifyWithLevel("SEND TIMED SYNC RESPONSE", LevelWarning)
			p.conn.SendResponse(levin.CommandTimedSync, levin.NewRequestTimedSync(uint64(p.lastBlockHeight), p.lastBlockHash).Bytes())
		}
		return nil
	}
	_ = timedsync

	requestchain := func(header *levin.Header, raw *levin.PortableStorage) error {
		if header.Flags == levin.LevinPacketRequest && header.ExpectsResponse == false {
			p.n.NotifyWithLevel("Request chain", LevelSuccess)
			for _, entry := range raw.Entries {
				p.n.NotifyWithLevel("	- Entry Name: "+entry.Name, LevelSuccess)
				if entry.Name == "block_ids" {
					if hashes, err := ProcessBlockIds(entry.Value); err == nil {
						for _, hash := range hashes {
							p.n.NotifyWithLevel("		- Hash str: "+hash, LevelSuccess)
						}
					}
				}
				p.n.NotifyWithLevel("	- Entry Name: "+entry.Name, LevelSuccess)
			}
		}
		return nil
	}
	_ = requestchain

	newblock := func(header *levin.Header, raw *levin.PortableStorage) error {
		go func() {
			for _, entry := range raw.Entries {
				p.n.NotifyWithLevel(" -- Entry: "+entry.Name, LevelSuccess)
				if entry.Name == "b" {
					// block blob here
				} else if entry.Name == "current_blockchain_height" {
					p.n.NotifyWithLevel(fmt.Sprintf("Current Blockchain Height: %d", entry.Uint64()), LevelSuccess)
				}
			}
		}()
		return nil
	}
	_ = newblock

	newtx := func(header *levin.Header, raw *levin.PortableStorage) error {
		return nil
	}
	_ = newtx

	switch header.Command {
	case levin.CommandPing: // <- DONE
		return ping(header)
	case levin.CommandTimedSync: // <- DONE
		return timedsync(header, raw)

	case levin.NotifyNewTransaction:
		p.showHeader(header)
		return nil
		// return newtx(header, raw)
	case levin.NotifyRequestChain:
		p.showHeader(header)
		return nil
		// return requestchain(header, raw)
	// case levin.NotifyNewFluffyBlock:
	// 	p.showHeader(header)
	// 	return newblock(header, raw)
	default:
		// p.showHeader(header)
		p.n.NotifyWithLevel(fmt.Sprintf("Unhandeled message::%d", header.Command), LevelGray)
		return nil
	}
}
