package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"xmr_scanner/levin"
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

const (
	LevelInfo    = "🔵INFO🔵"
	LevelSuccess = "🟢SUCCESS🟢"
	LevelWarning = "🟡WARNING🟡"
	LevelError   = "🔴ERROR🔴"
	LevelGray    = "⚫INFO⚫"
)

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

func (p *ScannerXMR) Close() {
	p.destroy = true
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

	pl, err := p.conn.Handshake(uint64(p.lastBlockHeight), p.lastBlockHash)
	if err != nil {
		p.n.NotifyWithLevel("Handshake error: "+err.Error(), LevelError)
		return err
	}
	p.n.NotifyWithLevel(fmt.Sprintf("Connected to host: %s; Current Height: %d; Peers count: %d", p.node, pl.CurrentHeight, len(pl.GetPeers())), LevelSuccess)
	p.SetPeers(pl.GetPeers())

	p.connected = true
	p.n.NotifyWithLevel("Request Timed Sync", LevelSuccess)
	p.conn.SendRequest(levin.CommandTimedSync, levin.NewRequestTimedSync(uint64(p.lastBlockHeight), p.lastBlockHash).Bytes())

	// go func() {
	// 	time.Sleep(time.Second * 3)
	// 	p.conn.SendRequest(levin.NotifyRequestGetObjects, GetBlock())
	// }()

	return nil
}

func (p *ScannerXMR) Disconnect(err error) {
	if p.conn != nil {
		p.conn.Close()
		p.connected = false
		p.n.NotifyWithLevel(fmt.Sprintf("Disconnected from node: %s", p.node), LevelError)
		if err != nil {
			p.n.NotifyWithLevel(fmt.Sprintf("Disconnect Error: %s", err.Error()), LevelError)
		}
	}
}

func (p *ScannerXMR) SetPeers(pers map[string]*levin.Peer) {
	var list Nodelist
	for _, node := range pers {
		list = append(list, fmt.Sprintf("%s:%d", node.Ip, node.Port))
	}
	p.nodelist = &list
}

func GetBlock() []byte {
	return (&levin.PortableStorage{
		Entries: []levin.Entry{
			{
				Name:         "blocks",
				Serializable: levin.BoostString(" 1a572331ddfa81b42de7d41e662b84a9595b487c24e5243943129b84e4f91706"),
			},
		},
	}).Bytes()
}

/*--- Message Handlers ---*/
func (p *ScannerXMR) handleMessage(header *levin.Header, raw *levin.PortableStorage) error { //msg wire.Message
	ping := func(header *levin.Header) error {
		if header.Flags == levin.LevinPacketReponse {
			if levin.IsValidReturnCode(header.ReturnCode) {
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
	// case levin.NotifyRequestChain:
	// 	p.showHeader(header)
	// 	return nil
	// return requestchain(header, raw)
	// case levin.NotifyNewFluffyBlock:
	// 	p.showHeader(header)
	// 	return newblock(header, raw)
	default:
		// p.showHeader(header)
		p.n.NotifyWithLevel(fmt.Sprintf("Unhandeled message::%d", header.Command), LevelGray)
		p.showHeader(header)
		return nil
	}
}

/*--- Loop Methods ---*/
func (p *ScannerXMR) MainLoop() { //3
	// go p.GetBlockDataLoop()
	// go p.WriteBlockToDBLoop()
	go p.KeepConnectionLoop()
	go p.ReadStreamLoop()
	go p.KeepTimeSync()
	go p.SendNotifyRequestChain()
}

func (p *ScannerXMR) KeepConnectionLoop() {
	for !p.destroy {
		if !p.connected {
			p.Connect()
		} else {
			time.Sleep(time.Second * 5)
		}
	}

	if p.destroy {
		p.conn.Close()
	}
}

func (p *ScannerXMR) ReadStreamLoop() {
	for !p.destroy {
		if p.connected {
			if header, raw, err := p.conn.ReadMessage(); err != nil {
				p.Disconnect(err)
			} else {
				p.handleMessage(header, raw)
			}
		}
		time.Sleep(time.Millisecond * 200)
	}
}

func (p *ScannerXMR) KeepTimeSync() {
	for !p.destroy {
		if p.connected {
			p.n.NotifyWithLevel("Request Timed Sync", LevelSuccess)
			p.conn.SendRequest(levin.CommandTimedSync, levin.NewRequestTimedSync(uint64(p.lastBlockHeight), p.lastBlockHash).Bytes())
		}
		time.Sleep(time.Second * 30)
	}
}

func (p *ScannerXMR) SendNotifyRequestChain() {
	for !p.destroy {
		if p.connected {
			p.n.NotifyWithLevel("SendNotifyRequestChain", LevelSuccess)
			byter, _ := hex.DecodeString(p.lastBlockHash)

			balbik := (&levin.PortableStorage{
				Entries: []levin.Entry{
					{
						Name:         "block_ids",
						Serializable: levin.BoostByte(byter),
					},
				},
			}).Bytes()
			p.conn.SendRequest(levin.NotifyRequestChain, balbik)
		}
		time.Sleep(time.Second * 10)
	}
}
