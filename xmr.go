package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cirocosta/go-monero/pkg/levin"
)

/*
	Сценарий использования следующий:
		Сначало создается новый экземпляр с помощью NewPeer
		После чего идет соединение с нодой, которое можно вызвать вручную вызвав функцию Connect, либо вызов пройдет в MainLoop
		После чего можно запустить главный цикл, который будет обрабатывать сообщения и отправлять запросы на получение блоков
		Также есть два дополнительных цикла, которые будут отправлять запросы на получение данных о блоках и записывать их в БД
		Все методы, которые начинаются с request - отправляют запросы на получение данных
		Все методы, которые начинаются с insert - записывают данные в БД
		На этом все

	**Для адекватного старта нужно в базе указаьб порядковый номер и хэш последнего блока, который был обработан.
		Также нужно указать ноды, с которых будет происходить сканирование.
*/

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

// const (
// 	btcnet  = wire.MainNet
// 	btcpver = wire.ProtocolVersion
// )

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

func (p *ScannerXMR) Connect() error {
	p.node = p.nodelist.GetRandomNode()
	p.n.NotifyWithLevel("Connecting to the node: "+p.node, LevelWarning)

	ctx := context.Background()
	conn, err := levin.NewClient(ctx, p.node)
	if err != nil {
		p.n.NotifyWithLevel("Connecting to the node, error: "+p.node, LevelError)
		return err
	}
	p.conn = conn

	_, err = p.conn.Handshake(ctx)
	if err != nil {
		p.n.NotifyWithLevel("Handshake error: "+err.Error(), LevelError)
		return err
	}
	p.n.NotifyWithLevel("Connected to host: "+p.node, LevelInfo)

	go func() {
		time.Sleep(time.Second * 5)
		p.n.NotifyWithLevel("Request PING", LevelSuccess)
		p.conn.SendRequest(levin.CommandPing, p.conn.NilPayload())
	}()

	p.connected = true
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

func (p *ScannerXMR) Close() {
	p.destroy = true
}

/*--- Loop Methods ---*/
func (p *ScannerXMR) MainLoop() { //3
	// go p.GetBlockDataLoop()
	// go p.WriteBlockToDBLoop()
	go p.KeepConnectionLoop()
	go p.ReadStreamLoop()
}

func (p *ScannerXMR) ReadStreamLoop() {
	p.n.NotifyWithLevel("Started reader", LevelWarning)
	for !p.destroy {
		if p.connected {
			header, raw, err := p.conn.ReadMessage()
			if err != nil {
				p.Disconnect(err)
			} else {
				p.showHeader(header)
				if err := p.handleMessage(header, raw); err != nil {
					p.n.NotifyWithLevel(fmt.Sprintf("2 Error(143 line): %s", err.Error()), LevelError)
				}
			}
		}
		time.Sleep(time.Millisecond * 200)
	}
}

/*--- Message Handlers ---*/
func (p *ScannerXMR) handleMessage(header *levin.Header, raw *levin.PortableStorage) error { //msg wire.Message
	ping := func(header *levin.Header) error {
		if header.Flags == levin.LevinPacketReponse {
			if header.ReturnCode >= 0 {
				p.n.NotifyWithLevel("GET PONG WITH SUCCESS", LevelSuccess)
			} else {
				p.n.NotifyWithLevel(fmt.Sprintf("GET PONG WITH ERROR::%d", header.ReturnCode), LevelError)
			}
		} else {
			if header.ExpectsResponse {
				p.conn.SendResponse(levin.CommandPing, p.conn.NilPayload())
			}
		}
		return nil
	}

	timedsync := func(header *levin.Header, raw *levin.PortableStorage) error {
		if header.ExpectsResponse {
			payload := (&levin.PortableStorage{
				Entries: []levin.Entry{
					{
						Name: "payload_data",
						Serializable: &levin.Section{
							Entries: []levin.Entry{
								{
									Name:         "current_height",
									Serializable: levin.BoostUint64(p.lastBlockHeight),
								},
								{
									Name:         "top_id",
									Serializable: levin.BoostString(p.lastBlockHash),
								},
							},
						},
					},
				},
			}).Bytes()
			p.conn.SendResponse(levin.CommandTimedSync, payload)
		}
		return nil
	}

	newblock := func(header *levin.Header, raw *levin.PortableStorage) error {
		go func() {
			for _, e := range raw.Entries {
				if e.Name == "block_ids" {
					if hashes, err := ProcessBlockIds(e.Value); err == nil {
						for _, hash := range hashes {
							p.blocks.Add(hash, &Block{
								Hash:     hash,
								sended:   false,
								received: false,
							})
						}
					}
				}
			}
		}()
		return nil
	}

	// newtx := func(header *levin.Header, raw *levin.PortableStorage) error {
	// 	if !header.ExpectsResponse && header.Flags == 1 {
	// 		if header.ReturnCode >= 0 {
	// 			p.n.NotifyWithLevel("New TX Searching Message", LevelGray)
	// 		} else {
	// 			p.n.NotifyWithLevel(fmt.Sprintf("New TX Searching Message ERROR::%d", header.ReturnCode), LevelGray)
	// 		}
	// 	}
	// 	return nil
	// }

	// sync := func(header *levin.Header, raw *levin.PortableStorage) error {
	// 	payload := (&levin.PortableStorage{
	// 		Entries: []levin.Entry{
	// 			{
	// 				Name:         "start_height",
	// 				Serializable: levin.BoostUint64(p.lastBlockHeight),
	// 			},
	// 			{
	// 				Name:         "total_height",
	// 				Serializable: levin.BoostUint64(p.lastBlockHeight),
	// 			},
	// 		},
	// 	}).Bytes()
	// 	p.conn.SendRequest(levin.NotifyResponseChainEntry, payload)
	// 	return nil
	// }

	// syncresponse := func(header *levin.Header) error {
	// 	if !header.ExpectsResponse && header.Flags == 2 {
	// 		if header.ReturnCode >= 0 {
	// 			p.n.NotifyWithLevel("SYNC RESPONSE SUCCESS", LevelSuccess)
	// 		} else {
	// 			p.n.NotifyWithLevel(fmt.Sprintf("SYNC RESPONSE ERROR::%d", header.ReturnCode), LevelError)
	// 		}
	// 	}
	// 	return nil
	// }

	// p.purple(header)
	switch header.Command {
	case levin.CommandPing:
		return ping(header)
	case levin.CommandTimedSync:
		p.n.NotifyWithLevel("Timed sync find", LevelWarning)
		return timedsync(header, raw)
	case levin.NotifyNewBlock:
		return newblock(header, raw)
	// case levin.NotifyNewTransaction:
	// 	return newtx(header, raw)
	// case levin.NotifyRequestChain:
	// 	return sync(header, raw)
	// case levin.NotifyResponseChainEntry:
	// 	return syncresponse(header)
	default:
		p.n.NotifyWithLevel("Unhandeled message", LevelGray)
		return nil
	}
}
