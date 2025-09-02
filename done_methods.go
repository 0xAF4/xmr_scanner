package main

import (
	"fmt"
	"time"

	"github.com/cirocosta/go-monero/pkg/levin"
)

const (
	LevelInfo    = "🔵INFO🔵"
	LevelSuccess = "🟢SUCCESS🟢"
	LevelWarning = "🟡WARNING🟡"
	LevelError   = "🔴ERROR🔴"
	LevelGray    = "⚫INFO⚫"
)

func (p *ScannerXMR) SetPeers(pers map[string]*levin.Peer) {
	var list Nodelist
	for _, node := range pers {
		list = append(list, fmt.Sprintf("%s:%d", node.Ip, node.Port))
	}
	p.nodelist = &list
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
