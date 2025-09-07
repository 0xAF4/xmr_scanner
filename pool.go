package main

import (
	"sync"
	"time"
)

type Block struct {
	Hash         string
	PreviousHash string
	Timestamp    time.Time
	Bits         uint32
	Nonce        uint32
	Transactions interface{} //[]*wire.MsgTx
	sended       bool
	received     bool
	chainName    string
}

type Pool struct {
	chain map[string]*Block
	wu    sync.Mutex
}

func NewPool() *Pool {
	return &Pool{
		chain: make(map[string]*Block),
	}
}

func (p *Pool) Add(key string, value *Block) {
	p.wu.Lock()
	defer p.wu.Unlock()

	p.chain[key] = value
}

func (p *Pool) Delete(key string) {
	p.wu.Lock()
	defer p.wu.Unlock()

	delete(p.chain, key)
}

func (p *Pool) Range(iterate func(key string, value *Block) bool) {
	p.wu.Lock()
	defer p.wu.Unlock()

	for key, value := range p.chain {
		if !iterate(key, value) {
			return
		}
	}
}

func (p *Pool) Count() int {
	return len(p.chain)
}

func (p *Pool) SetSendedFalse() {
	for key, value := range p.chain {
		if !value.received {
			value.sended = false
			p.chain[key] = value
		}
	}
}

func (b *Block) GetChainName() string {
	return b.chainName
}

func (b *Block) ConvertToDBBlock() interface{} {
	return nil
}
