package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"xmr_scanner/levin"
)

type ScannerXMR struct {
	nodelist         *Nodelist
	node             string
	lastBlockHeight  int32
	lastBlockHash    string
	lashBlockHashArr map[int32]string

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
	peer_id   uint64
}

const (
	LevelInfo    = "🔵INFO🔵"
	LevelSuccess = "🟢SUCCESS🟢"
	LevelWarning = "🟡WARNING🟡"
	LevelError   = "🔴ERROR🔴"
	LevelGray    = "⚫INFO⚫"
)

func (p *ScannerXMR) GenerateSequence() {
	currentHeight := p.lastBlockHeight

	sequence := make([]int32, 0, 28) // 11 + 16 + 1 = 28 элементов

	// Шаг 1: 11 чисел, уменьшаем на 1 (включая начальное)
	current := currentHeight
	for i := 0; i < 11; i++ {
		sequence = append(sequence, current)
		current--
	}

	// Теперь current = начальное - 11
	// Но нам нужно начать вычитать степени двойки с (currentHeight - 10)
	// То есть последнее значение в линейной фазе: currentHeight - 10
	// В коде выше: после 11 итераций current = currentHeight - 11
	// Значит, последнее добавленное число: currentHeight - 10
	// → следующее значение для обработки: currentHeight - 10

	startExp := currentHeight - 10 // Это последнее число линейной фазы

	// Шаг 2: вычитаем 2^1, 2^2, ..., 2^16
	powerOfTwo := int32(2)
	for i := 0; i < 16; i++ {
		startExp -= powerOfTwo
		sequence = append(sequence, startExp)
		powerOfTwo *= 2 // 2, 4, 8, 16, ...
	}

	// Шаг 3: финальный переход к 0
	sequence = append(sequence, 0)

	// Теперь заполняем словарь: map[int32]string
	// Предположим, что p.lashBlockHashArr объявлен как:
	// lashBlockHashArr map[int32]string

	// Если ещё не инициализирован — инициализируем
	if p.lashBlockHashArr == nil {
		p.lashBlockHashArr = make(map[int32]string)
	}

	// Очищаем перед заполнением (если может вызываться повторно)
	// Или можно не очищать, если нужно кэшировать
	for _, height := range sequence {
		// Пока ставим пустую строку — позже подставим реальные хеши
		p.lashBlockHashArr[height] = "" // или "pending", или оставить пустым
	}
}

func (p *ScannerXMR) GetXMRChain(height int32) (*string, error) {
	resp, err := http.Get(fmt.Sprintf("https://xmrchain.net/search?value=%d", height))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	html := string(body)
	return &html, nil
}

/*--- Basic Methods ---*/
func NewScannerXMR(nl *Nodelist, startHeight int32, hash string, n Notifier, d DBWrapper, c string) *ScannerXMR { //1
	scanner := &ScannerXMR{
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
		peer_id:         uint64(time.Now().Unix()),
	}
	scanner.GenerateSequence()
	scanner.lashBlockHashArr[scanner.lastBlockHeight] = scanner.lastBlockHash
	scanner.lashBlockHashArr[0] = levin.MainnetGenesisTx
	return scanner
}

func (p *ScannerXMR) Close() {
	p.destroy = true
}

func (p *ScannerXMR) Connect() error {
	//Получение хэщей по API
	{
	repeat:
		var wg sync.WaitGroup
		errs := 0
		for key, val := range p.lashBlockHashArr {
			if val == "" {
				wg.Add(1)
				go func() {
					defer wg.Done()
					html, err := p.GetXMRChain(key)
					if err != nil {
						errs += 1
						return
					}
					pattern := fmt.Sprintf(`Block hash \(height\): ([a-f0-9]{64}) \(%d\)`, key)
					re := regexp.MustCompile(`(?i)<h4.*?>` + pattern + `</h4>`)
					matches := re.FindStringSubmatch(*html)

					if len(matches) >= 2 {
						p.n.NotifyWithLevel(fmt.Sprintf("Set hash for key: %d", key), LevelSuccess)
						p.lashBlockHashArr[key] = matches[1]
					} else {
						errs += 1
					}
				}()
			}
		}
		wg.Wait()

		if errs > 0 {
			p.n.NotifyWithLevel("Не все хэши были получены, сейчас повторим", LevelError)
			goto repeat
		} else {
			p.n.NotifyWithLevel("Все хэши были получены", LevelSuccess)
			// for key, val := range p.lashBlockHashArr {
			// 	fmt.Println("Key:", key, "Val:", val)
			// }
		}
	}

	p.node = p.nodelist.GetRandomNode()
	p.n.NotifyWithLevel(fmt.Sprintf("Nodes count: %d; Connecting to the node: %s", len(*p.nodelist), p.node), LevelWarning)

	conn, err := levin.NewClient(p.node)
	if err != nil {
		p.n.NotifyWithLevel("Connecting to the node, error: "+p.node, LevelError)
		return err
	}
	p.conn = conn

	pl, err := p.conn.Handshake(uint64(p.lastBlockHeight), p.lastBlockHash, p.peer_id)
	if err != nil {
		p.n.NotifyWithLevel("Handshake error: "+err.Error(), LevelError)
		return err
	}

	if pl.CurrentHeight == 1 {
		return errors.New("Height equal '1', chain not synced")
	}

	p.n.NotifyWithLevel(fmt.Sprintf("Connected to host: %s; Current Height: %d; Peers count: %d", p.node, pl.CurrentHeight, len(pl.GetPeers())), LevelSuccess)
	p.SetPeers(pl.GetPeers())

	if p.blocks.Count() == 0 {
		p.n.NotifyWithLevel("Request queue for sync", LevelInfo)
		p.SendRequestChain()
	} else {
		p.blocks.SetSendedFalse()
	}

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
				paylaod := (&levin.PortableStorage{
					Entries: []levin.Entry{
						{
							Name:         "status",
							Serializable: levin.BoostString("OK"),
						},
						{
							Name:         "peer_id",
							Serializable: levin.BoostUint64(p.peer_id),
						},
					},
				}).Bytes()
				p.conn.SendResponse(levin.CommandPing, paylaod)
			}
		}
		return nil
	}

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

	processqueue := func(header *levin.Header, raw *levin.PortableStorage) error {
		for _, entry := range raw.Entries {
			if entry.Name == "m_block_ids" {
				if hashes, err := ProcessBlockIds(entry.Value); err == nil {
					previosHash := p.lastBlockHash
					for _, hash := range hashes {
						if hash == p.lastBlockHash {
							continue
						}
						b := Block{
							sended:       false,
							received:     false,
							Hash:         hash,
							PreviousHash: previosHash,
						}
						p.blocks.Add(hash, &b)
						previosHash = hash
						p.n.NotifyWithLevel(fmt.Sprintf("Block Hash: %s, Previous Hash: %s", b.Hash, b.PreviousHash), LevelSuccess)

					}
				}
			}
		}
		return nil
	}

	processblocks := func(header *levin.Header, raw *levin.PortableStorage) error {
		for _, entry := range raw.Entries {
			if entry.Name == "blocks" {
				for _, blk := range entry.Entries() {
					block := levin.NewBlock()
					for _, ibl := range blk.Entries() {
						if ibl.Name == "block" {
							block.SetBlockData([]byte(ibl.String()))
						} else {
							for _, itx := range ibl.Entries() {
								block.InsertTx([]byte(itx.String()))
							}
						}
					}
					// p.n.NotifyWithLevel(fmt.Sprintf("block len: %d", len(block.block)), LevelSuccess)
					for _, tx := range block.TXs {
						p.n.NotifyWithLevel(fmt.Sprintf(" - tx len: %d", len(tx.Raw)), LevelSuccess)
					}
					p.n.NotifyWithLevel("=====", LevelSuccess)
				}
			}
		}
		return nil
	}

	switch header.Command {
	case levin.CommandPing: // <- DONE
		return ping(header)
	case levin.CommandTimedSync: // <- DONE
		return timedsync(header, raw)
	case levin.NotifyResponseChainEntry: // <- DONE
		return processqueue(header, raw)
	case levin.NotifyResponseGetObjects:
		return processblocks(header, raw)
	default:
		p.n.NotifyWithLevel(fmt.Sprintf("Unhandeled message::%d", header.Command), LevelGray)
		p.showHeader(header)
		return nil
	}
}

/*--- Loop Methods ---*/
func (p *ScannerXMR) MainLoop() { //3
	go p.GetBlockDataLoop()
	// go p.WriteBlockToDBLoop()
	go p.KeepConnectionLoop()
	go p.ReadStreamLoop()
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

func (p *ScannerXMR) GetBlockHashes() []string {
	// Получаем количество элементов
	n := len(p.lashBlockHashArr)
	if n == 0 {
		return []string{}
	}

	// Шаг 1: собрать ключи (высоты)
	keys := make([]int32, 0, n)
	for height := range p.lashBlockHashArr {
		keys = append(keys, height)
	}

	// Шаг 2: отсортировать по убыванию
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] > keys[j] // от большего к меньшему
	})

	// Шаг 3: собрать хеши в порядке отсортированных ключей
	hashes := make([]string, 0, n)
	for _, height := range keys {
		hash := p.lashBlockHashArr[height]
		// Можно добавлять только если хеш не пустой
		if hash != "" {
			hashes = append(hashes, hash)
		}
	}

	return hashes
}

func (p *ScannerXMR) SendRequestChain() {
	p.n.NotifyWithLevel("SendNotifyRequestChain", LevelSuccess)
	balbik := (&levin.PortableStorage{
		Entries: []levin.Entry{
			{
				Name:         "block_ids",
				Serializable: levin.BoostBlockIds(p.GetBlockHashes()),
			},
		},
	}).Bytes()

	p.conn.SendRequest(levin.NotifyRequestChain, balbik)
}

const packetsize = 10 // 100

func (p *ScannerXMR) GetBlockDataLoop() {
	for !p.destroy {
		time.Sleep(time.Second * 3)
		if p.blocks.Count() == 0 {
			continue
		}

		//TODO: По идее надо собирать пакеты по сто блоков и так их отрпавлять
		lst := make(map[string]string)
		prevHash := p.lastBlockHash
		blocks := []string{}

		p.blocks.Range(func(key string, value *Block) bool {
			if !value.sended {
				lst[value.PreviousHash] = key
			}
			return true
		})

		for i := 0; i < packetsize; i++ {
			val := lst[prevHash]
			if val == "" {
				break
			}
			blocks = append(blocks, val)
			prevHash = val
		}

		if len(blocks) == 0 {
			continue
		}

		for i, val := range blocks {
			p.n.NotifyWithLevel(fmt.Sprintf("I: %d, val: %s", i, val), LevelGray)
		}

		p.n.NotifyWithLevel("RequestBlocks", LevelSuccess)
		bulbik := (&levin.PortableStorage{
			Entries: []levin.Entry{
				{
					Name:         "blocks",
					Serializable: levin.BoostBlock(blocks),
				},
			},
		}).Bytes()

		err := p.conn.SendRequest(levin.NotifyRequestGetObjects, bulbik)
		if err == nil {
			incblocks := 0
			p.blocks.Range(func(key string, value *Block) bool {
				if slices.Contains(blocks, key) {
					value.sended = true
					incblocks += 1
				}

				if incblocks == packetsize {
					return false
				}
				return true
			})
		}

	}
}
