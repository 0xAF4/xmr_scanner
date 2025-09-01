package main

type bScanner struct {
	Scanner
}

type Scanner interface {
	Close()
	Connect() error
	MainLoop()
}

type Notifier interface {
	NotifyWithLevel(message string, level string) error
}

type DBWrapper interface {
	GetNodeAddrs(coin string) (*Nodelist, error)
	GetChainHeight(coin string) (int32, string, error)
	ProcessBlock(chainName string, block interface{}) error
}

func New(coin string, n Notifier, d DBWrapper) (*bScanner, error) {
	scn := bScanner{}
	nodes, err := d.GetNodeAddrs(coin)
	if err != nil {
		return nil, err
	}

	height, hash, err := d.GetChainHeight(coin)
	if err != nil {
		return nil, err
	}

	switch coin {
	case "XMR":
		scn.Scanner = NewScannerXMR(nodes, height, hash, n, d, coin)
	default:
		scn.Scanner = nil
	}

	// if scn.Scanner != nil {
	// 	err = scn.Scanner.Connect()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	return &scn, nil
}

func (s bScanner) RunLoop() {
	if s.Scanner != nil {
		s.Scanner.MainLoop()
	}
}

func (s bScanner) Close() {
	s.Scanner.Close()
}
