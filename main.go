package main

import (
	"fmt"
	"log"
)

type NotifierMock struct{}

type Tx struct {
	TxId    string
	Vout    int
	Address string
	Balance float64
}

func (n *NotifierMock) NotifyWithLevel(message string, level string) error {
	fmt.Println("[NOTIFY] " + level + ": " + message)
	return nil
}

var (
	coin    = "XMR"
	BotMock = &NotifierMock{}
	DBMock  = &DatabaseMock{}
)

func main() {
	scanner, err := New(coin, BotMock, DBMock)
	if err != nil {
		log.Fatalf("ERROR Scanner(%s): %v", coin, err)
	}
	defer scanner.Close()
	scanner.RunLoop()
	select {}
}
