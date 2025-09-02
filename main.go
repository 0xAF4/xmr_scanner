package main

import (
	"fmt"
	"log"
	"time"
)

type NotifierMock struct{}

func (n *NotifierMock) NotifyWithLevel(message string, level string) error {
	timestamp := time.Now().Format("15:04:05 02.01.2006")
	fmt.Println("[" + timestamp + "] [NOTIFY] " + level + ": " + message)
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
