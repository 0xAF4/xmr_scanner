package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

type NotifierMock struct{}

var timeForFilename = time.Now().Format("15-04-05_02.01.2006") // ЧЧ-ММ-СС_ДД.ММ.ГГГГ

func (n *NotifierMock) NotifyWithLevel(message string, level string) error {
	// Форматируем временнУю метку
	timestamp := time.Now().Format("15:04:05 02.01.2006")
	logEntry := "[" + timestamp + "] [NOTIFY] " + level + ": " + message

	// Выводим в консоль
	fmt.Println(logEntry)

	// Записываем в файл
	filename := fmt.Sprintf("notification_%s.log", timeForFilename)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		// Если не удалось открыть файл, хотя бы выведем ошибку в консоль
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		return nil
	}
	defer file.Close()

	// Используем log для удобной записи
	logger := log.New(file, "", 0)
	logger.Println(logEntry)

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
