package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type NotifierMock struct{}

// var timeForFilename = time.Now().Format("15-04-05_02.01.2006") // ЧЧ-ММ-СС_ДД.ММ.ГГГГ
var timeForFilename = "1"

func (n *NotifierMock) NotifyWithLevel(message string, level string) error {
	// Форматируем временную метку
	timestamp := time.Now().Format("15:04:05 02.01.2006")
	logEntry := "[" + timestamp + "] [NOTIFY] " + level + ": " + message

	// Выводим в консоль
	fmt.Println(logEntry)

	// Убедимся, что директория logs существует
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
		return err
	}

	// Формируем путь к файлу в logs
	filename := fmt.Sprintf("notification_%s.log", timeForFilename)
	filepath := filepath.Join(logDir, filename)

	// Открываем файл
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		return err
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

func main2() {
	scanner, err := New(coin, BotMock, DBMock)
	if err != nil {
		log.Fatalf("ERROR Scanner(%s): %v", coin, err)
	}
	defer scanner.Close()
	scanner.RunLoop()
	select {}
}
