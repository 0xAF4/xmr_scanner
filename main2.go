package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Monero P2P протокол константы
const (
	MONERO_P2P_SIGNATURE      = 0x0101010101012101
	MONERO_P2P_HANDSHAKE_FLAG = 0x01
	MONERO_P2P_PING           = 1000
	MONERO_P2P_NEW_BLOCK      = 2001
	MONERO_P2P_NEW_TXS        = 2002
)

// P2P сообщение структура
type P2PMessage struct {
	Signature uint64
	Size      uint64
	Command   uint32
	Data      []byte
}

// Handshake структура (упрощенная)
type HandshakeData struct {
	NetworkID    [16]byte
	MyPort       uint32
	PeerID       uint64
	SupportFlags uint32
}

// Block notification структура (упрощенная)
type BlockNotification struct {
	BlockHash [32]byte
	Height    uint64
	Timestamp uint64
	TxCount   uint32
}

type MoneroP2PMonitor struct {
	conn           net.Conn
	peerAddresses  []string
	currentPeer    int
	blockHeight    uint64
	mutex          sync.RWMutex
	stopChan       chan struct{}
	reconnectDelay time.Duration
}

func NewMoneroP2PMonitor(peers []string) *MoneroP2PMonitor {
	return &MoneroP2PMonitor{
		peerAddresses:  peers,
		currentPeer:    0,
		reconnectDelay: 5 * time.Second,
		stopChan:       make(chan struct{}),
	}
}

// Подключение к Monero ноде
func (m *MoneroP2PMonitor) connectToPeer() error {
	if m.currentPeer >= len(m.peerAddresses) {
		m.currentPeer = 0
	}

	address := m.peerAddresses[m.currentPeer]
	log.Printf("Подключение к ноде: %s", address)

	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		m.currentPeer++
		return fmt.Errorf("ошибка подключения к %s: %v", address, err)
	}

	m.conn = conn
	return nil
}

// Отправка handshake
func (m *MoneroP2PMonitor) sendHandshake() error {
	// Создание базового handshake пакета
	handshake := HandshakeData{
		MyPort:       0,
		PeerID:       uint64(time.Now().Unix()),
		SupportFlags: 1,
	}

	// Monero mainnet network ID (упрощенная версия)
	copy(handshake.NetworkID[:], []byte("MoneroMainNet123"))

	// Сериализация handshake данных (упрощенная)
	data := make([]byte, 32)
	copy(data[:16], handshake.NetworkID[:])
	binary.LittleEndian.PutUint32(data[16:20], handshake.MyPort)
	binary.LittleEndian.PutUint64(data[20:28], handshake.PeerID)
	binary.LittleEndian.PutUint32(data[28:32], handshake.SupportFlags)

	msg := P2PMessage{
		Signature: MONERO_P2P_SIGNATURE,
		Size:      uint64(len(data)),
		Command:   MONERO_P2P_HANDSHAKE_FLAG,
		Data:      data,
	}

	return m.sendMessage(msg)
}

// Отправка сообщения
func (m *MoneroP2PMonitor) sendMessage(msg P2PMessage) error {
	// Сериализация заголовка
	header := make([]byte, 20)
	binary.LittleEndian.PutUint64(header[0:8], msg.Signature)
	binary.LittleEndian.PutUint64(header[8:16], msg.Size)
	binary.LittleEndian.PutUint32(header[16:20], msg.Command)

	// Отправка заголовка и данных
	if _, err := m.conn.Write(header); err != nil {
		return err
	}

	if len(msg.Data) > 0 {
		if _, err := m.conn.Write(msg.Data); err != nil {
			return err
		}
	}

	return nil
}

// Чтение сообщения
func (m *MoneroP2PMonitor) readMessage() (*P2PMessage, error) {
	// Чтение заголовка (20 байт)
	header := make([]byte, 20)
	if _, err := io.ReadFull(m.conn, header); err != nil {
		return nil, err
	}

	msg := &P2PMessage{
		Signature: binary.LittleEndian.Uint64(header[0:8]),
		Size:      binary.LittleEndian.Uint64(header[8:16]),
		Command:   binary.LittleEndian.Uint32(header[16:20]),
	}

	// Проверка сигнатуры
	if msg.Signature != MONERO_P2P_SIGNATURE {
		return nil, fmt.Errorf("неверная сигнатура: %x", msg.Signature)
	}

	// Чтение данных если есть
	if msg.Size > 0 {
		if msg.Size > 1024*1024 { // Защита от слишком больших сообщений
			return nil, fmt.Errorf("слишком большое сообщение: %d байт", msg.Size)
		}

		msg.Data = make([]byte, msg.Size)
		if _, err := io.ReadFull(m.conn, msg.Data); err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// Обработка нового блока
func (m *MoneroP2PMonitor) handleNewBlock(data []byte) {
	if len(data) < 44 { // Минимальный размер блок-уведомления
		log.Printf("Получено сообщение о новом блоке (размер данных: %d байт)", len(data))
		return
	}

	// Парсинг базовой информации о блоке
	blockNotif := BlockNotification{
		Height:    binary.LittleEndian.Uint64(data[32:40]),
		Timestamp: binary.LittleEndian.Uint64(data[40:48]),
	}

	if len(data) >= 52 {
		blockNotif.TxCount = binary.LittleEndian.Uint32(data[48:52])
	}

	copy(blockNotif.BlockHash[:], data[0:32])

	m.mutex.Lock()
	if blockNotif.Height > m.blockHeight {
		m.blockHeight = blockNotif.Height
	}
	m.mutex.Unlock()

	log.Printf("🆕 НОВЫЙ БЛОК!")
	log.Printf("   Высота: %d", blockNotif.Height)
	log.Printf("   Хеш: %s", hex.EncodeToString(blockNotif.BlockHash[:8]))
	log.Printf("   Время: %s", time.Unix(int64(blockNotif.Timestamp), 0).Format("15:04:05"))
	if blockNotif.TxCount > 0 {
		log.Printf("   Транзакций: %d", blockNotif.TxCount)
	}
	log.Printf("   ---")
}

// Отправка ping сообщения
func (m *MoneroP2PMonitor) sendPing() error {
	timestamp := uint64(time.Now().Unix())
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, timestamp)

	msg := P2PMessage{
		Signature: MONERO_P2P_SIGNATURE,
		Size:      8,
		Command:   MONERO_P2P_PING,
		Data:      data,
	}

	return m.sendMessage(msg)
}

// Основной цикл мониторинга
func (m *MoneroP2PMonitor) startMonitoring(ctx context.Context) error {
	log.Printf("Запуск мониторинга сети Monero...")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.stopChan:
			return nil
		default:
		}

		// Подключение к ноде
		if err := m.connectToPeer(); err != nil {
			log.Printf("Ошибка подключения: %v", err)
			time.Sleep(m.reconnectDelay)
			continue
		}

		log.Printf("Подключен к %s", m.peerAddresses[m.currentPeer])

		// Отправка handshake
		if err := m.sendHandshake(); err != nil {
			log.Printf("Ошибка handshake: %v", err)
			m.conn.Close()
			time.Sleep(m.reconnectDelay)
			continue
		}

		log.Printf("Handshake выполнен успешно")

		// Запуск ping горутины
		pingTicker := time.NewTicker(30 * time.Second)
		go func() {
			for {
				select {
				case <-pingTicker.C:
					if err := m.sendPing(); err != nil {
						log.Printf("Ошибка ping: %v", err)
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		// Основной цикл чтения сообщений
		for {
			select {
			case <-ctx.Done():
				pingTicker.Stop()
				return nil
			default:
			}

			// Установка timeout для чтения
			m.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

			msg, err := m.readMessage()
			if err != nil {
				log.Printf("Ошибка чтения сообщения: %v", err)
				break
			}

			// Обработка различных типов сообщений
			switch msg.Command {
			case MONERO_P2P_NEW_BLOCK:
				m.handleNewBlock(msg.Data)
			case MONERO_P2P_NEW_TXS:
				log.Printf("Получено уведомление о новых транзакциях")
			case MONERO_P2P_PING:
				log.Printf("Получен ping от ноды")
			default:
				log.Printf("Получено сообщение: команда %d, размер %d", msg.Command, msg.Size)
			}
		}

		pingTicker.Stop()
		m.conn.Close()
		log.Printf("Соединение разорвано, переподключение через %v", m.reconnectDelay)
		time.Sleep(m.reconnectDelay)
	}
}

// Остановка мониторинга
func (m *MoneroP2PMonitor) Stop() {
	close(m.stopChan)
	if m.conn != nil {
		m.conn.Close()
	}
}

// Получение текущей высоты блока
func (m *MoneroP2PMonitor) GetCurrentHeight() uint64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.blockHeight
}

func main1() {
	// Список публичных Monero нод для подключения
	peers := []string{
		"node.moneroworld.com:18080",
		"nodes.hashvault.pro:18080",
		"node.community.rino.io:18080",
		"p2pmd.xmrvsbeast.com:18080",
		"node-de.monero.net:18080",
	}

	log.Printf("🚀 Monero P2P Block Monitor запущен")
	log.Printf("Настроенные ноды: %v", peers)

	// Создание монитора
	monitor := NewMoneroP2PMonitor(peers)

	// Контекст для graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Обработка сигналов для корректного завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("Получен сигнал завершения...")
		cancel()
		monitor.Stop()
	}()

	// Запуск мониторинга
	if err := monitor.startMonitoring(ctx); err != nil {
		log.Fatalf("Ошибка мониторинга: %v", err)
	}

	log.Printf("Мониторинг завершен")
}
