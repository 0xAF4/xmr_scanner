package main

import (
	"encoding/hex"
	"encoding/json"
)

type Hash [32]byte
type HByte byte
type ByteArray []byte

func (h Hash) MarshalJSON() ([]byte, error) {
	hexStr := hex.EncodeToString(h[:])
	return json.Marshal(hexStr) // оборачиваем в кавычки
}

func (b HByte) MarshalJSON() ([]byte, error) {
	hexStr := hex.EncodeToString([]byte{byte(b)})
	return json.Marshal(hexStr)
}

func (b ByteArray) MarshalJSON() ([]byte, error) {
	// ❗️Главная ошибка, которую делают — маршалят сам `b`, а не сконвертированный срез
	ints := make([]int, len(b))
	for i, v := range b {
		ints[i] = int(v)
	}
	return json.Marshal(ints)
}
