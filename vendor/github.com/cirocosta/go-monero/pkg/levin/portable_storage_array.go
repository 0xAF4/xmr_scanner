package levin

import (
	"bytes"
	"encoding/binary"
)

// ArrayType определяет тип элементов в массиве
type ArrayType byte

const (
	ArrayTypeNil    ArrayType = 0x00
	ArrayTypeUint8  ArrayType = 0x01
	ArrayTypeUint16 ArrayType = 0x02
	ArrayTypeUint32 ArrayType = 0x03
	ArrayTypeUint64 ArrayType = 0x04
	ArrayTypeInt8   ArrayType = 0x05
	ArrayTypeInt16  ArrayType = 0x06
	ArrayTypeInt32  ArrayType = 0x07
	ArrayTypeInt64  ArrayType = 0x08
	ArrayTypeFloat  ArrayType = 0x09
	ArrayTypeDouble ArrayType = 0x0A
	ArrayTypeBool   ArrayType = 0x0B
	ArrayTypeString ArrayType = 0x0C
	ArrayTypeObject ArrayType = 0x0D
	ArrayTypeArray  ArrayType = 0x0E
	ArrayTypeBin    ArrayType = 0x0F
)

// Array представляет массив в формате Portable Storage
type Array struct {
	Type   ArrayType
	Values []Serializable
}

// Bytes сериализует массив в байты согласно формату Portable Storage
func (a *Array) Bytes() []byte {
	var buf bytes.Buffer

	// Записываем тип массива
	buf.WriteByte(byte(a.Type))

	// Записываем количество элементов (4 байта, little-endian)
	countBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBytes, uint32(len(a.Values)))
	buf.Write(countBytes)

	// Сериализуем каждый элемент
	for _, value := range a.Values {
		buf.Write(value.Bytes())
	}

	return buf.Bytes()
}

// BoostStringArray создает массив строк для использования в PortableStorage
func BoostStringArray(values []string) *Array {
	serializables := make([]Serializable, len(values))
	for i, v := range values {
		serializables[i] = BoostString(v)
	}

	return &Array{
		Type:   ArrayTypeString,
		Values: serializables,
	}
}
