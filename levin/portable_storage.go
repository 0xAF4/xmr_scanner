package levin

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	PortableStorageSignatureA    uint32 = 0x01011101
	PortableStorageSignatureB    uint32 = 0x01020101
	PortableStorageFormatVersion byte   = 0x01

	PortableRawSizeMarkMask  byte   = 0x03
	PortableRawSizeMarkByte  byte   = 0x00
	PortableRawSizeMarkWord  uint16 = 0x01
	PortableRawSizeMarkDword uint32 = 0x02
	PortableRawSizeMarkInt64 uint64 = 0x03
)

type Entry struct {
	Name         string
	Serializable Serializable `json:"-,omitempty"`
	Value        interface{}
}

func (e Entry) String() string {
	v, ok := e.Value.(string)
	if !ok {
		panic(fmt.Errorf("interface couldnt be casted to string"))
	}

	return v
}

func (e Entry) Uint8() uint8 {
	v, ok := e.Value.(uint8)
	if !ok {
		panic(fmt.Errorf("interface couldnt be casted to uint8"))
	}

	return v
}

func (e Entry) Uint16() uint16 {
	v, ok := e.Value.(uint16)
	if !ok {
		panic(fmt.Errorf("interface couldnt be casted to uint16"))
	}

	return v
}

func (e Entry) Uint32() uint32 {
	v, ok := e.Value.(uint32)
	if !ok {
		panic(fmt.Errorf("interface couldnt be casted to uint32"))
	}

	return v
}

func (e Entry) Uint64() uint64 {
	v, ok := e.Value.(uint64)
	if !ok {
		panic(fmt.Errorf("interface couldnt be casted to uint64"))
	}

	return v
}

func (e Entry) Entries() Entries {
	v, ok := e.Value.(Entries)
	if !ok {
		panic(fmt.Errorf("interface couldnt be casted to levin.Entries"))
	}

	return v
}

func (e Entry) Bytes() []byte {
	if e.Serializable != nil {
		return e.Serializable.Bytes()
	}

	// Determine type and serialize value
	switch v := e.Value.(type) {
	case uint8:
		return append([]byte{BoostSerializeTypeUint8}, v)

	case uint16:
		result := []byte{BoostSerializeTypeUint16}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, v)
		return append(result, b...)

	case uint32:
		result := []byte{BoostSerializeTypeUint32}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		return append(result, b...)

	case uint64:
		result := []byte{BoostSerializeTypeUint64}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		return append(result, b...)

	case int64:
		result := []byte{BoostSerializeTypeInt64}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(v))
		return append(result, b...)

	case string:
		result := []byte{BoostSerializeTypeString}
		varInB, err := VarIn(len(v))
		if err != nil {
			panic(fmt.Errorf("varin for string length: %w", err))
		}
		result = append(result, varInB...)
		result = append(result, []byte(v)...)
		return result

	case Entries:
		result := []byte{BoostSerializeTypeObject}
		varInB, err := VarIn(len(v))
		if err != nil {
			panic(fmt.Errorf("varin for entries length: %w", err))
		}
		result = append(result, varInB...)
		for _, entry := range v {
			result = append(result, byte(len(entry.Name)))
			result = append(result, []byte(entry.Name)...)
			result = append(result, entry.Bytes()...)
		}
		return result

	default:
		// Check if it's an array by looking at type
		if entries, ok := v.(Entries); ok {
			// Determine array element type based on first element
			if len(entries) == 0 {
				panic(fmt.Errorf("cannot serialize empty array - unknown element type"))
			}

			var elementType byte
			switch entries[0].Value.(type) {
			case uint8:
				elementType = BoostSerializeTypeUint8
			case uint16:
				elementType = BoostSerializeTypeUint16
			case uint32:
				elementType = BoostSerializeTypeUint32
			case uint64:
				elementType = BoostSerializeTypeUint64
			case int64:
				elementType = BoostSerializeTypeInt64
			case string:
				elementType = BoostSerializeTypeString
			case Entries:
				elementType = BoostSerializeTypeObject
			default:
				panic(fmt.Errorf("unsupported array element type: %T", entries[0].Value))
			}

			result := []byte{elementType | BoostSerializeFlagArray}
			varInB, err := VarIn(len(entries))
			if err != nil {
				panic(fmt.Errorf("varin for array length: %w", err))
			}
			result = append(result, varInB...)

			for _, entry := range entries {
				// For arrays, we don't include the type byte for each element
				valueBytes := entry.Bytes()
				// Skip the first byte (type) since it's already specified in array header
				if len(valueBytes) > 1 {
					result = append(result, valueBytes[1:]...)
				}
			}
			return result
		}

		panic(fmt.Errorf("unsupported value type: %T", v))
	}
}

type Entries []Entry

func (e Entries) Bytes() []byte {
	return nil
}

type PortableStorage struct {
	Entries Entries
}

func NewPortableStorageFromBytes(bytes []byte) (*PortableStorage, error) {
	var (
		size = 0
		idx  = 0
	)

	{ // sig-a
		size = 4

		if len(bytes[idx:]) < size {
			return nil, fmt.Errorf("sig-a out of bounds")
		}

		sig := binary.LittleEndian.Uint32(bytes[idx : idx+size])
		idx += size

		if sig != uint32(PortableStorageSignatureA) {
			return nil, fmt.Errorf("sig-a doesn't match")
		}
	}

	{ // sig-b
		size = 4
		sig := binary.LittleEndian.Uint32(bytes[idx : idx+size])
		idx += size

		if sig != uint32(PortableStorageSignatureB) {
			return nil, fmt.Errorf("sig-b doesn't match")
		}
	}

	{ // format ver
		size = 1
		version := bytes[idx]
		idx += size

		if version != PortableStorageFormatVersion {
			return nil, fmt.Errorf("version doesn't match")
		}
	}

	ps := &PortableStorage{}

	_, ps.Entries = ReadObject(bytes[idx:])

	return ps, nil
}

func ReadString(bytes []byte) (int, string) {
	idx := 0

	n, strLen := ReadVarInt(bytes)
	idx += n

	return idx + strLen, string(bytes[idx : idx+strLen])
}

func ReadObject(bytes []byte) (int, Entries) {
	idx := 0

	n, i := ReadVarInt(bytes[idx:])
	idx += n

	entries := make(Entries, i)

	for iter := 0; iter < i; iter++ {
		entries[iter] = Entry{}
		entry := &entries[iter]

		lenName := int(bytes[idx])
		idx += 1

		entry.Name = string(bytes[idx : idx+lenName])
		idx += lenName

		ttype := bytes[idx]
		idx += 1

		n, obj := ReadAny(bytes[idx:], ttype)
		idx += n

		entry.Value = obj
	}

	return idx, entries
}

func ReadArray(ttype byte, bytes []byte) (int, Entries) {
	var (
		idx = 0
		n   = 0
	)

	n, i := ReadVarInt(bytes[idx:])
	idx += n

	entries := make(Entries, i)

	for iter := 0; iter < i; iter++ {
		n, obj := ReadAny(bytes[idx:], ttype)
		idx += n

		entries[iter] = Entry{
			Value: obj,
		}
	}

	return idx, entries
}

func ReadAny(bytes []byte, ttype byte) (int, interface{}) {
	var (
		idx = 0
		n   = 0
	)

	if ttype&BoostSerializeFlagArray != 0 {
		internalType := ttype &^ BoostSerializeFlagArray
		n, obj := ReadArray(internalType, bytes[idx:])
		idx += n

		return idx, obj
	}

	if ttype == BoostSerializeTypeObject {
		n, obj := ReadObject(bytes[idx:])
		idx += n

		return idx, obj
	}

	if ttype == BoostSerializeTypeUint8 {
		obj := uint8(bytes[idx])
		n += 1
		idx += n

		return idx, obj
	}

	if ttype == BoostSerializeTypeUint16 {
		obj := binary.LittleEndian.Uint16(bytes[idx:])
		n += 2
		idx += n

		return idx, obj
	}

	if ttype == BoostSerializeTypeUint32 {
		obj := binary.LittleEndian.Uint32(bytes[idx:])
		n += 4
		idx += n

		return idx, obj
	}

	if ttype == BoostSerializeTypeUint64 {
		obj := binary.LittleEndian.Uint64(bytes[idx:])
		n += 8
		idx += n

		return idx, obj
	}

	if ttype == BoostSerializeTypeInt64 {
		obj := binary.LittleEndian.Uint64(bytes[idx:])
		n += 8
		idx += n

		return idx, int64(obj)
	}

	if ttype == BoostSerializeTypeString {
		n, obj := ReadString(bytes[idx:])
		idx += n

		return idx, obj
	}

	panic(fmt.Errorf("unknown ttype %x", ttype))
}

// reads var int, returning number of bytes read and the integer in that byte
// sequence.
func ReadVarInt(b []byte) (int, int) {
	sizeMask := b[0] & PortableRawSizeMarkMask

	switch uint32(sizeMask) {
	case uint32(PortableRawSizeMarkByte):
		return 1, int(b[0] >> 2)
	case uint32(PortableRawSizeMarkWord):
		return 2, int((binary.LittleEndian.Uint16(b[0:2])) >> 2)
	case PortableRawSizeMarkDword:
		return 4, int((binary.LittleEndian.Uint32(b[0:4])) >> 2)
	case uint32(PortableRawSizeMarkInt64):
		panic("int64 not supported") // TODO
		// return int((binary.LittleEndian.Uint64(b[0:8])) >> 2)
		//         '-> bad
	default:
		panic(fmt.Errorf("malformed sizemask: %+v", sizeMask))
	}
}

func (s *PortableStorage) Bytes() []byte {
	var (
		body = make([]byte, 9) // fit _at least_ signatures + format ver
		b    = make([]byte, 8) // biggest type

		idx  = 0
		size = 0
	)

	{ // signature a
		size = 4

		binary.LittleEndian.PutUint32(b, PortableStorageSignatureA)
		copy(body[idx:], b[:size])
		idx += size
	}

	{ // signature b
		size = 4

		binary.LittleEndian.PutUint32(b, PortableStorageSignatureB)
		copy(body[idx:], b[:size])
		idx += size
	}

	{ // format ver
		size = 1

		b[0] = PortableStorageFormatVersion
		copy(body[idx:], b[:size])
		idx += size
	}

	// // write_var_in
	varInB, err := VarIn(len(s.Entries))
	if err != nil {
		panic(fmt.Errorf("varin '%d': %w", len(s.Entries), err))
	}

	body = append(body, varInB...)
	for _, entry := range s.Entries {
		body = append(body, byte(len(entry.Name))) // section name length
		body = append(body, []byte(entry.Name)...) // section name
		body = append(body, entry.Serializable.Bytes()...)
	}

	return body
}

type Serializable interface {
	Bytes() []byte
}

type Section struct {
	Entries []Entry
}

func (s Section) Bytes() []byte {
	body := []byte{
		BoostSerializeTypeObject,
	}

	varInB, err := VarIn(len(s.Entries))
	if err != nil {
		panic(fmt.Errorf("varin '%d': %w", len(s.Entries), err))
	}

	body = append(body, varInB...)
	for _, entry := range s.Entries {
		body = append(body, byte(len(entry.Name))) // section name length
		body = append(body, []byte(entry.Name)...) // section name
		body = append(body, entry.Serializable.Bytes()...)
	}

	return body
}

func VarIn(i int) ([]byte, error) {
	if i <= 63 {
		return []byte{
			(byte(i) << 2) | PortableRawSizeMarkByte,
		}, nil
	}

	if i <= 16383 {
		b := []byte{0x00, 0x00}
		binary.LittleEndian.PutUint16(b,
			(uint16(i)<<2)|PortableRawSizeMarkWord,
		)

		return b, nil
	}

	if i <= 1073741823 {
		b := []byte{0x00, 0x00, 0x00, 0x00}
		binary.LittleEndian.PutUint32(b,
			(uint32(i)<<2)|PortableRawSizeMarkDword,
		)

		return b, nil
	}

	return nil, fmt.Errorf("int %d too big", i)
}

// readVarint читает varint из reader
func ReadVarint(reader *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint

	for {
		if shift >= 64 {
			return 0, fmt.Errorf("varint too long")
		}

		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}

		result |= uint64(b&0x7F) << shift

		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, nil
}

func ReadUint8(reader *bytes.Reader) (uint8, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	return b, nil
}
