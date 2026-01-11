package moneroutil

import (
	"fmt"
	"io"

	"github.com/ebfe/keccak"
)

const (
	ChecksumLength = 4
	HashLength     = 32
)

type Hash [HashLength]byte
type Checksum [ChecksumLength]byte

var (
	NullHash = [HashLength]byte{}
)

func ReadVarInt(buf io.Reader) (result uint64, err error) {
	b := make([]byte, 1)
	var r uint64
	var n int
	for i := 0; ; i++ {
		n, err = buf.Read(b)
		if err != nil {
			return
		}
		if n != 1 {
			err = fmt.Errorf("Buffer ended prematurely for varint")
			return
		}
		r += (uint64(b[0]) & 0x7f) << uint(i*7)
		if uint64(b[0])&0x80 == 0 {
			break
		}
	}
	result = r
	return
}

func Uint64ToBytes(num uint64) (result []byte) {
	for ; num >= 0x80; num >>= 7 {
		result = append(result, byte((num&0x7f)|0x80))
	}
	result = append(result, byte(num))
	return
}

func Keccak256(data ...[]byte) (result Hash) {
	h := keccak.New256()
	for _, b := range data {
		h.Write(b)
	}
	r := h.Sum(nil)
	copy(result[:], r)
	return
}
