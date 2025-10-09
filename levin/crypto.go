package levin

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

const moneroBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var b58Map [256]int

func init() {
	for i := range b58Map {
		b58Map[i] = -1
	}
	for i, c := range moneroBase58Alphabet {
		b58Map[c] = i
	}
}

// decodeMoneroBase58 decodes Monero's special base58 string into bytes.
// It expects groups of 11 chars -> 8 bytes and final 7 chars -> 5 bytes for standard address.
func decodeMoneroBase58(s string) ([]byte, error) {
	// remove spaces/newlines just in case
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty string")
	}

	// standard address length is 95 chars -> 8 groups of 11 + last 7
	// compute expected groups
	out := make([]byte, 0)

	// process in chunks: 11 chars -> 8 bytes, except last which may be 7 -> 5 bytes
	i := 0
	for i < len(s) {
		rem := len(s) - i
		var chunkLenChars int
		var chunkLenBytes int
		if rem > 7 {
			chunkLenChars = 11
			chunkLenBytes = 8
		} else if rem == 7 {
			chunkLenChars = 7
			chunkLenBytes = 5
		} else {
			return nil, errors.New("unexpected base58 length for monero address")
		}

		chunk := s[i : i+chunkLenChars]
		i += chunkLenChars

		// convert chunk to integer
		val := big.NewInt(0)
		for _, ch := range []byte(chunk) {
			idx := b58Map[ch]
			if idx < 0 {
				return nil, errors.New("invalid base58 char")
			}
			val.Mul(val, big.NewInt(58))
			val.Add(val, big.NewInt(int64(idx)))
		}

		// extract bytes big-endian chunkLenBytes (Monero base58 uses big-endian per chunk)
		buf := make([]byte, chunkLenBytes)
		tmp := new(big.Int).Set(val)
		// fill from the end
		for j := chunkLenBytes - 1; j >= 0; j-- {
			b := new(big.Int)
			b.Mod(tmp, big.NewInt(256))
			buf[j] = byte(b.Int64())
			tmp.Div(tmp, big.NewInt(256))
		}

		out = append(out, buf...)
	}

	return out, nil
}

// DecodeAddressRaw decodes monero base58 address and returns raw decoded bytes (for debug)
func DecodeAddressRaw(s string) ([]byte, error) {
	return decodeMoneroBase58(s)
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// DecodeAddress decodes a standard Monero address and returns public spend and view keys
func DecodeAddress(addr string) (pubSpend [32]byte, pubView [32]byte, err error) {
	b, err := decodeMoneroBase58(addr)
	if err != nil {
		return pubSpend, pubView, err
	}

	// expected minimal length 1 + 32 + 32 + 4 = 69
	if len(b) < 69 {
		return pubSpend, pubView, errors.New("decoded address too short")
	}

	// first byte is network tag
	// next 32 is pubSpend, next 32 is pubView, last 4 is checksum
	copy(pubSpend[:], b[1:33])
	copy(pubView[:], b[33:65])

	// verify checksum
	payload := b[:65]
	sum := keccak256(payload)
	if len(sum) < 4 || !equalBytes(sum[:4], b[65:69]) {
		return pubSpend, pubView, errors.New("address checksum mismatch")
	}

	return pubSpend, pubView, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// derivePublicKey implements Monero's derive_public_key: given tx pubkey R (32 bytes),
// recipient private view key (32 bytes hex) and recipient public spend key B (32 bytes),
// returns the one-time public key for given output index.
func DerivePublicKey(txPubKey []byte, privateViewKey []byte, pubSpendKey []byte, index uint64) ([]byte, error) {
	if len(txPubKey) != 32 || len(privateViewKey) != 32 || len(pubSpendKey) != 32 {
		return nil, errors.New("invalid key lengths")
	}

	// load tx pubpoint
	var R edwards25519.Point
	if _, err := R.SetBytes(txPubKey); err != nil {
		return nil, err
	}

	// load scalar a (private view key) - treat as little-endian
	var a edwards25519.Scalar
	// use SetBytesWithClamping? private view key is already scalar; use SetUniformBytes to reduce
	// try SetBytes with reduced form via SetUniformBytes on hash of key if available
	// here we will use SetBytes(&privateViewKey) via SetBytesWithClamping-like approach
	// The edwards25519 Scalar provides SetBytesWithClamping
	if _, err := a.SetBytesWithClamping(privateViewKey); err != nil {
		// fallback: try SetCanonical
		if _, err2 := a.SetCanonicalBytes(privateViewKey); err2 != nil {
			return nil, err
		}
	}

	// shared = a * R
	shared := new(edwards25519.Point).ScalarMult(&a, &R)
	sharedBytes := shared.Bytes()

	// hash shared || index(le)
	idxBytes := make([]byte, 8)
	// little endian
	for i := 0; i < 8; i++ {
		idxBytes[i] = byte((index >> (8 * i)) & 0xff)
	}
	h := keccak256(append(sharedBytes, idxBytes...))

	// reduce to scalar using sc_reduce32 (Monero's sc_reduce32 behavior)
	reduced := sc_reduce32(h)
	var scalar edwards25519.Scalar
	if _, err := scalar.SetCanonicalBytes(reduced); err != nil {
		// SetCanonicalBytes may return error if not canonical; fall back to SetUniformBytes
		scalar.SetUniformBytes(append(h, h...))
	}

	// derivedPoint = scalar*G + B
	derivedBase := new(edwards25519.Point).ScalarBaseMult(&scalar)

	var B edwards25519.Point
	if _, err := B.SetBytes(pubSpendKey); err != nil {
		return nil, err
	}

	derivedPoint := new(edwards25519.Point).Add(derivedBase, &B)
	return derivedPoint.Bytes(), nil
}

// helper: parse hex key
func hexTo32(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("hex length != 32")
	}
	return b, nil
}

// sc_reduce32 reduces a 32-byte array modulo the ed25519 group order l.
func sc_reduce32(in []byte) []byte {
	// ed25519 order L = 2^252 + 27742317777372353535851937790883648493
	// We'll perform reduction using big.Int
	// Above is placeholder; instead use canonical order
	// Real L:
	L, _ := new(big.Int).SetString("723700557733226221397318656304299424085711635937990760600195093828545425057", 10)

	v := new(big.Int).SetBytes(in)
	v.Mod(v, L)
	// produce 32-byte little-endian
	res := make([]byte, 32)
	tmp := new(big.Int).Set(v)
	for i := 0; i < 32; i++ {
		if tmp.Sign() == 0 {
			res[i] = 0
			continue
		}
		byteVal := new(big.Int).And(tmp, big.NewInt(0xff))
		res[i] = byte(byteVal.Int64())
		tmp.Rsh(tmp, 8)
	}
	return res
}
