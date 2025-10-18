package levin

import (
	"encoding/hex"
	"errors"
	"fmt"
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
func decodeMoneroBase58(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty string")
	}

	out := make([]byte, 0)
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

		val := big.NewInt(0)
		for _, ch := range []byte(chunk) {
			idx := b58Map[ch]
			if idx < 0 {
				return nil, errors.New("invalid base58 char")
			}
			val.Mul(val, big.NewInt(58))
			val.Add(val, big.NewInt(int64(idx)))
		}

		buf := make([]byte, chunkLenBytes)
		tmp := new(big.Int).Set(val)
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

func DecodeAddressRaw(s string) ([]byte, error) {
	return decodeMoneroBase58(s)
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func KeccakByte(data []byte) byte {
	h := keccak256(data)
	if len(h) == 0 {
		return 0
	}
	return h[0]
}

// DecodeAddress decodes a standard or integrated Monero address and returns public spend and view keys
func DecodeAddress(addr string) (pubSpend [32]byte, pubView [32]byte, err error) {
	b, err := decodeMoneroBase58(addr)
	if err != nil {
		return pubSpend, pubView, err
	}

	if len(b) < 69 {
		return pubSpend, pubView, errors.New("decoded address too short")
	}

	networkByte := b[0]
	
	var checksumDataLen int
	var checksumStart int
	
	switch {
	case len(b) == 69 && (networkByte == 0x12 || networkByte == 0x2A):
		// Standard address or subaddress
		checksumDataLen = 65
		checksumStart = 65
		
	case len(b) == 77 && networkByte == 0x13:
		// Integrated address (has 8-byte payment_id after pubView)
		checksumDataLen = 73
		checksumStart = 73
		
	default:
		return pubSpend, pubView, fmt.Errorf("invalid address: unknown format (len=%d, network_byte=0x%02x)", len(b), networkByte)
	}

	// Extract keys (same position for all types)
	copy(pubSpend[:], b[1:33])
	copy(pubView[:], b[33:65])

	// Verify checksum
	payload := b[:checksumDataLen]
	sum := keccak256(payload)
	
	expectedChecksum := b[checksumStart : checksumStart+4]
	if !equalBytes(sum[:4], expectedChecksum) {
		return pubSpend, pubView, errors.New("address checksum mismatch")
	}

	return pubSpend, pubView, nil
}

// ExtractPaymentID extracts payment_id from an integrated address
// Returns empty slice for standard addresses
func ExtractPaymentID(addr string) ([]byte, error) {
	b, err := decodeMoneroBase58(addr)
	if err != nil {
		return nil, err
	}

	if len(b) < 69 {
		return nil, errors.New("decoded address too short")
	}

	networkByte := b[0]
	
	// Only integrated addresses (0x13) have payment_id
	if len(b) == 77 && networkByte == 0x13 {
		paymentID := make([]byte, 8)
		copy(paymentID, b[65:73])
		return paymentID, nil
	}

	// Standard or subaddress - no payment_id
	return nil, nil
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

// DerivePublicKey implements Monero's derive_public_key
// P = Hs(8*a*R || index)*G + B
func DerivePublicKey(txPubKey []byte, privateViewKey []byte, pubSpendKey []byte, index uint64) ([]byte, error) {
	if len(txPubKey) != 32 || len(privateViewKey) != 32 || len(pubSpendKey) != 32 {
		return nil, errors.New("invalid key lengths")
	}

	// Step 1: Calculate shared secret (derivation = 8 * a * R)
	derivation, err := SharedSecret(txPubKey, privateViewKey)
	if err != nil {
		return nil, err
	}

	// Step 2: Create hash input: derivation || varint(index)
	idxBytes := encodeVarint(index)
	hashInput := append(derivation, idxBytes...)

	// Step 3: Hash to scalar: Hs(derivation || index)
	h := keccak256(hashInput)

	// Step 4: Convert to edwards25519 scalar using SetBytesWithClamping
	var s edwards25519.Scalar
	_, err = s.SetBytesWithClamping(h)
	if err != nil {
		return nil, errors.New("failed to convert hash to scalar")
	}

	// Step 5: Calculate Hs(...)*G
	hsG := new(edwards25519.Point).ScalarBaseMult(&s)

	// Step 6: Parse public spend key B
	var B edwards25519.Point
	if _, err := B.SetBytes(pubSpendKey); err != nil {
		return nil, errors.New("invalid public spend key")
	}

	// Step 7: P = Hs(...)*G + B
	P := new(edwards25519.Point).Add(hsG, &B)

	return P.Bytes(), nil
}

// DerivePublicKeyWithPaymentID implements Monero's derive_public_key for integrated addresses
// P = Hs(8*a*R || index || payment_id)*G + B
func DerivePublicKeyWithPaymentID(txPubKey []byte, privateViewKey []byte, pubSpendKey []byte, index uint64, paymentID []byte) ([]byte, error) {
	if len(txPubKey) != 32 || len(privateViewKey) != 32 || len(pubSpendKey) != 32 {
		return nil, errors.New("invalid key lengths")
	}
	
	if len(paymentID) != 8 {
		return nil, errors.New("payment_id must be 8 bytes")
	}

	// Step 1: Calculate shared secret (derivation = 8 * a * R)
	derivation, err := SharedSecret(txPubKey, privateViewKey)
	if err != nil {
		return nil, err
	}

	// Step 2: Create hash input: derivation || varint(index) || payment_id
	idxBytes := encodeVarint(index)
	hashInput := append(derivation, idxBytes...)
	hashInput = append(hashInput, paymentID...)

	// Step 3: Hash to scalar: Hs(derivation || index || payment_id)
	h := keccak256(hashInput)

	// Step 4: Convert to edwards25519 scalar using SetBytesWithClamping
	var s edwards25519.Scalar
	_, err = s.SetBytesWithClamping(h)
	if err != nil {
		return nil, errors.New("failed to convert hash to scalar")
	}

	// Step 5: Calculate Hs(...)*G
	hsG := new(edwards25519.Point).ScalarBaseMult(&s)

	// Step 6: Parse public spend key B
	var B edwards25519.Point
	if _, err := B.SetBytes(pubSpendKey); err != nil {
		return nil, errors.New("invalid public spend key")
	}

	// Step 7: P = Hs(...)*G + B
	P := new(edwards25519.Point).Add(hsG, &B)

	return P.Bytes(), nil
}

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

func SharedSecret(txPubKey []byte, privateViewKey []byte) ([]byte, error) {
	if len(txPubKey) != 32 || len(privateViewKey) != 32 {
		return nil, errors.New("invalid key lengths")
	}

	var R edwards25519.Point
	if _, err := R.SetBytes(txPubKey); err != nil {
		return nil, err
	}

	var a edwards25519.Scalar
	if _, err := a.SetCanonicalBytes(privateViewKey); err != nil {
		a.SetUniformBytes(append(privateViewKey, privateViewKey...))
	}

	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	var eight edwards25519.Scalar
	if _, err := eight.SetCanonicalBytes(eightBytes); err != nil {
		eight.SetUniformBytes(append(eightBytes, eightBytes...))
	}

	var eightA edwards25519.Scalar
	eightA.Multiply(&eight, &a)

	shared := new(edwards25519.Point).ScalarMult(&eightA, &R)

	return shared.Bytes(), nil
}