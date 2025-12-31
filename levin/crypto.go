package levin

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	moneroutil "xmr_scanner/moneroutil"

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

// Proper sc_reduce32 using big.Int modulo arithmetic
func sc_reduce32(in []byte) []byte {
	// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
	L := new(big.Int)
	L.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	// Convert input bytes (little-endian) to big.Int
	n := new(big.Int)
	// Reverse for big-endian
	reversed := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		reversed[len(in)-1-i] = in[i]
	}
	n.SetBytes(reversed)

	// Perform modulo
	n.Mod(n, L)

	// Convert back to little-endian 32 bytes
	resultBytes := n.Bytes()
	result := make([]byte, 32)

	// Copy in reverse (back to little-endian)
	for i := 0; i < len(resultBytes); i++ {
		result[i] = resultBytes[len(resultBytes)-1-i]
	}

	return result
}

func DerivePublicKey(txPubKey, privateViewKey, pubSpendKey []byte, index uint64) ([]byte, error) {
	// Parse R
	var R edwards25519.Point
	if _, err := R.SetBytes(txPubKey); err != nil {
		return nil, err
	}

	// Parse a (private view key)
	var a edwards25519.Scalar
	if _, err := a.SetCanonicalBytes(privateViewKey); err != nil {
		return nil, err
	}

	// Calculate 8 scalar
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	var eight edwards25519.Scalar
	eight.SetCanonicalBytes(eightBytes)

	// Method 1: 8 * (a * R)
	aR := new(edwards25519.Point).ScalarMult(&a, &R)
	derivation := new(edwards25519.Point).ScalarMult(&eight, aR)

	// Create hash input: derivation || varint(index)
	idxBytes := encodeVarint(index)
	hashInput := append(derivation.Bytes(), idxBytes...)

	// Hash with Keccak256
	h := keccak256(hashInput)
	// Apply sc_reduce32
	scalarBytes := sc_reduce32(h)

	// Convert to scalar
	var s edwards25519.Scalar
	if _, err := s.SetCanonicalBytes(scalarBytes); err != nil {
		// If not canonical, try SetUniformBytes
		s.SetUniformBytes(append(scalarBytes, scalarBytes...))
	}

	// Calculate Hs(derivation || i) * G
	hsG := new(edwards25519.Point).ScalarBaseMult(&s)
	// Parse B (public spend key)
	var B edwards25519.Point
	if _, err := B.SetBytes(pubSpendKey); err != nil {
		return nil, err
	}

	P := new(edwards25519.Point).Add(hsG, &B)
	// result1 := hex.EncodeToString(P1.Bytes())
	// result2 := hex.EncodeToString(hsG.Bytes())
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

const (
	TX_EXTRA_TAG_PUBKEY         = 0x01
	TX_EXTRA_NONCE              = 0x02
	TX_EXTRA_ADDITIONAL_PUBKEYS = 0x04

	TX_EXTRA_NONCE_PAYMENT_ID     = 0x00
	TX_EXTRA_NONCE_ENC_PAYMENT_ID = 0x01
)

func parseTxExtra(extra []byte) (txPubKey []byte, additionalKeys [][]byte, pid []byte, encPID []byte, err error) {
	i := 0
	for i < len(extra) {
		tag := extra[i]
		i++

		switch tag {
		case 0x00: // padding
			continue

		case TX_EXTRA_TAG_PUBKEY:
			if i+32 > len(extra) {
				return nil, nil, nil, nil, errors.New("tx extra: truncated pubkey")
			}
			txPubKey = make([]byte, 32)
			copy(txPubKey, extra[i:i+32])
			i += 32

		case TX_EXTRA_NONCE:
			if i >= len(extra) {
				return nil, nil, nil, nil, errors.New("tx extra: nonce length missing")
			}
			L := int(extra[i])
			i++
			if i+L > len(extra) {
				return nil, nil, nil, nil, errors.New("tx extra: nonce truncated")
			}
			nonce := extra[i : i+L]
			i += L

			if len(nonce) >= 1 {
				switch nonce[0] {
				case TX_EXTRA_NONCE_PAYMENT_ID:
					if len(nonce) >= 1+32 {
						pid = make([]byte, 32)
						copy(pid, nonce[1:1+32])
					}
				case TX_EXTRA_NONCE_ENC_PAYMENT_ID:
					if len(nonce) >= 1+8 {
						encPID = make([]byte, 8)
						copy(encPID, nonce[1:1+8])
					}
				}
			}

		case TX_EXTRA_ADDITIONAL_PUBKEYS:
			if i >= len(extra) {
				return nil, nil, nil, nil, errors.New("tx extra: additional keys length missing")
			}
			L := int(extra[i])
			i++
			if i+L > len(extra) || L%32 != 0 {
				return nil, nil, nil, nil, errors.New("tx extra: invalid additional keys")
			}
			count := L / 32
			for j := 0; j < count; j++ {
				key := make([]byte, 32)
				copy(key, extra[i+j*32:i+(j+1)*32])
				additionalKeys = append(additionalKeys, key)
			}
			i += L

		default:
			// неизвестный тег — в Monero их может быть больше
			// но без длины мы не можем корректно пропустить
			// так что просто прерываемся
			return txPubKey, additionalKeys, pid, encPID, nil
		}
	}
	return txPubKey, additionalKeys, pid, encPID, nil
}

// decryptShortPaymentID:
// - txPubKey: 32-byte tx public key (from extra tag 0x01)
// - privViewKey: 32-byte private view key (hex-decoded, little-endian)
// - encPID: 8-byte encrypted payment id (from nonce type 0x01)
// returns uint64 payment id (interpreted little-endian), and raw 8 bytes
func decryptShortPaymentID(txPubKey, privViewKey, encPID []byte) (uint64, []byte, error) {
	if len(txPubKey) != 32 {
		return 0, nil, errors.New("txPubKey must be 32 bytes")
	}
	if len(privViewKey) != 32 {
		return 0, nil, errors.New("privViewKey must be 32 bytes")
	}
	if len(encPID) != 8 {
		return 0, nil, errors.New("encPID must be 8 bytes")
	}

	// Decode txPubKey as Point
	R := new(edwards25519.Point)
	if _, err := R.SetBytes(txPubKey); err != nil {
		return 0, nil, fmt.Errorf("invalid tx pubkey: %w", err)
	}

	// Load private view key as scalar (Monero private keys are scalars mod l)
	// Use SetCanonicalBytes to set scalar from 32-byte little-endian encoding (must be canonical)
	scalar := new(edwards25519.Scalar)
	if _, err := scalar.SetCanonicalBytes(privViewKey); err != nil {
		// Try SetBytesWithClamping as fallback if not canonical
		if _, err2 := scalar.SetBytesWithClamping(privViewKey); err2 != nil {
			return 0, nil, fmt.Errorf("invalid privViewKey: %v / %v", err, err2)
		}
	}

	// shared = a * R
	sharedPoint := new(edwards25519.Point).ScalarMult(scalar, R)

	// multiply by 8 (Monero code uses 8*R etc in derivations)
	eight := ScalarFromUint64(8)
	sharedPoint = new(edwards25519.Point).ScalarMult(eight, sharedPoint)

	// serialize shared point to bytes (compressed)
	sharedBytes := sharedPoint.Bytes() // 32 bytes

	// compute keccak256(sharedBytes || 0x8d)
	h := sha3.NewLegacyKeccak256()
	h.Write(sharedBytes)
	h.Write([]byte{0x8d})
	hash := h.Sum(nil) // 32 bytes

	// XOR first 8 bytes of hash with encPID
	key := hash[:8]
	pidBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		pidBytes[i] = encPID[i] ^ key[i]
	}

	// interpret as little-endian uint64
	id := binary.LittleEndian.Uint64(pidBytes)
	return id, pidBytes, nil
}

func encryptPaymentID(paymentID, pubViewKey, txSecretKey []byte) ([8]byte, error) {
	shared, err := SharedSecret(pubViewKey, txSecretKey)
	if err != nil {
		return [8]byte{}, err
	}

	// append magic byte 0x8d
	data := append(shared, 0x8d)
	hash := moneroutil.Keccak256(data)

	var encrypted [8]byte
	for i := 0; i < 8; i++ {
		encrypted[i] = paymentID[i] ^ hash[i]
	}
	return encrypted, nil
}

func ScalarFromUint64(v uint64) *edwards25519.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], v) // кладём в первые 8 байт
	sc, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic(err) // или обрабатывай ошибку
	}
	return sc
}
