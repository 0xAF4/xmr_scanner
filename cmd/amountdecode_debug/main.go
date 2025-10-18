package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// parseTxExtra ищет tx pubkey (tag 0x01 -> 32 bytes) и short encrypted payment id
// (tag 0x02 -> length byte L, content: [nonce_type][...]; nonce_type==0x01 -> next 8 bytes are enc pid)
func parseTxExtra(extraHex string) (txPubKey []byte, encPID []byte, err error) {
	extra, err := hex.DecodeString(extraHex)
	if err != nil {
		return nil, nil, err
	}
	i := 0
	for i < len(extra) {
		tag := extra[i]
		i++
		switch tag {
		case 0x00: // padding: skip until non-zero? (in practice padding is zeros)
			// nothing to consume specifically
		case 0x01: // TX_EXTRA_TAG_PUBKEY -> next 32 bytes
			if i+32 > len(extra) {
				return nil, nil, errors.New("tx extra: truncated pubkey")
			}
			txPubKey = make([]byte, 32)
			copy(txPubKey, extra[i:i+32])
			i += 32
		case 0x02: // TX_EXTRA_NONCE -> next byte is length L, then L bytes of nonce
			if i >= len(extra) {
				return nil, nil, errors.New("tx extra: nonce length missing")
			}
			L := int(extra[i])
			i++
			if i+L > len(extra) {
				return nil, nil, errors.New("tx extra: nonce truncated")
			}
			nonce := extra[i : i+L]
			i += L
			// nonce[0] indicates type:
			// 0x00 -> plain payment id (32 bytes)
			// 0x01 -> encrypted short payment id (8 bytes)
			if len(nonce) >= 1 && nonce[0] == 0x01 && len(nonce) >= 1+8 {
				encPID = make([]byte, 8)
				copy(encPID, nonce[1:1+8])
				// we can return early (but still we keep txPubKey if already found)
			}
		default:
			// unknown tag — many tags are followed by variable-length data in real monero impl,
			// but common tags we care about are handled above. To be safe, try to bail out.
			// In many txs unknown padding or other data may appear; we cannot reliably skip size here.
			// So we continue (best-effort) — but to avoid infinite loop, just continue.
		}
	}
	return txPubKey, encPID, nil
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

func ScalarFromUint64(v uint64) *edwards25519.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], v) // кладём в первые 8 байт
	sc, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic(err) // или обрабатывай ошибку
	}
	return sc
}

func main() {
	// ====== входные данные (пример из твоего tx.extra) ======
	extraHex := "01b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff02090154c7cf8dc2d8c619"
	// privViewKeyHex нужно поставить свою — без неё дешифровка невозможна.
	// Пример: privViewKeyHex := "..." — 32 байта (64 hex chars)
	privViewKeyHex := "7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604"

	txPubKey, encPID, err := parseTxExtra(extraHex)
	fmt.Printf("txPubKey: %X\n", txPubKey)
	fmt.Printf("encPID: %X\n", encPID)
	if err != nil {
		log.Fatalf("parseTxExtra error: %v", err)
	}
	if txPubKey == nil {
		log.Fatalf("tx public key not found in extra")
	}
	if encPID == nil {
		log.Fatalf("encrypted short payment id (nonce type 0x01) not found in extra")
	}

	privViewKey, err := hex.DecodeString(privViewKeyHex)
	if err != nil {
		log.Fatalf("privViewKey hex decode: %v", err)
	}

	id, pidBytes, err := decryptShortPaymentID(txPubKey, privViewKey, encPID)
	if err != nil {
		log.Fatalf("decryptShortPaymentID error: %v", err)
	}
	fmt.Printf("Payment ID bytes (little-endian hex): %x\n", pidBytes)
	fmt.Printf("Payment ID decimal: %d\n", id)
}
