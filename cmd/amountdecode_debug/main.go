package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// keccak256 returns 32-byte keccak-256 hash.
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// keccak512 returns 64-byte legacy keccak-512 hash.
func keccak512(data []byte) []byte {
	h := sha3.NewLegacyKeccak512()
	h.Write(data)
	return h.Sum(nil)
}

// encodeVarint encodes n as Monero varint (LE base-128).
func encodeVarint(n uint64) []byte {
	var buf []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if n == 0 {
			break
		}
	}
	return buf
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// hashToPoint: hash input -> scalar -> scalar*G -> *8 (returns 32-byte encoded point)
func hashToPoint(pBytes []byte) ([]byte, error) {
	// Use keccak512 to produce 64 bytes suitable for SetUniformBytes.
	h := keccak512(pBytes) // 64 bytes

	// Create scalar s from 64-byte wide input (SetUniformBytes reduces mod l).
	s := new(edwards25519.Scalar)
	if _, err := s.SetUniformBytes(h); err != nil {
		return nil, fmt.Errorf("SetUniformBytes failed: %w", err)
	}

	// point = s * G
	point := new(edwards25519.Point).ScalarBaseMult(s)

	// Multiply point by 8 (cofactor clearing): make scalar 8 and scalar-mult
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	eight := new(edwards25519.Scalar)
	if _, err := eight.SetCanonicalBytes(eightBytes); err != nil {
		return nil, fmt.Errorf("creating scalar 8 failed: %w", err)
	}

	result := new(edwards25519.Point).ScalarMult(eight, point)
	return result.Bytes(), nil
}

// decodeRctAmount decrypts a RingCT encrypted amount (8 bytes)
// decodeRctAmount decrypts a RingCT encrypted amount (8 bytes)
func decodeRctAmount(txPubKey []byte, privateViewKey []byte, outputIndex uint64, encryptedAmount []byte) (uint64, error) {
	if len(encryptedAmount) != 8 {
		return 0, fmt.Errorf("invalid encrypted amount length: %d", len(encryptedAmount))
	}

	// Parse R (tx pubkey)
	Rpt, err := new(edwards25519.Point).SetBytes(txPubKey)
	if err != nil {
		return 0, fmt.Errorf("invalid tx public key: %w", err)
	}

	// Parse scalar a (private view key)
	a := new(edwards25519.Scalar)
	if _, err := a.SetCanonicalBytes(privateViewKey); err != nil {
		return 0, fmt.Errorf("invalid private view key scalar bytes: %w", err)
	}

	// Scalar eight = 8
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	eight := new(edwards25519.Scalar)
	if _, err := eight.SetCanonicalBytes(eightBytes); err != nil {
		return 0, fmt.Errorf("creating scalar 8 failed: %w", err)
	}

	// eightA = eight * a
	eightA := new(edwards25519.Scalar).Multiply(eight, a)

	// Compute shared secret: sharedPoint = (8*a) * R
	sharedPoint := new(edwards25519.Point).ScalarMult(eightA, Rpt)
	sharedBytes := sharedPoint.Bytes()

	// Monero hash_to_scalar (Hs):
	// 1. Concatenate 8aR with varint(outputIndex)
	// 2. Hash with keccak256 to get 32 bytes
	// 3. Interpret as scalar (reduce mod l) - this is Hs(8aR || i)
	hashInput := append(sharedBytes, encodeVarint(outputIndex)...)
	hsHash := keccak256(hashInput) // 32 bytes

	// For sc_reduce32: pad the 32-byte hash to 64 bytes for SetUniformBytes
	// SetUniformBytes expects 64 bytes and reduces mod l internally
	hsHash64 := make([]byte, 64)
	copy(hsHash64, hsHash)

	hsScalar := new(edwards25519.Scalar)
	if _, err := hsScalar.SetUniformBytes(hsHash64); err != nil {
		return 0, fmt.Errorf("hash_to_scalar failed: %w", err)
	}

	// Get the canonical bytes of the scalar Hs
	hsBytes := hsScalar.Bytes()

	// Compute amount mask: keccak256("amount" || Hs)
	amountMask := keccak256(append([]byte("amount"), hsBytes...))

	// XOR first 8 bytes (little-endian) to get amount
	var amount uint64
	for i := 0; i < 8; i++ {
		decrypted := encryptedAmount[i] ^ amountMask[i]
		amount |= uint64(decrypted) << (8 * i)
	}

	return amount, nil
}

func main() {
	txPubKey := mustHex("b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff")
	privateViewKey := mustHex("7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604")
	encryptedAmount := mustHex("277ede35c7f0cf5b")
	outputIndex := uint64(0)

	expectedXMR := 0.033592475285
	expectedAtomic := uint64(expectedXMR * 1e12)

	fmt.Println("=== Amount Decoding Test ===")
	fmt.Printf("TX PubKey: %x\n", txPubKey)
	fmt.Printf("Private View Key: %x\n", privateViewKey)

	sm, err := decodeRctAmount(txPubKey, privateViewKey, outputIndex, encryptedAmount)
	if err != nil {
		log.Fatalf("Error decoding RCT amount: %v", err)
	}

	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Expected: %.12f XMR (%d piconeros)\n", expectedXMR, expectedAtomic)
	fmt.Printf("Decoded Amount: %d piconeros\n", sm)
	fmt.Printf("Decoded Amount (XMR): %.12f XMR\n", float64(sm)/1e12)

	if sm == expectedAtomic {
		fmt.Println("\n✅ SUCCESS! Amounts match perfectly!")
	} else {
		fmt.Println("\n❌ FAIL! Amounts don't match")
		fmt.Printf("Difference: %d piconeros\n", int64(sm)-int64(expectedAtomic))
	}
}
