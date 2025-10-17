package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"xmr_scanner/levin"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

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

func SharedSecret(txPubKey []byte, privateViewKey []byte) ([]byte, error) {
	if len(txPubKey) != 32 || len(privateViewKey) != 32 {
		return nil, fmt.Errorf("invalid key lengths")
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
	eight.SetCanonicalBytes(eightBytes)

	var eightA edwards25519.Scalar
	eightA.Multiply(&eight, &a)

	shared := new(edwards25519.Point).ScalarMult(&eightA, &R)
	return shared.Bytes(), nil
}

func main() {
	txPubKey := mustHex("b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff")
	privateViewKey := mustHex("7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604")
	encryptedAmount := mustHex("277ede35c7f0cf5b")
	outputIndex := uint64(0) // Вы сказали индекс 0

	expectedXMR := 0.033592475285
	expectedAtomic := uint64(expectedXMR * 1e12)

	sm, err := levin.DecodeRctAmount(txPubKey, privateViewKey, outputIndex, encryptedAmount)
	if err != nil {
		log.Fatalf("Error decoding RCT amount: %v", err)
	}

	fmt.Println("=== Amount Decoding Test ===")
	fmt.Printf("\nExpected: %.12f XMR (%d piconeros)\n", expectedXMR, expectedAtomic)
	fmt.Printf("Expected hex: %016x\n", expectedAtomic)
	fmt.Printf("\nEncrypted Amount: %x\n", encryptedAmount)
	fmt.Printf("Output Index: %d\n", outputIndex)
	fmt.Printf("Decoded Amount: %d piconeros\n", sm)
	fmt.Printf("Decoded Amount (XMR): %.12f XMR\n", float64(sm)/1e12)
}
