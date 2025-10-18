package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"

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

func main() {
	txPubKey := mustHex("43a07a2617840ef0bcbb1c75b15a730ae2365bedb147499aa4a909856cb2ec13")
	privateViewKey := mustHex("98540b36f09f5e5439f98f048e81e32fbbf19f836c962fef1510d3af605f0102")
	pubSpendKey := mustHex("12c75c7955eb5509fec4d82074963aa5cc88c8ae05a3b2c57ff17c8b8be25497")

	fmt.Println("Testing Monero Stealth Address Derivation")
	fmt.Println("==========================================\n")

	// Try indices 0-5
	for index := uint64(1); index < 6; index++ {
		fmt.Printf("\n╔═══════════════════════════════════════════╗\n")
		fmt.Printf("║         TESTING WITH INDEX = %d           ║\n", index)
		fmt.Printf("╚═══════════════════════════════════════════╝\n")

		if testIndex(txPubKey, privateViewKey, pubSpendKey, index) {
			return
		}
	}

	fmt.Println("\n✗✗✗ NO MATCH FOUND WITH ANY COMBINATION ✗✗✗")
	fmt.Println("Expected either:")
	fmt.Println("  16f13dcaa21472c3fd31f6ba0c70077fc993fabfdc10f0c7d84a5639b23ff94a")
	fmt.Println("  59cf3fe4003457f8da36beee36ee5e252d28a90af8e3ca2f306cb673a0ce3325")
}

func testIndex(txPubKey, privateViewKey, pubSpendKey []byte, index uint64) bool {
	// Parse R
	var R edwards25519.Point
	if _, err := R.SetBytes(txPubKey); err != nil {
		log.Fatal("Failed to parse R:", err)
	}

	// Parse a (private view key)
	var a edwards25519.Scalar
	if _, err := a.SetCanonicalBytes(privateViewKey); err != nil {
		log.Fatal("Failed to parse private view key:", err)
	}

	// Calculate 8 scalar
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	var eight edwards25519.Scalar
	eight.SetCanonicalBytes(eightBytes)

	// Method 1: 8 * (a * R)
	aR := new(edwards25519.Point).ScalarMult(&a, &R)
	derivation1 := new(edwards25519.Point).ScalarMult(&eight, aR)

	// Method 2: (8*a) * R
	var eightA edwards25519.Scalar
	eightA.Multiply(&eight, &a)
	derivation2 := new(edwards25519.Point).ScalarMult(&eightA, &R)

	// Method 3: a * R (NO 8x) - for comparison
	derivation3 := aR

	derivations := [][]byte{derivation1.Bytes(), derivation2.Bytes(), derivation3.Bytes()}
	derivationNames := []string{"8*(a*R)", "(8*a) * R", "a*R (no 8x)"}

	for derivIdx, derivation := range derivations {
		// Create hash input: derivation || varint(index)
		idxBytes := encodeVarint(index)
		hashInput := append(derivation, idxBytes...)

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
			log.Fatal("Failed to parse B:", err)
		}

		// Method A: P = Hs(...)*G + B (standard stealth address)
		P1 := new(edwards25519.Point).Add(hsG, &B)
		result1 := hex.EncodeToString(P1.Bytes())

		fmt.Printf("result1: %s\n", result1)
		os.Exit(991)

		// Method B: P = Hs(...)*G (without B, for some RingCT outputs)
		result2 := hex.EncodeToString(hsG.Bytes())

		// Check results
		if result1 == "16f13dcaa21472c3fd31f6ba0c70077fc993fabfdc10f0c7d84a5639b23ff94a" ||
			result1 == "59cf3fe4003457f8da36beee36ee5e252d28a90af8e3ca2f306cb673a0ce3325" {
			fmt.Printf("\n✓✓✓ SUCCESS! ✓✓✓\n")
			fmt.Printf("Index: %d\n", index)
			fmt.Printf("Derivation: %s\n", derivationNames[derivIdx])
			fmt.Printf("Formula: P = Hs(derivation || i)*G + B\n")
			fmt.Printf("Result: %s\n", result1)
			return true
		}

		if result2 == "16f13dcaa21472c3fd31f6ba0c70077fc993fabfdc10f0c7d84a5639b23ff94a" ||
			result2 == "59cf3fe4003457f8da36beee36ee5e252d28a90af8e3ca2f306cb673a0ce3325" {
			fmt.Printf("\n✓✓✓ SUCCESS! ✓✓✓\n")
			fmt.Printf("Index: %d\n", index)
			fmt.Printf("Derivation: %s\n", derivationNames[derivIdx])
			fmt.Printf("Formula: P = Hs(derivation || i)*G (without B)\n")
			fmt.Printf("Result: %s\n", result2)
			return true
		}

		// Print first attempt for debugging
		if derivIdx == 0 && index == 0 {
			fmt.Printf("\nIndex %d, %s:\n", index, derivationNames[derivIdx])
			fmt.Printf("  +B:  %s\n", result1)
			fmt.Printf("  noB: %s\n", result2)
		}
	}

	return false
}
