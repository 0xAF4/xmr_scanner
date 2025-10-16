package main

import (
	"encoding/hex"
	"fmt"
	"log"

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

func sc_reduce32Manual(in []byte) []byte {
	// Ed25519 order L (little-endian)
	L := []byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}

	result := make([]byte, 32)
	copy(result, in)

	// Check if reduction needed
	needsReduction := false
	for i := 31; i >= 0; i-- {
		if result[i] > L[i] {
			needsReduction = true
			break
		} else if result[i] < L[i] {
			break
		}
	}

	if needsReduction {
		borrow := 0
		for i := 0; i < 32; i++ {
			diff := int(result[i]) - int(L[i]) - borrow
			if diff < 0 {
				diff += 256
				borrow = 1
			} else {
				borrow = 0
			}
			result[i] = byte(diff)
		}
	}

	return result
}

func main() {
	txPubKey := mustHex("b8cdf95be694f3b0cbb5174ea1945f95097706adfc889a8d6be92d42b0cd06ff")
	privateViewKey := mustHex("7c14de0bd019c6cda063c2e458083d3c9f891a4b962cb730a83352da8d61f604")
	pubSpendKey := mustHex("cb7daf66af88f390889517765b175416ebbe384baa92945eb250aff05f30d489")

	// Try both index 0 and index 1
	for _, index := range []uint64{0, 1} {
		fmt.Printf("\n\n╔═══════════════════════════════════════════╗\n")
		fmt.Printf("║         TESTING WITH INDEX = %d           ║\n", index)
		fmt.Printf("╚═══════════════════════════════════════════╝\n")

		if testIndex(txPubKey, privateViewKey, pubSpendKey, index) {
			return
		}
	}

	fmt.Println("\n✗✗✗ NO MATCH FOUND WITH ANY COMBINATION ✗✗✗")
	fmt.Println("Expected either:")
	fmt.Println("  f293d8f16ea0dbac4bb71c7c95604d276092dabe0d907609a801cee3692c6e0c")
	fmt.Println("  41374d00ff602ddbfcd65873df41e1d083399f4c7eb6807c8603300951f117e0")
}

func testIndex(txPubKey, privateViewKey, pubSpendKey []byte, index uint64) bool {

	fmt.Println("=== Input Data ===")
	fmt.Printf("txPubKey (R): %x\n", txPubKey)
	fmt.Printf("privateViewKey (a): %x\n", privateViewKey)
	fmt.Printf("pubSpendKey (B): %x\n", pubSpendKey)
	fmt.Printf("index: %d\n", index)

	// Step 1: Parse R
	var R edwards25519.Point
	if _, err := R.SetBytes(txPubKey); err != nil {
		log.Fatal("Failed to parse R:", err)
	}
	fmt.Printf("\n✓ R parsed successfully\n")

	// Step 2: Parse a
	var a edwards25519.Scalar
	if _, err := a.SetCanonicalBytes(privateViewKey); err != nil {
		log.Println("Warning: using SetUniformBytes for a")
		a.SetUniformBytes(append(privateViewKey, privateViewKey...))
	}
	fmt.Printf("✓ a parsed successfully\n")

	// Step 3: Calculate a * R (without 8)
	aR := new(edwards25519.Point).ScalarMult(&a, &R)
	fmt.Printf("\n=== Step 3: a * R ===\n")
	fmt.Printf("a * R: %x\n", aR.Bytes())

	// Step 4: Calculate 8 * (a * R)
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	var eight edwards25519.Scalar
	eight.SetCanonicalBytes(eightBytes)

	derivation1 := new(edwards25519.Point).ScalarMult(&eight, aR)
	fmt.Printf("\n=== Method 1: 8 * (a * R) ===\n")
	fmt.Printf("derivation: %x\n", derivation1.Bytes())

	// Step 5: Alternative - Calculate (8*a) * R
	var eightA edwards25519.Scalar
	eightA.Multiply(&eight, &a)

	derivation2 := new(edwards25519.Point).ScalarMult(&eightA, &R)
	fmt.Printf("\n=== Method 2: (8*a) * R ===\n")
	fmt.Printf("derivation: %x\n", derivation2.Bytes())

	// Step 5b: Try WITHOUT multiplying by 8
	derivation3 := new(edwards25519.Point).ScalarMult(&a, &R)
	fmt.Printf("\n=== Method 3: a * R (NO 8x) ===\n")
	fmt.Printf("derivation: %x\n", derivation3.Bytes())

	// Test both derivations
	derivations := [][]byte{derivation2.Bytes(), derivation3.Bytes()}
	derivationNames := []string{"with 8x", "without 8x"}

	// Test both derivations
	derivations = [][]byte{derivation2.Bytes(), derivation3.Bytes()}
	derivationNames = []string{"with 8x", "without 8x"}

	for derivIdx, derivation := range derivations {
		fmt.Printf("\n\n========== TESTING DERIVATION: %s ==========\n", derivationNames[derivIdx])

		// Step 6: Create hash input
		idxBytes := encodeVarint(index)
		fmt.Printf("\n=== Step 6: Hash Input ===\n")
		fmt.Printf("index varint: %x\n", idxBytes)

		hashInput := append(derivation, idxBytes...)
		fmt.Printf("hash input: %x\n", hashInput)

		// Step 7: Hash
		h := keccak256(hashInput)
		fmt.Printf("\n=== Step 7: Keccak256 ===\n")
		fmt.Printf("hash: %x\n", h)

		// Step 8: Try different scalar reduction methods
		fmt.Printf("\n=== Step 8: Reduce scalar ===\n")

		// Method 1: SetBytesWithClamping
		var s1 edwards25519.Scalar
		s1Bytes, err := s1.SetBytesWithClamping(h)
		if err != nil {
			log.Fatal("SetBytesWithClamping failed:", err)
		}

		// Method 2: Use SetUniformBytes with 64 bytes
		var s2 edwards25519.Scalar
		s2.SetUniformBytes(append(h, h...))

		// Method 3: Manual reduction
		scalarReduced := sc_reduce32Manual(h)
		var s3 edwards25519.Scalar
		if _, err2 := s3.SetCanonicalBytes(scalarReduced); err2 != nil {
			s3.SetUniformBytes(append(scalarReduced, scalarReduced...))
		}

		// Try all three methods
		for i, s := range []*edwards25519.Scalar{s1Bytes, &s2, &s3} {
			// Step 9: s * G
			hsG := new(edwards25519.Point).ScalarBaseMult(s)

			// Step 10: Parse B
			var B edwards25519.Point
			if _, err := B.SetBytes(pubSpendKey); err != nil {
				log.Fatal("Failed to parse B:", err)
			}

			// Step 11a: P = (s*G) + B (standard)
			P1 := new(edwards25519.Point).Add(hsG, &B)
			result1 := hex.EncodeToString(P1.Bytes())

			// Step 11b: P = s*G (without B) - for RingCT v2+
			result2 := hex.EncodeToString(hsG.Bytes())

			// Check both possible expected values
			for _, result := range []string{result1, result2} {
				if result == "f293d8f16ea0dbac4bb71c7c95604d276092dabe0d907609a801cee3692c6e0c" {
					fmt.Printf("\n✓✓✓ SUCCESS! Derivation=%s, Scalar Method=%d ✓✓✓\n", derivationNames[derivIdx], i+1)
					fmt.Printf("Matched first expected: %s\n", result)
					if result == result2 {
						fmt.Println("Formula: P = Hs(...)*G (without B)")
					} else {
						fmt.Println("Formula: P = Hs(...)*G + B")
					}
					return true
				}
				if result == "41374d00ff602ddbfcd65873df41e1d083399f4c7eb6807c8603300951f117e0" {
					fmt.Printf("\n✓✓✓ SUCCESS! Derivation=%s, Scalar Method=%d ✓✓✓\n", derivationNames[derivIdx], i+1)
					fmt.Printf("Matched second expected: %s\n", result)
					if result == result2 {
						fmt.Println("Formula: P = Hs(...)*G (without B)")
					} else {
						fmt.Println("Formula: P = Hs(...)*G + B")
					}
					return true
				}
			}

			// Print all results for comparison (only first method to reduce noise)
			if i == 0 {
				fmt.Printf("Deriv=%s, +B: %s\n", derivationNames[derivIdx], result1)
				fmt.Printf("Deriv=%s, noB: %s\n", derivationNames[derivIdx], result2)
			}
		}
	}

	return false
}
