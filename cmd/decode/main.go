package main

import (
	"crypto/sha256"
	"fmt"
	"xmr_scanner/levin"

	"golang.org/x/crypto/sha3"
)

func main() {
	addr := "49LNPHcXRMkRBA4biaciBd4qMwxH9f3PZGqgA2EYztksQ2yE43Tr8pa7ZjgksuVenfWcNGKqNeddGHWu7ejroEJvCcQRt73"
	raw, err := levin.DecodeAddressRaw(addr)
	if err != nil {
		fmt.Println("DecodeAddressRaw error:", err)
		return
	}

	fmt.Printf("decoded len: %d\n", len(raw))
	fmt.Printf("decoded hex: %x\n", raw)
	if len(raw) >= 69 {
		payload := raw[:65]
		sum := sha3.NewLegacyKeccak256()
		sum.Write(payload)
		h := sum.Sum(nil)
		fmt.Printf("keccak first4: %x\n", h[:4])
		fmt.Printf("addr checksum: %x\n", raw[65:69])

		// print sha256 of payload too just in case
		s2 := sha256.Sum256(payload)
		fmt.Printf("sha256 first4: %x\n", s2[:4])
	}
}
