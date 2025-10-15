package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"xmr_scanner/levin"
)

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hex decode failed: %v\n", err)
		os.Exit(2)
	}
	return b
}

func main() {
	privView := flag.String("privView", "", "private view key (hex, 32 bytes) - optional, needed to compute shared derivation")
	pubSpend := flag.String("pubSpend", "", "public spend key (hex, 32 bytes)")
	pubView := flag.String("pubView", "", "public view key (hex, 32 bytes)")
	txPub := flag.String("txPub", "", "transaction public key (hex, 32 bytes)")
	index := flag.Uint64("index", 0, "output index")
	flag.Parse()

	if *pubSpend == "" || *pubView == "" || *txPub == "" {
		fmt.Println("pubSpend, pubView and txPub are required")
		flag.Usage()
		os.Exit(2)
	}

	pubSpendB := mustHexDecode(*pubSpend)
	pubViewB := mustHexDecode(*pubView)
	txPubB := mustHexDecode(*txPub)

	fmt.Printf("pubSpend: %x\n", pubSpendB)
	fmt.Printf("pubView : %x\n", pubViewB)
	fmt.Printf("txPub   : %x\n", txPubB)
	fmt.Printf("index   : %d\n", *index)

	if *privView == "" {
		fmt.Println("privView not provided -> cannot compute shared secret; will only show public operations")
		// We can still call DerivePublicKeyWithViewTag if privView provided; otherwise abort
		os.Exit(0)
	}

	privViewB := mustHexDecode(*privView)

	derived, vt, err := levin.DerivePublicKeyWithViewTag(txPubB, privViewB, pubSpendB, *index)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DerivePublicKeyWithViewTag error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("derived one-time public key: %x\n", derived)
	fmt.Printf("view tag (first byte): %02x\n", vt)

	// ComputeViewTagForDebug returns the view-tag byte (for debugging)
	vtByte := levin.ComputeViewTagForDebug(txPubB, privViewB, *index)
	fmt.Printf("ComputeViewTagForDebug (byte): %02x\n", vtByte)
}
