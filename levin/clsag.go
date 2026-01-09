package levin

import (
	"encoding/binary"
	"fmt"
	moneroutil "xmr_scanner/moneroutil"

	"filippo.io/edwards25519"
)

func (t *Transaction) signCLSAGs(tx1 Transaction) ([]CLSAG, error) {
	if len(t.Outputs) == 0 {
		return nil, fmt.Errorf("no outputs available")
	}
	if len(t.Inputs) == 0 {
		return nil, fmt.Errorf("no inputs available")
	}

	CLSAGs := make([]CLSAG, len(t.Inputs))

	// Получаем full_message один раз для всех входов
	full_message, err := GetFullMessage(t.RctSignature)
	if err != nil {
		return nil, err
	}
	_ = full_message

	for i, input := range t.Inputs {
		clsag := CLSAG{}

		for range len(input.KeyOffsets) {
			key := moneroutil.RandomScalar()
			key.FromScalar(randomScalar())
			clsag.S = append(clsag.S, Hash(key.ToBytes()))
		}

		full_message, err := GetFullMessage(t.RctSignature)
		if err != nil {
			return nil, err
		}
		_ = full_message

		// fasdmt.Printf("a[i]=%x\n", t.InputScalars[i].Bytes())
		// fasdmt.Printf("pseudoOuts[i]=%x\n", t.RctSigPrunable.PseudoOuts[i])
		// os.Exit(333)

		// rv.p.CLSAGs[i] = proveRctCLSAGSimple(full_message??, rv.mixRing[i]??, inSk[i]??, t.InputScalars[i], t.RctSigPrunable.PseudoOuts[i], index[i]??, hwdev??);

		d, c1, err := SignInput(t.PrefixHash(), t.RctSigPrunable.PseudoOuts[i], input.KeyImage, clsag.S)
		if err != nil {
			return []CLSAG{}, fmt.Errorf("Error during creation of clsag: %e", err)
		}
		clsag.D = d
		clsag.C1 = c1

		CLSAGs[i] = clsag
	}

	return CLSAGs, nil
}

func SignInput(prefixHash, pseudoOut, KeyImage Hash, S []Hash) (d, c1 Hash, err error) {
	return
}

// generateKeyImage создает ключевое изображение на основе секретного ключа и цели
func generateKeyImage(secretKey Hash, target []byte) Hash {
	data := append(secretKey[:], target...)
	hash := moneroutil.Keccak256(data)
	_ = hash
	scl := new(edwards25519.Scalar)
	scalar := new(edwards25519.Scalar)
	if _, err := scalar.SetCanonicalBytes(secretKey[:]); err != nil {
		if _, err2 := scalar.SetBytesWithClamping(secretKey[:]); err2 != nil {
			panic(err2)
		}
	}
	point := new(edwards25519.Point).ScalarBaseMult(scl)
	return Hash(point.Bytes())
}

// generateCommitmentPoint создает Pedersen commitment для массива сумм
func generateCommitmentPoint(amounts []uint64, masks []*edwards25519.Scalar) Hash {
	// C = sum(mask[i] * G + amount[i] * H)
	result := edwards25519.NewIdentityPoint()
	H := getH()

	for i, amount := range amounts {
		// mask[i] * G
		maskG := new(edwards25519.Point).ScalarBaseMult(masks[i])

		// amount[i] * H
		amountBytes := make([]byte, 32)
		binary.LittleEndian.PutUint64(amountBytes, amount)
		amountScalar := new(edwards25519.Scalar)
		amountScalar.SetCanonicalBytes(amountBytes)
		amountH := new(edwards25519.Point).ScalarMult(amountScalar, H)

		// Суммируем
		commitment := new(edwards25519.Point).Add(maskG, amountH)
		result = new(edwards25519.Point).Add(result, commitment)
	}

	return Hash(result.Bytes())
}
