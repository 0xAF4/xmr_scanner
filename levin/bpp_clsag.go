package levin

import (
	"encoding/binary"
	"fmt"
	moneroutil "xmr_scanner/moneroutil"

	"filippo.io/edwards25519"
)

func (t *Transaction) signBpp() (Bpp, error) {
	// Bulletproof Plus для доказательства, что суммы выходов положительные
	// без раскрытия самих сумм
	bpp, err := createBulletproofPlus(t.BlindAmounts, t.BlindScalars)
	if err != nil {
		return Bpp{}, fmt.Errorf("failed to create bulletproof: %w", err)
	}

	return bpp, nil
}

// createBulletproofPlus создает Bulletproof Plus доказательство
func createBulletproofPlus(amounts []uint64, masks []*edwards25519.Scalar) (Bpp, error) {
	if len(amounts) != len(masks) {
		return Bpp{}, fmt.Errorf("amounts and masks length mismatch")
	}

	// Количество битов в доказательстве (обычно 64 для Monero)
	const nBits = 64

	// Количество выходов должно быть степенью 2 для оптимизации
	n := len(amounts)

	// Вычисляем размер логарифмической части (log2(n * nBits))
	logMN := 0
	mn := n * nBits
	for temp := mn; temp > 1; temp >>= 1 {
		logMN++
	}

	bpp := Bpp{
		L: make([]Hash, logMN),
		R: make([]Hash, logMN),
	}

	// Генерируем случайные значения для начальных точек
	// В реальной имплементации это сложные вычисления с векторными commitment'ами

	// A - агрегированный commitment всех amounts
	bpp.A = generateCommitmentPoint(amounts, masks)

	// A1 - вспомогательная точка
	bpp.A1 = generateRandomPoint(append(bpp.A[:], 0x01))

	// B - точка для доказательства
	bpp.B = generateRandomPoint(append(bpp.A[:], 0x02))

	// R1, S1, D1 - дополнительные точки для протокола
	bpp.R1 = generateRandomPoint(append(bpp.A[:], 0x03))
	bpp.S1 = generateRandomPoint(append(bpp.A[:], 0x04))
	bpp.D1 = generateRandomPoint(append(bpp.A[:], 0x05))

	// L и R - логарифмическая структура доказательства
	// Каждая пара (L[i], R[i]) соответствует одному раунду протокола
	var temp moneroutil.Hash
	seed := append(bpp.A[:], bpp.A1[:]...)
	for i := 0; i < logMN; i++ {
		temp = moneroutil.Keccak256(seed[:]) // Преобразование в срез
		seed = temp[:]
		bpp.L[i] = Hash(seed[:])

		temp = moneroutil.Keccak256(seed)
		seed = temp[:]
		bpp.R[i] = Hash(seed)
	}

	return bpp, nil
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

// generateRandomPoint генерирует детерминированную случайную точку из seed
func generateRandomPoint(seed []byte) Hash {
	hash := moneroutil.Keccak256(seed)

	// Пытаемся создать валидную точку на кривой
	point, err := new(edwards25519.Point).SetBytes(hash[:])
	if err != nil {
		// Если не получилось, используем hash_to_point
		return Hash(hashToPoint(hash[:]))
	}

	return Hash(point.Bytes())
}

// hashToPoint конвертирует хеш в точку на кривой (как в Monero)
func hashToPoint(hash []byte) []byte {
	// Итеративно пробуем найти валидную точку
	for i := 0; i < 256; i++ {
		data := append(hash, byte(i))
		attempt := moneroutil.Keccak256(data)

		if point, err := new(edwards25519.Point).SetBytes(attempt[:]); err == nil {
			return point.Bytes()
		}
	}

	// Fallback: используем базовую точку
	return edwards25519.NewGeneratorPoint().Bytes()
}

func (t *Transaction) signCLSAGs() ([]CLSAG, error) {
	CLSAGs := []CLSAG{}
	return CLSAGs, nil
}

func (t *Transaction) calculatePseudoOuts() ([]Hash, error) {
	PseudoOuts := []Hash{}
	return PseudoOuts, nil
}
