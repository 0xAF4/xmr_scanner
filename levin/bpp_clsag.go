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
	amounts := []uint64{}
	for _, val := range t.BlindAmounts {
		amounts = append(amounts, val)
	}
	// for _, _ = range t.BlindAmounts {
	// 	amounts = append(amounts, 0)
	// }

	bpp, err := createBulletproofPlus(amounts, t.BlindScalars)
	if err != nil {
		return Bpp{}, fmt.Errorf("failed to create bulletproof: %w", err)
	}

	return bpp, nil
}

// createBulletproofPlus создает Bulletproof Plus доказательство
// createBulletproofPlus создает Bulletproof Plus доказательство
func createBulletproofPlus(amounts []uint64, masks []*edwards25519.Scalar) (Bpp, error) {
	if len(amounts) != len(masks) {
		return Bpp{}, fmt.Errorf("amounts and masks length mismatch")
	}

	const nBits = 64
	n := len(amounts)

	// Вычисляем размер логарифмической части
	logMN := 0
	mn := n * nBits
	for temp := mn; temp > 1; temp >>= 1 {
		logMN++
	}

	bpp := Bpp{
		L: make([]Hash, logMN),
		R: make([]Hash, logMN),
	}

	// Генерируем криптографически стойкие случайные скаляры
	alpha := randomScalar()
	rho := randomScalar()

	// A = α*G + Σ(aL[i]*Gi + aR[i]*Hi)
	// где aL, aR - биты amounts
	bpp.A = computeA(amounts, alpha)

	// A1 = ρ*G + Σ(sL[i]*Gi + sR[i]*Hi)
	// где sL, sR - случайные маскирующие векторы
	sL, sR := generateBlindingVectors(n * nBits)
	bpp.A1 = computeA1(sL, sR, rho)

	// Вычисляем challenges (вызовы Fiat-Shamir)
	y := computeChallenge(append(bpp.A[:], bpp.A1[:]...))
	z := computeChallenge(append(y.Bytes(), bpp.A[:]...))

	// B связывает commitment с доказательством
	bpp.B = computeB(amounts, masks, y, z)

	// Вычисляем полиномиальные коэффициенты
	t1, t2 := computePolynomials(amounts, sL, sR, y, z)

	// R1 = t1*G
	bpp.R1 = Hash(new(edwards25519.Point).ScalarBaseMult(t1).Bytes())

	// S1 = t2*G
	bpp.S1 = Hash(new(edwards25519.Point).ScalarBaseMult(t2).Bytes())

	// Вычисляем x challenge
	x := computeChallenge(append(bpp.R1[:], bpp.S1[:]...))

	// D1 = d1*G + d2*H
	d1, d2 := computeD1Scalars(alpha, rho, t1, t2, x, z)
	bpp.D1 = computeD1(d1, d2)

	// Генерируем L и R для inner product argument
	// Это рекурсивный протокол сжатия векторов
	aL, aR := convertAmountsToBits(amounts, nBits)
	applyYPowers(aR, y)

	for i := 0; i < logMN; i++ {
		dL := randomScalar()
		dR := randomScalar()

		// L[i] и R[i] - это cross-term commitments
		bpp.L[i] = computeLR(aL, aR, dL, true, i)
		bpp.R[i] = computeLR(aL, aR, dR, false, i)

		// Fold vectors для следующего раунда
		challenge := computeChallenge(append(bpp.L[i][:], bpp.R[i][:]...))
		aL, aR = foldVectors(aL, aR, challenge, i)
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
	if len(t.Outputs) == 0 {
		return nil, fmt.Errorf("no outputs available")
	}

	pseudoOuts, err := t.calculatePseudoOuts()
	_ = pseudoOuts
	if err != nil {
		return nil, fmt.Errorf("failed to calculate pseudo outs: %w", err)
	}

	CLSAGs := make([]CLSAG, len(t.Outputs))

	for i, output := range t.Outputs {
		// Генерация CLSAG для каждого выхода
		keyImage := generateKeyImage(t.SecretKey, output.Target[:])
		pseudoOut := Hash{} // pseudoOuts[i]

		// Генерация значений для S, C1 и D
		S := generateSValues(t.SecretKey, output.Target[:])
		C1 := computeChallenge(append(pseudoOut[:], keyImage[:]...)) // Используем псевдо-выход и ключевое изображение
		D := keyImage                                                // Используем keyImage как D

		clsag := CLSAG{
			S:  S,
			C1: Hash(C1.Bytes()),
			D:  D,
		}
		CLSAGs[i] = clsag
	}

	return CLSAGs, nil
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

// generateSValues создает массив значений S для CLSAG
func generateSValues(secretKey Hash, target []byte) []Hash {
	sValues := make([]Hash, 10) // Пример: создаем 10 значений S
	for i := 0; i < len(sValues); i++ {
		data := append(secretKey[:], target...)
		data = append(data, byte(i))
		hash := moneroutil.Keccak256(data)
		sValues[i] = Hash(hash)
	}
	return sValues
}

func (t *Transaction) calculatePseudoOuts() ([]Hash, error) {
	if len(t.Inputs) == 0 {
		return nil, fmt.Errorf("no inputs available")
	}

	pseudoOuts := make([]Hash, len(t.Inputs))

	for i := range t.Inputs {
		// Декодируем адрес
		pubSpendKey, pubViewKey, err := DecodeAddress(t.Inputs[i].Address)
		if err != nil {
			return nil, fmt.Errorf("failed to decode address: %w", err)
		}

		// Вычисляем outPk
		_, outPk, err := CalcOutPk(0, pubViewKey[:], pubSpendKey[:], t.SecretKey[:], uint64(i))
		if err != nil {
			return nil, fmt.Errorf("failed to calculate output public key: %w", err)
		}

		// Сохраняем результат в pseudoOuts
		pseudoOuts[i] = Hash(outPk)
		// fmt.Printf("Hash(outPk): %x\n", Hash(outPk))
	}

	return pseudoOuts, nil
}
