package levin

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	moneroutil "xmr_scanner/moneroutil"

	"filippo.io/edwards25519"
)

func (t *Transaction) signBpp2() (Bpp, error) {
	// Bulletproof Plus требует правильного вычисления всех параметров
	bpp, err := createBulletproofPlus(t.BlindAmounts, t.BlindScalars)
	if err != nil {
		return Bpp{}, fmt.Errorf("failed to create bulletproof: %w", err)
	}

	return bpp, nil
}

// createBulletproofPlus создает Bulletproof Plus доказательство
func createBulletproofPlus2(amounts []uint64, masks []*edwards25519.Scalar) (Bpp, error) {
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

// randomScalar генерирует криптографически стойкий случайный скаляр
func randomScalar() *edwards25519.Scalar {
	var buf [64]byte
	rand.Read(buf[:])
	scalar := new(edwards25519.Scalar)
	scalar.SetUniformBytes(buf[:])
	return scalar
}

// computeA вычисляет начальный commitment A
func computeA(amounts []uint64, alpha *edwards25519.Scalar) Hash {
	// A = α*G + Σ(aL[i]*Gi + aR[i]*Hi)
	result := new(edwards25519.Point).ScalarBaseMult(alpha)

	// Для простоты используем упрощенную версию
	// В полной реализации нужны генераторы Gi, Hi
	for _, amount := range amounts {
		amountBytes := make([]byte, 32)
		binary.LittleEndian.PutUint64(amountBytes, amount)
		amountScalar := new(edwards25519.Scalar)
		amountScalar.SetCanonicalBytes(amountBytes)

		term := new(edwards25519.Point).ScalarBaseMult(amountScalar)
		result = new(edwards25519.Point).Add(result, term)
	}

	return Hash(result.Bytes())
}

// computeA1 вычисляет маскирующий commitment A1
func computeA1(sL, sR []*edwards25519.Scalar, rho *edwards25519.Scalar) Hash {
	// A1 = ρ*G + Σ(sL[i]*Gi + sR[i]*Hi)
	result := new(edwards25519.Point).ScalarBaseMult(rho)

	for i := range sL {
		term := new(edwards25519.Point).ScalarBaseMult(sL[i])
		result = new(edwards25519.Point).Add(result, term)

		term = new(edwards25519.Point).ScalarBaseMult(sR[i])
		result = new(edwards25519.Point).Add(result, term)
	}

	return Hash(result.Bytes())
}

// computeChallenge создает Fiat-Shamir challenge
func computeChallenge(data []byte) *edwards25519.Scalar {
	hash := moneroutil.Keccak256(data)
	hash64 := make([]byte, 64)
	copy(hash64, hash[:])

	scalar := new(edwards25519.Scalar)
	scalar.SetUniformBytes(hash64)
	return scalar
}

// computeB вычисляет commitment B
func computeB(amounts []uint64, masks []*edwards25519.Scalar, y, z *edwards25519.Scalar) Hash {
	// B = Σ(mask[i]*G + amount[i]*H) с модификациями от y и z
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

		commitment := new(edwards25519.Point).Add(maskG, amountH)
		result = new(edwards25519.Point).Add(result, commitment)
	}

	// Применяем challenges
	yInv := new(edwards25519.Scalar).Invert(y)
	result = new(edwards25519.Point).ScalarMult(yInv, result)

	return Hash(result.Bytes())
}

// computePolynomials вычисляет полиномиальные коэффициенты t1, t2
func computePolynomials(amounts []uint64, sL, sR []*edwards25519.Scalar, y, z *edwards25519.Scalar) (*edwards25519.Scalar, *edwards25519.Scalar) {
	// t(x) = <l(x), r(x)>
	// где l(x) = aL + sL*x, r(x) = aR + sR*x + y^n*z
	// t(x) = t0 + t1*x + t2*x^2

	t1 := randomScalar() // Упрощение
	t2 := randomScalar() // Упрощение

	// В полной реализации здесь сложные вычисления inner product

	return t1, t2
}

// computeD1Scalars вычисляет скаляры для D1
func computeD1Scalars(alpha, rho, t1, t2, x, z *edwards25519.Scalar) (*edwards25519.Scalar, *edwards25519.Scalar) {
	// d1 = α + ρ*x
	d1 := new(edwards25519.Scalar).Multiply(rho, x)
	d1 = new(edwards25519.Scalar).Add(alpha, d1)

	// d2 = t1*x + t2*x^2 + z*<aL, y^n>
	x2 := new(edwards25519.Scalar).Multiply(x, x)
	d2 := new(edwards25519.Scalar).Multiply(t2, x2)
	d2 = new(edwards25519.Scalar).Add(d2, new(edwards25519.Scalar).Multiply(t1, x))

	return d1, d2
}

// computeD1 вычисляет точку D1
func computeD1(d1, d2 *edwards25519.Scalar) Hash {
	// D1 = d1*G + d2*H
	G_d1 := new(edwards25519.Point).ScalarBaseMult(d1)
	H_d2 := new(edwards25519.Point).ScalarMult(d2, getH())
	result := new(edwards25519.Point).Add(G_d1, H_d2)

	return Hash(result.Bytes())
}

// generateBlindingVectors создает случайные маскирующие векторы
func generateBlindingVectors(size int) ([]*edwards25519.Scalar, []*edwards25519.Scalar) {
	sL := make([]*edwards25519.Scalar, size)
	sR := make([]*edwards25519.Scalar, size)

	for i := 0; i < size; i++ {
		sL[i] = randomScalar()
		sR[i] = randomScalar()
	}

	return sL, sR
}

// convertAmountsToBits конвертирует amounts в биты
func convertAmountsToBits(amounts []uint64, nBits int) ([]*edwards25519.Scalar, []*edwards25519.Scalar) {
	size := len(amounts) * nBits
	aL := make([]*edwards25519.Scalar, size)
	aR := make([]*edwards25519.Scalar, size)

	one := new(edwards25519.Scalar)
	oneBytes := make([]byte, 32)
	oneBytes[0] = 1
	one.SetCanonicalBytes(oneBytes)

	zero := new(edwards25519.Scalar)

	for i, amount := range amounts {
		for j := 0; j < nBits; j++ {
			idx := i*nBits + j
			bit := (amount >> j) & 1

			if bit == 1 {
				aL[idx] = one
				aR[idx] = zero
			} else {
				aL[idx] = zero
				// aR[idx] = -1 (в поле)
				aR[idx] = new(edwards25519.Scalar).Negate(one)
			}
		}
	}

	return aL, aR
}

// applyYPowers применяет степени y к вектору
func applyYPowers(vec []*edwards25519.Scalar, y *edwards25519.Scalar) {
	yPower := new(edwards25519.Scalar)
	yPowerBytes := make([]byte, 32)
	yPowerBytes[0] = 1
	yPower.SetCanonicalBytes(yPowerBytes)

	for i := range vec {
		vec[i] = new(edwards25519.Scalar).Multiply(vec[i], yPower)
		yPower = new(edwards25519.Scalar).Multiply(yPower, y)
	}
}

// computeLR вычисляет L или R для inner product
func computeLR(aL, aR []*edwards25519.Scalar, d *edwards25519.Scalar, isL bool, round int) Hash {
	result := new(edwards25519.Point).ScalarBaseMult(d)

	// Упрощенная версия
	// В полной реализации здесь сложные вычисления с векторами

	return Hash(result.Bytes())
}

// foldVectors складывает векторы для следующего раунда
func foldVectors(aL, aR []*edwards25519.Scalar, challenge *edwards25519.Scalar, round int) ([]*edwards25519.Scalar, []*edwards25519.Scalar) {
	half := len(aL) / 2
	newL := make([]*edwards25519.Scalar, half)
	newR := make([]*edwards25519.Scalar, half)

	for i := 0; i < half; i++ {
		// aL[i] = aL[i] + challenge*aL[i+half]
		term := new(edwards25519.Scalar).Multiply(challenge, aL[i+half])
		newL[i] = new(edwards25519.Scalar).Add(aL[i], term)

		// aR[i] = aR[i] + challenge^-1*aR[i+half]
		challengeInv := new(edwards25519.Scalar).Invert(challenge)
		term = new(edwards25519.Scalar).Multiply(challengeInv, aR[i+half])
		newR[i] = new(edwards25519.Scalar).Add(aR[i], term)
	}

	return newL, newR
}
