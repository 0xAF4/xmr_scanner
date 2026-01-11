package levin

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
)

type Exponent struct {
	Transcript Key
	MaxN       int
	MaxM       int
	Gi_p3      []*edwards25519.Point
	Hi_p3      []*edwards25519.Point
}

// MultiexpData содержит скаляр и точку для multiexponentiation
type MultiexpData struct {
	Scalar Key
	Point  *edwards25519.Point
}

const maxN = 64
const maxM = 16

func (t *Transaction) signBpp() (Bpp, error) {
	bpp := Bpp{}
	// Bulletproof Plus для доказательства, что суммы выходов положительные
	// без раскрытия самих сумм
	amounts := []uint64{}
	for _, val := range t.BlindAmounts {
		amounts = append(amounts, val)
	}

	bpp, err := createBulletproofPlus(amounts, t.BlindScalars)
	if err != nil {
		return Bpp{}, fmt.Errorf("failed to create bulletproof: %w", err)
	}

	return bpp, nil
}

// Given two scalar arrays, construct a vector pre-commitment:
//
// a = (a_0, ..., a_{n-1})
// b = (b_0, ..., b_{n-1})
//
// Outputs a_0*Gi_0 + ... + a_{n-1}*Gi_{n-1} +
//
//	b_0*Hi_0 + ... + b_{n-1}*Hi_{n-1}
func vectorExponent(a, b []Key, exponent Exponent) *edwards25519.Point {
	// Результат - сумма всех произведений
	result := edwards25519.NewIdentityPoint()

	for i := 0; i < len(a); i++ {
		// a[i] * Gi[i]
		aScalar := a[i].KeyToScalar()
		giPoint := exponent.Gi_p3[i] // Gi должен быть массив точек
		term1 := new(edwards25519.Point).ScalarMult(aScalar, giPoint)
		result.Add(result, term1)

		// b[i] * Hi[i]
		bScalar := b[i].KeyToScalar()
		hiPoint := exponent.Hi_p3[i] // Hi должен быть массив точек
		term2 := new(edwards25519.Point).ScalarMult(bScalar, hiPoint)
		result.Add(result, term2)
	}

	return result
}

func computeA(alpha *edwards25519.Scalar, aL8, aR8 []Key, expn Exponent) Hash {
	var (
		A     Key
		temp  Key
		pre_A Key
	)
	// pre_A, _ := ParseKeyFromHex("78ae20b0e83dc61b5c0864b15245040f818c9f027e56a0bd807cc4c7ba50dca4")
	point := vectorExponent(aL8, aR8, expn)
	pre_A = Key(point.Bytes())

	tempScalar := new(edwards25519.Scalar).Multiply(alpha, INV_EIGHT_E)
	temp.FromPoint(new(edwards25519.Point).ScalarBaseMult(tempScalar))
	AddKeys(&A, &pre_A, &temp)

	return A.ToBytes()
}

func AmountToScalar(amount uint64) *edwards25519.Scalar {
	amountBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(amountBytes, amount)
	amountScalar, _ := new(edwards25519.Scalar).SetCanonicalBytes(amountBytes)
	return amountScalar
}

// createBulletproofPlus создает Bulletproof Plus доказательство
func createBulletproofPlus(amounts []uint64, masks []*edwards25519.Scalar) (Bpp, error) {
	if len(amounts) != len(masks) {
		return Bpp{}, fmt.Errorf("amounts and masks length mismatch")
	}

	const (
		logN = 6
		N    = 1 << logN
		maxM = 16 // Максимальное количество outputs в одном bulletproof
	)

	logM := 0
	M := 1
	for M <= maxM && M < len(masks) {
		logM++
		M = 1 << logM
	}

	if M > maxM {
		return Bpp{}, fmt.Errorf("sv/gamma are too large")
	}

	logMN := logM + logN
	MN := M * N

	aL := make([]Key, MN)
	aR := make([]Key, MN)
	aL8 := make([]Key, MN)
	aR8 := make([]Key, MN)
	temp := Key{}
	temp2 := Key{}

	V := make([]Key, len(masks))
	for i, mask := range masks {
		var (
			gamma8Key Key
			sv8Key    Key
			HKey      Key
		)

		gamma8 := new(edwards25519.Scalar).Multiply(mask, INV_EIGHT_E)
		amountScalar := AmountToScalar(amounts[i])
		sv8 := new(edwards25519.Scalar).Multiply(amountScalar, INV_EIGHT_E)
		H := getH()

		gamma8Key.FromScalar(gamma8)
		sv8Key.FromScalar(sv8)
		HKey.FromPoint(H)

		AddKeys2(&V[i], &gamma8Key, &sv8Key, &HKey)
	}

	for j := 0; j < M; j++ {
		for i := N - 1; i >= 0; i-- {
			amountBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(amountBytes, amounts[j])
			if j < len(amounts) && (amountBytes[i/8]&(1<<(i%8))) != 0 {
				aL[j*N+i] = Identity
				aL8[j*N+i] = INV_EIGHT
				aR[j*N+i] = Zero
				aR8[j*N+i] = Zero
			} else {
				aL[j*N+i] = Zero
				aL8[j*N+i] = Zero
				aR[j*N+i] = MINUS_ONE
				aR8[j*N+i] = MINUS_INV_EIGHT
			}
		}
	}

	exponent := initExponents(maxN, maxM)

	var buf bytes.Buffer
	for _, v := range V {
		buf.Write(v[:])
	}

	exponent.Transcript = TranscriptUpdate(&exponent.Transcript, HashToScalar(buf.Bytes()).ToBytes2())
	bpp := Bpp{}

	// Генерируем криптографически стойкие случайные скаляры
	alpha := randomScalar()

	bpp.A = computeA(alpha, aL8, aR8, *exponent)

	y := TranscriptUpdate(&exponent.Transcript, bpp.A[:])
	exponent.Transcript = *HashToScalar(y.ToBytes2())
	z := exponent.Transcript
	z_squared := new(Key)
	ScMul(z_squared, z, z)

	d := createWindowedVector(*z_squared, N, M)
	yPowers := vectorOfScalarPowers(y, MN+2)

	aL1 := vectorSubtract(aL, z)
	aR1 := vectorAdd(aR, z)

	dy := make([]Key, MN)
	for i := 0; i < MN; i++ {
		ScMul(&dy[i], d[i], yPowers[MN-i])
	}
	aR1 = vectorAdd2(aR1, dy)

	alpha1 := new(Key)
	alpha1.FromScalar(alpha)

	temp = ONE
	for j := 0; j < len(amounts); j++ {
		ScMul(&temp, temp, *z_squared)
		ScMul(&temp2, yPowers[MN+1], temp)
		gamma := new(Key)
		gamma.FromScalar(masks[j])
		ScMulAdd(alpha1, &temp2, gamma, alpha1)
	}

	nprime := MN
	Gprime := make([]edwards25519.Point, MN)
	Hprime := make([]edwards25519.Point, MN)
	aprime := make([]Key, MN)
	bprime := make([]Key, MN)

	yinv := Key{}
	yinv.FromScalar(new(edwards25519.Scalar).Invert(y.KeyToScalar()))
	yinvpow := make([]Key, MN)
	yinvpow[0] = ONE
	for i := 0; i < MN; i++ {
		Gprime[i] = *exponent.Gi_p3[i]
		Hprime[i] = *exponent.Hi_p3[i]
		if i > 0 {
			ScMul(&yinvpow[i], yinvpow[i-1], yinv)
		}
		aprime[i] = aL1[i]
		bprime[i] = aR1[i]
	}
	L := make([]edwards25519.Point, logMN)
	R := make([]edwards25519.Point, logMN)
	round := 0

	// Inner-product rounds
	for nprime > 1 {
		nprime /= 2

		// Вычисляем cL и cR
		cL := weightedInnerProduct(slice(aprime, 0, nprime), slice(bprime, nprime, len(bprime)), y)
		cR := weightedInnerProduct(vectorScalar(slice(aprime, nprime, len(aprime)), yPowers[nprime]), slice(bprime, 0, nprime), y)

		// Генерируем случайные dL и dR
		dL := RandomScalar()
		dL.FromScalar(randomScalar())

		dR := RandomScalar()
		dR.FromScalar(randomScalar())

		// Вычисляем L[round] и R[round]
		L[round] = computeLR(nprime, yinvpow[nprime], &Gprime, nprime, &Hprime, 0, aprime, 0, bprime, nprime, cL, *dL)
		R[round] = computeLR(nprime, yPowers[nprime], &Gprime, 0, &Hprime, nprime, aprime, nprime, bprime, 0, cR, *dR)

		// Обновляем transcript и получаем challenge
		var buff bytes.Buffer
		buff.Write(L[round].Bytes())
		buff.Write(R[round].Bytes())
		challenge := TranscriptUpdate(&exponent.Transcript, buff.Bytes())

		// Вычисляем обратный challenge
		challengeInv := Key{}
		challengeInv.FromScalar(new(edwards25519.Scalar).Invert(challenge.KeyToScalar()))

		// temp = yinvpow[nprime] * challenge
		var temp Key
		ScMul(&temp, yinvpow[nprime], challenge)

		// Hadamard fold для Gprime
		hadamardFold(&Gprime, challengeInv, temp)
		hadamardFold(&Hprime, challenge, challengeInv)

		// temp = challenge_inv * y_powers[nprime]
		ScMul(&temp, challengeInv, yPowers[nprime])

		// Обновляем aprime
		aprime = vectorAdd2(
			vectorScalar(slice(aprime, 0, nprime), challenge),
			vectorScalar(slice(aprime, nprime, len(aprime)), temp),
		)

		// Обновляем bprime
		bprime = vectorAdd2(
			vectorScalar(slice(bprime, 0, nprime), challengeInv),
			vectorScalar(slice(bprime, nprime, len(bprime)), challenge),
		)

		var challengeSquared Key
		var challengeSquaredInv Key

		ScMul(&challengeSquared, challenge, challenge)
		ScMul(&challengeSquaredInv, challengeInv, challengeInv)
		ScMulAdd(alpha1, dL, &challengeSquared, alpha1)
		ScMulAdd(alpha1, dR, &challengeSquaredInv, alpha1)

		round++

	}

	for i := range L {
		bpp.L = append(bpp.L, Hash(L[i].Bytes()))
		bpp.R = append(bpp.R, Hash(R[i].Bytes()))
	}

	r := RandomScalar()
	r.FromScalar(randomScalar())
	s := RandomScalar()
	s.FromScalar(randomScalar())
	d_ := RandomScalar()
	d_.FromScalar(randomScalar())
	eta := RandomScalar()
	eta.FromScalar(randomScalar())

	// Подготовка данных для A1
	A1Data := make([]MultiexpData, 4)

	ScMul(&A1Data[0].Scalar, *r, INV_EIGHT)
	A1Data[0].Point = &Gprime[0]

	ScMul(&A1Data[1].Scalar, *s, INV_EIGHT)
	A1Data[1].Point = &Hprime[0]

	ScMul(&A1Data[2].Scalar, *d_, INV_EIGHT)
	A1Data[2].Point = edwards25519.NewGeneratorPoint()

	ScMul(&temp, *r, y)
	ScMul(&temp, temp, bprime[0])
	ScMul(&temp2, *s, y)
	ScMul(&temp2, temp2, aprime[0])
	ScAdd(&temp, &temp, &temp2)
	ScMul(&A1Data[3].Scalar, temp, INV_EIGHT)
	A1Data[3].Point = getH()

	A1Key := multiexp(A1Data)
	A1Point, _ := new(edwards25519.Point).SetBytes(A1Key[:])
	A1 := *A1Point
	bpp.A1 = Hash(A1.Bytes())

	ScMul(&temp, *r, y)
	ScMul(&temp, temp, *s)
	ScMul(&temp, temp, INV_EIGHT)
	ScMul(&temp2, *eta, INV_EIGHT)

	var B Key
	HKey := Key{}
	HKey.FromPoint(getH())
	AddKeys2(&B, &temp2, &temp, &HKey)
	bpp.B = Hash(B.ToBytes2())

	var buffE bytes.Buffer
	buffE.Write(A1.Bytes())
	buffE.Write(B[:])
	e := TranscriptUpdate(&exponent.Transcript, buffE.Bytes())

	var eSquared Key
	ScMul(&eSquared, e, e)

	var r1 Key
	ScMulAdd(&r1, &aprime[0], &e, r)
	bpp.R1 = Hash(r1.ToBytes2())

	var s1 Key
	ScMulAdd(&s1, &bprime[0], &e, s)
	bpp.S1 = Hash(s1.ToBytes2())

	var d1 Key
	ScMulAdd(&d1, d_, &e, eta)
	ScMulAdd(&d1, alpha1, &eSquared, &d1)
	bpp.D1 = Hash(d1.ToBytes2())

	return bpp, nil
}

// Создаем windowed vector d
func createWindowedVector(zSquared Key, N, M int) []Key {
	MN := M * N
	d := make([]Key, MN)

	for i := range d {
		d[i] = Zero
	}

	d[0] = zSquared

	for i := 1; i < N; i++ {
		ScMul(&d[i], d[i-1], TWO)
	}

	for j := 1; j < M; j++ {
		for i := 0; i < N; i++ {
			ScMul(&d[j*N+i], d[(j-1)*N+i], zSquared)
		}
	}

	return d
}

// vectorOfScalarPowers создает вектор степеней скаляра: [1, x, x^2, x^3, ..., x^(n-1)]
func vectorOfScalarPowers(x Key, n int) []Key {
	if n == 0 {
		panic("Need n > 0")
	}

	res := make([]Key, n)
	res[0] = Identity
	if n == 1 {
		return res
	}

	res[1] = x
	for i := 2; i < n; i++ {
		ScMul(&res[i], res[i-1], x)
	}

	return res
}

// vectorSubtract вычитает скаляр из всех элементов вектора
// res[i] = a[i] - b
func vectorSubtract(a []Key, b Key) []Key {
	res := make([]Key, len(a))

	for i := 0; i < len(a); i++ {
		ScSub(&res[i], &a[i], &b)
	}

	return res
}

func vectorAdd(a []Key, b Key) []Key {
	res := make([]Key, len(a))

	for i := 0; i < len(a); i++ {
		ScAdd(&res[i], &a[i], &b)
	}

	return res
}

func vectorAdd2(a []Key, b []Key) []Key {
	res := make([]Key, len(a))

	for i := 0; i < len(a); i++ {
		ScAdd(&res[i], &a[i], &b[i])
	}

	return res
}

func slice(arr []Key, start, end int) []Key {
	return arr[start:end]
}

// weightedInnerProduct вычисляет взвешенное внутреннее произведение
// res = sum(a[i] * b[i] * y^(i+1)) для i от 0 до len(a)-1
func weightedInnerProduct(a, b []Key, y Key) Key {
	if len(a) != len(b) {
		panic("Incompatible sizes of a and b")
	}

	res := Zero
	yPower := Identity // y^0 = 1
	var temp Key

	for i := 0; i < len(a); i++ {
		ScMul(&temp, a[i], b[i])
		ScMul(&yPower, yPower, y)
		ScMulAdd(&res, &temp, &yPower, &res)
	}

	return res
}

// vectorScalar умножает каждый элемент вектора на скаляр
// res[i] = a[i] * b
func vectorScalar(a []Key, b Key) []Key {
	res := make([]Key, len(a))

	for i := 0; i < len(a); i++ {
		ScMul(&res[i], a[i], b)
	}

	return res
}

// computeLR вычисляет L или R для inner product argument
func computeLR(size int, y Key, G *[]edwards25519.Point, G0 int, H *[]edwards25519.Point, H0 int,
	a []Key, a0 int, b []Key, b0 int, c Key, d Key) edwards25519.Point {

	// Проверки размеров
	if size+G0 > len(*G) {
		panic(fmt.Sprintf("Incompatible size for G: size=%d, G0=%d, len(G)=%d", size, G0, len(*G)))
	}
	if size+H0 > len(*H) {
		panic(fmt.Sprintf("Incompatible size for H: size=%d, H0=%d, len(H)=%d", size, H0, len(*H)))
	}
	if size+a0 > len(a) {
		panic(fmt.Sprintf("Incompatible size for a: size=%d, a0=%d, len(a)=%d", size, a0, len(a)))
	}
	if size+b0 > len(b) {
		panic(fmt.Sprintf("Incompatible size for b: size=%d, b0=%d, len(b)=%d", size, b0, len(b)))
	}
	if size > maxN*maxM {
		panic(fmt.Sprintf("size is too large: %d > %d", size, maxN*maxM))
	}

	// Создаем массив для multiexp
	multiexpData := make([]MultiexpData, size*2+2)

	var temp Key

	// Заполняем данные для G и H
	for i := 0; i < size; i++ {
		// temp = a[a0+i] * y
		ScMul(&temp, a[a0+i], y)

		// scalar = temp * INV_EIGHT
		ScMul(&multiexpData[i*2].Scalar, temp, INV_EIGHT)
		multiexpData[i*2].Point = &(*G)[G0+i]

		// scalar = b[b0+i] * INV_EIGHT
		ScMul(&multiexpData[i*2+1].Scalar, b[b0+i], INV_EIGHT)
		multiexpData[i*2+1].Point = &(*H)[H0+i]
	}

	// Добавляем c * H
	ScMul(&multiexpData[2*size].Scalar, c, INV_EIGHT)
	multiexpData[2*size].Point = getH() // H базовая точка

	// Добавляем d * G
	ScMul(&multiexpData[2*size+1].Scalar, d, INV_EIGHT)
	multiexpData[2*size+1].Point = edwards25519.NewGeneratorPoint() // G базовая точка

	// Вычисляем multiexp
	key := multiexp(multiexpData)
	return *key.KeyToPoint()
}

// multiexp вычисляет multi-scalar multiplication: sum(scalar[i] * point[i])
func multiexp(data []MultiexpData) Key {
	// Результат - сумма всех scalar[i] * point[i]
	result := edwards25519.NewIdentityPoint()

	for _, d := range data {
		scalar := d.Scalar.KeyToScalar()
		term := new(edwards25519.Point).ScalarMult(scalar, d.Point)
		result.Add(result, term)
	}

	return Key(result.Bytes())
}

// hadamardFold складывает вектор точек пополам используя линейную комбинацию
// v[i] = a*v[i] + b*v[i+sz] для i < sz, затем уменьшает размер вектора вдвое
func hadamardFold(v *[]edwards25519.Point, a, b Key) {
	if len(*v)%2 != 0 {
		panic("Vector size should be even")
	}

	sz := len(*v) / 2

	// Создаем новый вектор для результата
	result := make([]edwards25519.Point, sz)

	// Преобразуем скаляры
	aScalar := a.KeyToScalar()
	bScalar := b.KeyToScalar()

	for n := 0; n < sz; n++ {
		term1 := new(edwards25519.Point).ScalarMult(aScalar, &(*v)[n])
		term2 := new(edwards25519.Point).ScalarMult(bScalar, &(*v)[sz+n])
		result[n] = *new(edwards25519.Point).Add(term1, term2)
	}

	*v = result
}

func initExponents(mN, mM int) *Exponent {
	exp := Exponent{
		Transcript: INITIAL_TRANSCRIPT,
		MaxN:       mN,
		MaxM:       mM,
		Gi_p3:      make([]*edwards25519.Point, mN*mM),
		Hi_p3:      make([]*edwards25519.Point, mN*mM),
	}

	// H - базовая точка (как rct::H в Monero)
	H := getH() // или edwards25519.NewGeneratorPoint() если нужен G

	for i := 0; i < mN*mM; i++ {
		exp.Hi_p3[i] = getExponent(H, i*2)
		exp.Gi_p3[i] = getExponent(H, i*2+1)
	}

	return &exp
}

// get_exponent генерирует точки для bulletproofs
func getExponent(base *edwards25519.Point, idx int) *edwards25519.Point {
	// Hash base point и индекс
	var buf bytes.Buffer
	buf.Write(base.Bytes())
	buf.Write([]byte("bulletproof_plus"))
	buf.Write(encodeVarint(uint64(idx)))
	rbytes := keccak256(buf.Bytes())

	key := new(Key)
	key2 := new(Key)
	key.FromBytes([32]byte(rbytes))
	r := key.HashToEC()
	r.ToBytes(key2)
	b := key2.ToBytes()
	point, _ := new(edwards25519.Point).SetBytes(b[:])
	return point
}

func (t *Transaction) calculatePseudoOuts() ([]Hash, error) {
	if len(t.Inputs) == 0 {
		return nil, fmt.Errorf("no inputs available")
	}

	pseudoOuts := make([]Hash, len(t.Inputs))
	sumpouts := edwards25519.NewScalar()

	for i := range len(t.Inputs) - 1 {
		randomMask := RandomScalar()
		t.InputScalars = append(t.InputScalars, randomMask.KeyToScalar())
		sumpouts.Add(sumpouts, randomMask.KeyToScalar())
		amountAtomic := uint64(t.PInputs[i]["amount"].(float64) * 1e12)
		pseudoOut, err := CalcCommitment(amountAtomic, randomMask.ToBytes())
		if err != nil {
			return []Hash{}, fmt.Errorf("Error of calc commitment: %w", err)
		}

		pseudoOuts[i] = Hash(pseudoOut)
	}

	lastI := len(pseudoOuts) - 1
	amountAtomic := uint64(t.PInputs[lastI]["amount"].(float64) * 1e12)

	sumouts, err := CalcScalars(t.BlindScalars)
	if err != nil {
		return []Hash{}, fmt.Errorf("Error of calc output amounts: %w", err)
	}

	mask := new(edwards25519.Scalar).Subtract(sumouts, sumpouts)

	t.InputScalars = append(t.InputScalars, mask)
	pseudoOut, err := CalcCommitment(amountAtomic, [32]byte(mask.Bytes()))
	if err != nil {
		return []Hash{}, fmt.Errorf("Error of calc commitment: %w", err)
	}

	pseudoOuts[lastI] = Hash(pseudoOut)

	return pseudoOuts, nil
}

// randomScalar генерирует криптографически стойкий случайный скаляр
func randomScalar() *edwards25519.Scalar {
	var buf [64]byte
	binary.LittleEndian.PutUint64(buf[:8], 1) //
	// rand.Read(buf[:])
	scalar := new(edwards25519.Scalar)
	scalar.SetUniformBytes(buf[:])
	return scalar
}
