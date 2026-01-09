package levin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	moneroutil "xmr_scanner/moneroutil"

	"filippo.io/edwards25519"
)

type Exponent struct {
	Transcript moneroutil.Key
	MaxN       int
	MaxM       int
	Gi_p3      []*edwards25519.Point
	Hi_p3      []*edwards25519.Point
}

// MultiexpData содержит скаляр и точку для multiexponentiation
type MultiexpData struct {
	Scalar moneroutil.Key
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
func vectorExponent(a, b []moneroutil.Key, exponent Exponent) *edwards25519.Point {
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

func computeA(alpha *edwards25519.Scalar, aL8, aR8 []moneroutil.Key, expn Exponent) Hash {
	var (
		A     moneroutil.Key
		temp  moneroutil.Key
		pre_A moneroutil.Key
	)
	// pre_A, _ := moneroutil.ParseKeyFromHex("78ae20b0e83dc61b5c0864b15245040f818c9f027e56a0bd807cc4c7ba50dca4")
	point := vectorExponent(aL8, aR8, expn)
	pre_A = moneroutil.Key(point.Bytes())

	tempScalar := new(edwards25519.Scalar).Multiply(alpha, INV_EIGHT)
	temp.FromPoint(new(edwards25519.Point).ScalarBaseMult(tempScalar))
	moneroutil.AddKeys(&A, &pre_A, &temp)

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

	aL := make([]moneroutil.Key, MN)
	aR := make([]moneroutil.Key, MN)
	aL8 := make([]moneroutil.Key, MN)
	aR8 := make([]moneroutil.Key, MN)
	temp := moneroutil.Key{}
	temp2 := moneroutil.Key{}

	V := make([]moneroutil.Key, len(masks))
	for i, mask := range masks {
		var (
			gamma8Key moneroutil.Key
			sv8Key    moneroutil.Key
			HKey      moneroutil.Key
		)
		gamma8 := new(edwards25519.Scalar).Multiply(mask, INV_EIGHT)
		amountScalar := AmountToScalar(amounts[i])
		sv8 := new(edwards25519.Scalar).Multiply(amountScalar, INV_EIGHT)
		H := getH()

		gamma8Key.FromScalar(gamma8)
		sv8Key.FromScalar(sv8)
		HKey.FromPoint(H)

		moneroutil.AddKeys2(&V[i], &gamma8Key, &sv8Key, &HKey)
	}

	for j := 0; j < M; j++ {
		for i := N - 1; i >= 0; i-- {
			amountBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(amountBytes, amounts[j])
			if j < len(amounts) && (amountBytes[i/8]&(1<<(i%8))) != 0 {
				aL[j*N+i] = moneroutil.Identity
				aL8[j*N+i] = moneroutil.INV_EIGHT
				aR[j*N+i] = moneroutil.Zero
				aR8[j*N+i] = moneroutil.Zero
			} else {
				aL[j*N+i] = moneroutil.Zero
				aL8[j*N+i] = moneroutil.Zero
				aR[j*N+i] = moneroutil.MINUS_ONE
				aR8[j*N+i] = moneroutil.MINUS_INV_EIGHT
			}
		}
	}

	exponent := initExponents(maxN, maxM)

	var buf bytes.Buffer
	for _, v := range V {
		buf.Write(v[:])
	}

	exponent.Transcript = moneroutil.TranscriptUpdate(&exponent.Transcript, moneroutil.HashToScalar(buf.Bytes()).ToBytes2())
	bpp := Bpp{}

	// Генерируем криптографически стойкие случайные скаляры
	alpha := randomScalar()

	bpp.A = computeA(alpha, aL8, aR8, *exponent)

	y := moneroutil.TranscriptUpdate(&exponent.Transcript, bpp.A[:])
	exponent.Transcript = *moneroutil.HashToScalar(y.ToBytes2())
	z := exponent.Transcript
	z_squared := new(moneroutil.Key)
	moneroutil.ScMul(z_squared, z, z)

	d := createWindowedVector(*z_squared, N, M)
	yPowers := vectorOfScalarPowers(y, MN+2)

	aL1 := vectorSubtract(aL, z)
	aR1 := vectorAdd(aR, z)

	dy := make([]moneroutil.Key, MN)
	for i := 0; i < MN; i++ {
		moneroutil.ScMul(&dy[i], d[i], yPowers[MN-i])
	}
	aR1 = vectorAdd2(aR1, dy)

	alpha1 := new(moneroutil.Key)
	alpha1.FromScalar(alpha)

	temp = moneroutil.ONE
	for j := 0; j < len(amounts); j++ {
		moneroutil.ScMul(&temp, temp, *z_squared)
		moneroutil.ScMul(&temp2, yPowers[MN+1], temp)
		gamma := new(moneroutil.Key)
		gamma.FromScalar(masks[j])
		moneroutil.ScMulAdd(alpha1, &temp2, gamma, alpha1)
	}

	nprime := MN
	Gprime := make([]edwards25519.Point, MN)
	Hprime := make([]edwards25519.Point, MN)
	aprime := make([]moneroutil.Key, MN)
	bprime := make([]moneroutil.Key, MN)

	yinv := moneroutil.Key{}
	yinv.FromScalar(new(edwards25519.Scalar).Invert(y.KeyToScalar()))
	yinvpow := make([]moneroutil.Key, MN)
	yinvpow[0] = moneroutil.ONE
	for i := 0; i < MN; i++ {
		Gprime[i] = *exponent.Gi_p3[i]
		Hprime[i] = *exponent.Hi_p3[i]
		if i > 0 {
			moneroutil.ScMul(&yinvpow[i], yinvpow[i-1], yinv)
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
		dL := moneroutil.RandomScalar()
		dL.FromScalar(randomScalar())

		dR := moneroutil.RandomScalar()
		dR.FromScalar(randomScalar())

		// Вычисляем L[round] и R[round]
		L[round] = computeLR(nprime, yinvpow[nprime], &Gprime, nprime, &Hprime, 0, aprime, 0, bprime, nprime, cL, *dL)
		R[round] = computeLR(nprime, yPowers[nprime], &Gprime, 0, &Hprime, nprime, aprime, nprime, bprime, 0, cR, *dR)

		// Обновляем transcript и получаем challenge
		var buff bytes.Buffer
		buff.Write(L[round].Bytes())
		buff.Write(R[round].Bytes())
		challenge := moneroutil.TranscriptUpdate(&exponent.Transcript, buff.Bytes())

		// Вычисляем обратный challenge
		challengeInv := moneroutil.Key{}
		challengeInv.FromScalar(new(edwards25519.Scalar).Invert(challenge.KeyToScalar()))

		// temp = yinvpow[nprime] * challenge
		var temp moneroutil.Key
		moneroutil.ScMul(&temp, yinvpow[nprime], challenge)

		// Hadamard fold для Gprime
		hadamardFold(&Gprime, challengeInv, temp)
		hadamardFold(&Hprime, challenge, challengeInv)

		// temp = challenge_inv * y_powers[nprime]
		moneroutil.ScMul(&temp, challengeInv, yPowers[nprime])

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

		var challengeSquared moneroutil.Key
		var challengeSquaredInv moneroutil.Key

		moneroutil.ScMul(&challengeSquared, challenge, challenge)
		moneroutil.ScMul(&challengeSquaredInv, challengeInv, challengeInv)
		moneroutil.ScMulAdd(alpha1, dL, &challengeSquared, alpha1)
		moneroutil.ScMulAdd(alpha1, dR, &challengeSquaredInv, alpha1)

		round++

	}

	for i := range L {
		bpp.L = append(bpp.L, Hash(L[i].Bytes()))
		bpp.R = append(bpp.R, Hash(R[i].Bytes()))
	}

	r := moneroutil.RandomScalar()
	r.FromScalar(randomScalar())
	s := moneroutil.RandomScalar()
	s.FromScalar(randomScalar())
	d_ := moneroutil.RandomScalar()
	d_.FromScalar(randomScalar())
	eta := moneroutil.RandomScalar()
	eta.FromScalar(randomScalar())

	// Подготовка данных для A1
	A1Data := make([]MultiexpData, 4)

	moneroutil.ScMul(&A1Data[0].Scalar, *r, moneroutil.INV_EIGHT)
	A1Data[0].Point = &Gprime[0]

	moneroutil.ScMul(&A1Data[1].Scalar, *s, moneroutil.INV_EIGHT)
	A1Data[1].Point = &Hprime[0]

	moneroutil.ScMul(&A1Data[2].Scalar, *d_, moneroutil.INV_EIGHT)
	A1Data[2].Point = edwards25519.NewGeneratorPoint()

	moneroutil.ScMul(&temp, *r, y)
	moneroutil.ScMul(&temp, temp, bprime[0])
	moneroutil.ScMul(&temp2, *s, y)
	moneroutil.ScMul(&temp2, temp2, aprime[0])
	moneroutil.ScAdd(&temp, &temp, &temp2)
	moneroutil.ScMul(&A1Data[3].Scalar, temp, moneroutil.INV_EIGHT)
	A1Data[3].Point = getH()

	A1Key := multiexp(A1Data)
	A1Point, _ := new(edwards25519.Point).SetBytes(A1Key[:])
	A1 := *A1Point
	bpp.A1 = Hash(A1.Bytes())

	moneroutil.ScMul(&temp, *r, y)
	moneroutil.ScMul(&temp, temp, *s)
	moneroutil.ScMul(&temp, temp, moneroutil.INV_EIGHT)
	moneroutil.ScMul(&temp2, *eta, moneroutil.INV_EIGHT)

	var B moneroutil.Key
	HKey := moneroutil.Key{}
	HKey.FromPoint(getH())
	moneroutil.AddKeys2(&B, &temp2, &temp, &HKey)
	bpp.B = Hash(B.ToBytes2())

	var buffE bytes.Buffer
	buffE.Write(A1.Bytes())
	buffE.Write(B[:])
	e := moneroutil.TranscriptUpdate(&exponent.Transcript, buffE.Bytes())

	var eSquared moneroutil.Key
	moneroutil.ScMul(&eSquared, e, e)

	var r1 moneroutil.Key
	moneroutil.ScMulAdd(&r1, &aprime[0], &e, r)
	bpp.R1 = Hash(r1.ToBytes2())

	var s1 moneroutil.Key
	moneroutil.ScMulAdd(&s1, &bprime[0], &e, s)
	bpp.S1 = Hash(s1.ToBytes2())

	var d1 moneroutil.Key
	moneroutil.ScMulAdd(&d1, d_, &e, eta)
	moneroutil.ScMulAdd(&d1, alpha1, &eSquared, &d1)
	bpp.D1 = Hash(d1.ToBytes2())

	return bpp, nil
}

// Создаем windowed vector d
func createWindowedVector(zSquared moneroutil.Key, N, M int) []moneroutil.Key {
	MN := M * N
	d := make([]moneroutil.Key, MN)

	for i := range d {
		d[i] = moneroutil.Zero
	}

	d[0] = zSquared

	for i := 1; i < N; i++ {
		moneroutil.ScMul(&d[i], d[i-1], moneroutil.TWO)
	}

	for j := 1; j < M; j++ {
		for i := 0; i < N; i++ {
			moneroutil.ScMul(&d[j*N+i], d[(j-1)*N+i], zSquared)
		}
	}

	return d
}

// vectorOfScalarPowers создает вектор степеней скаляра: [1, x, x^2, x^3, ..., x^(n-1)]
func vectorOfScalarPowers(x moneroutil.Key, n int) []moneroutil.Key {
	if n == 0 {
		panic("Need n > 0")
	}

	res := make([]moneroutil.Key, n)
	res[0] = moneroutil.Identity
	if n == 1 {
		return res
	}

	res[1] = x
	for i := 2; i < n; i++ {
		moneroutil.ScMul(&res[i], res[i-1], x)
	}

	return res
}

// vectorSubtract вычитает скаляр из всех элементов вектора
// res[i] = a[i] - b
func vectorSubtract(a []moneroutil.Key, b moneroutil.Key) []moneroutil.Key {
	res := make([]moneroutil.Key, len(a))

	for i := 0; i < len(a); i++ {
		moneroutil.ScSub(&res[i], &a[i], &b)
	}

	return res
}

func vectorAdd(a []moneroutil.Key, b moneroutil.Key) []moneroutil.Key {
	res := make([]moneroutil.Key, len(a))

	for i := 0; i < len(a); i++ {
		moneroutil.ScAdd(&res[i], &a[i], &b)
	}

	return res
}

func vectorAdd2(a []moneroutil.Key, b []moneroutil.Key) []moneroutil.Key {
	res := make([]moneroutil.Key, len(a))

	for i := 0; i < len(a); i++ {
		moneroutil.ScAdd(&res[i], &a[i], &b[i])
	}

	return res
}

func slice(arr []moneroutil.Key, start, end int) []moneroutil.Key {
	return arr[start:end]
}

// weightedInnerProduct вычисляет взвешенное внутреннее произведение
// res = sum(a[i] * b[i] * y^(i+1)) для i от 0 до len(a)-1
func weightedInnerProduct(a, b []moneroutil.Key, y moneroutil.Key) moneroutil.Key {
	if len(a) != len(b) {
		panic("Incompatible sizes of a and b")
	}

	res := moneroutil.Zero
	yPower := moneroutil.Identity // y^0 = 1
	var temp moneroutil.Key

	for i := 0; i < len(a); i++ {
		moneroutil.ScMul(&temp, a[i], b[i])
		moneroutil.ScMul(&yPower, yPower, y)
		moneroutil.ScMulAdd(&res, &temp, &yPower, &res)
	}

	return res
}

// vectorScalar умножает каждый элемент вектора на скаляр
// res[i] = a[i] * b
func vectorScalar(a []moneroutil.Key, b moneroutil.Key) []moneroutil.Key {
	res := make([]moneroutil.Key, len(a))

	for i := 0; i < len(a); i++ {
		moneroutil.ScMul(&res[i], a[i], b)
	}

	return res
}

// computeLR вычисляет L или R для inner product argument
func computeLR(size int, y moneroutil.Key, G *[]edwards25519.Point, G0 int, H *[]edwards25519.Point, H0 int,
	a []moneroutil.Key, a0 int, b []moneroutil.Key, b0 int, c moneroutil.Key, d moneroutil.Key) edwards25519.Point {

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

	var temp moneroutil.Key

	// Заполняем данные для G и H
	for i := 0; i < size; i++ {
		// temp = a[a0+i] * y
		moneroutil.ScMul(&temp, a[a0+i], y)

		// scalar = temp * INV_EIGHT
		moneroutil.ScMul(&multiexpData[i*2].Scalar, temp, moneroutil.INV_EIGHT)
		multiexpData[i*2].Point = &(*G)[G0+i]

		// scalar = b[b0+i] * INV_EIGHT
		moneroutil.ScMul(&multiexpData[i*2+1].Scalar, b[b0+i], moneroutil.INV_EIGHT)
		multiexpData[i*2+1].Point = &(*H)[H0+i]
	}

	// Добавляем c * H
	moneroutil.ScMul(&multiexpData[2*size].Scalar, c, moneroutil.INV_EIGHT)
	multiexpData[2*size].Point = getH() // H базовая точка

	// Добавляем d * G
	moneroutil.ScMul(&multiexpData[2*size+1].Scalar, d, moneroutil.INV_EIGHT)
	multiexpData[2*size+1].Point = edwards25519.NewGeneratorPoint() // G базовая точка

	// Вычисляем multiexp
	key := multiexp(multiexpData)
	return *key.KeyToPoint()
}

// multiexp вычисляет multi-scalar multiplication: sum(scalar[i] * point[i])
func multiexp(data []MultiexpData) moneroutil.Key {
	// Результат - сумма всех scalar[i] * point[i]
	result := edwards25519.NewIdentityPoint()

	for _, d := range data {
		scalar := d.Scalar.KeyToScalar()
		term := new(edwards25519.Point).ScalarMult(scalar, d.Point)
		result.Add(result, term)
	}

	return moneroutil.Key(result.Bytes())
}

// hadamardFold складывает вектор точек пополам используя линейную комбинацию
// v[i] = a*v[i] + b*v[i+sz] для i < sz, затем уменьшает размер вектора вдвое
func hadamardFold(v *[]edwards25519.Point, a, b moneroutil.Key) {
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
		Transcript: moneroutil.INITIAL_TRANSCRIPT,
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

	key := new(moneroutil.Key)
	key2 := new(moneroutil.Key)
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
		randomMask := moneroutil.RandomScalar()
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
