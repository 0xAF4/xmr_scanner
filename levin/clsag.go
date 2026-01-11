package levin

import (
	"bytes"
	"fmt"
	moneroutil "xmr_scanner/moneroutil"

	"filippo.io/edwards25519"
)

func (t *Transaction) signCLSAGs() ([]CLSAG, error) {
	CLSAGs := make([]CLSAG, len(t.Inputs))

	full_message, err := GetFullMessage(moneroutil.Key(t.PrefixHash()), t.RctSignature, t.RctSigPrunable)
	if err != nil {
		return nil, err
	}

	for i, input := range t.Inputs {
		CLSAGs[i], err = proveRctCLSAGSimple(Hash(full_message), input.Mixins, input.InSk, Hash(t.InputScalars[i].Bytes()), t.RctSigPrunable.PseudoOuts[i], input.OrderIndx, input.KeyImage)
		if err != nil {
			return []CLSAG{}, fmt.Errorf("Error during creation of clsag: %e", err)
		}
	}

	return CLSAGs, nil
}

func proveRctCLSAGSimple(message Hash, mixins []Mixin, inSk Mixin, a Hash, pseudoOut Hash, realIndx int, keyImage Hash) (clsag CLSAG, err error) {

	rows := 1

	// Инициализация векторов
	sk := make([]moneroutil.Key, rows+1)
	P := make([]moneroutil.Key, 0, len(mixins))
	C := make([]moneroutil.Key, 0, len(mixins))
	C_nonzero := make([]moneroutil.Key, 0, len(mixins))

	// Обработка публичных ключей из mixins
	for _, mixin := range mixins {
		P = append(P, moneroutil.Key(mixin.Dest))
		C_nonzero = append(C_nonzero, moneroutil.Key(mixin.Mask))

		// C[i] = mixin.CommitmentMask - pseudoOut
		var tmp moneroutil.Key
		mask := moneroutil.Key(mixin.Mask)
		pOut := moneroutil.Key(pseudoOut)
		moneroutil.SubKeys(&tmp, &mask, &pOut)
		C = append(C, tmp)
	}

	// sk[0] = inSk.TxPublicKey (dest)
	sk[0] = moneroutil.Key(inSk.Dest)

	// sk[1] = inSk.CommitmentMask - a
	moneroutil.ScSub(&sk[1], (*moneroutil.Key)(&inSk.Mask), (*moneroutil.Key)(&a))

	// Вызов CLSAG_Gen
	return ClsagGen(message, P, sk[0], C, sk[1], C_nonzero, moneroutil.Key(pseudoOut), realIndx, keyImage)
}

func ClsagGen(message Hash, P []moneroutil.Key, p moneroutil.Key, C []moneroutil.Key, z moneroutil.Key, C_nonzero []moneroutil.Key, C_offset moneroutil.Key, l int, keyImage Hash) (CLSAG, error) {
	var sig CLSAG
	n := len(P) // ring size

	// Проверки размеров
	if n != len(C) {
		return CLSAG{}, fmt.Errorf("Signing and commitment key vector sizes must match! P:%d C:%d", len(P), len(C))
	}
	if n != len(C_nonzero) {
		return CLSAG{}, fmt.Errorf("Signing and commitment key vector sizes must match! P:%d C_nonzero:%d", len(P), len(C_nonzero))
	}
	if l >= n {
		return CLSAG{}, fmt.Errorf("Signing index out of range! l:%d n:%d", l, n)
	}

	// Key images
	H_p3 := new(moneroutil.ExtendedGroupElement)
	H_p3 = P[l].HashToEC()
	var H moneroutil.Key
	H_p3.ToBytes(&H)

	// Initial values
	var D, a, aG, aH moneroutil.Key

	// hwdev.clsag_prepare эквивалент
	clsagPrepare(z, &D, H, &a, &aG, &aH)

	// Precompute key images //???????????
	var I_precomp, D_precomp moneroutil.CachedGroupElement
	var I_p3, D_p3 moneroutil.ExtendedGroupElement
	// I_p3.FromBytes(&sig.I)
	I := moneroutil.Key(keyImage)
	D_p3.FromBytes(&D)
	I_p3.FromBytes(&I)
	I_p3.ToCached(&I_precomp)
	D_p3.ToCached(&D_precomp)

	// Offset key image: sig.D = D * INV_EIGHT
	sig.D = Hash(moneroutil.ScalarMult(&moneroutil.INV_EIGHT, &D))

	// Aggregation hashes
	mu_P_to_hash := make([]moneroutil.Key, 2*n+4)
	mu_C_to_hash := make([]moneroutil.Key, 2*n+4)

	// Domain separators
	HASH_KEY_CLSAG_AGG_0 := "CLSAG_agg_0"
	HASH_KEY_CLSAG_AGG_1 := "CLSAG_agg_1"
	copy(mu_P_to_hash[0][:], []byte(HASH_KEY_CLSAG_AGG_0))
	copy(mu_C_to_hash[0][:], []byte(HASH_KEY_CLSAG_AGG_1))

	// Копируем P
	for i := 1; i < n+1; i++ {
		mu_P_to_hash[i] = P[i-1]
		mu_C_to_hash[i] = P[i-1]
	}

	// Копируем C_nonzero
	for i := n + 1; i < 2*n+1; i++ {
		mu_P_to_hash[i] = C_nonzero[i-n-1]
		mu_C_to_hash[i] = C_nonzero[i-n-1]
	}

	mu_P_to_hash[2*n+1] = moneroutil.Key(keyImage)
	mu_P_to_hash[2*n+2] = moneroutil.Key(sig.D)
	mu_P_to_hash[2*n+3] = C_offset
	mu_C_to_hash[2*n+1] = moneroutil.Key(keyImage)
	mu_C_to_hash[2*n+2] = moneroutil.Key(sig.D)
	mu_C_to_hash[2*n+3] = C_offset

	var mu_P, mu_C moneroutil.Key
	mu_P = hashToScalar(mu_P_to_hash)
	mu_C = hashToScalar(mu_C_to_hash)

	// Initial commitment
	c_to_hash := make([]moneroutil.Key, 2*n+5)
	var c moneroutil.Key

	HASH_KEY_CLSAG_ROUND := "CLSAG_round"
	copy(c_to_hash[0][:], []byte(HASH_KEY_CLSAG_ROUND))

	for i := 1; i < n+1; i++ {
		c_to_hash[i] = P[i-1]
		c_to_hash[i+n] = C_nonzero[i-1]
	}
	c_to_hash[2*n+1] = C_offset
	c_to_hash[2*n+2] = moneroutil.Key(message)
	c_to_hash[2*n+3] = aG
	c_to_hash[2*n+4] = aH

	c = hashToScalar(c_to_hash)

	i := (l + 1) % n
	if i == 0 {
		sig.C1 = Hash(c)
	}

	// Decoy indices
	sig.S = make([]Hash, n)
	var c_new, L, R, c_p, c_c moneroutil.Key

	iteration := 0
	for i != l {

		// sig.s[i] = random scalar
		sig.S[i] = Hash(randomScalar().Bytes())

		// c_p = c * mu_P
		moneroutil.ScMul(&c_p, c, mu_P)
		// c_c = c * mu_C
		moneroutil.ScMul(&c_c, c, mu_C)

		// Precompute points
		var P_precomp, C_precomp moneroutil.CachedGroupElement
		var P_p3, C_p3 moneroutil.ExtendedGroupElement
		P_p3.FromBytes(&P[i])
		C_p3.FromBytes(&C[i])
		P_p3.ToCached(&P_precomp)
		C_p3.ToCached(&C_precomp)

		// Compute L = s[i]*G + c_p*P[i] + c_c*C[i]
		addKeysAGbBcC(&L, (*moneroutil.Key)(&sig.S[i]), &c_p, &P_precomp, &c_c, &C_precomp)

		// Precompute points
		var H_precomp moneroutil.CachedGroupElement
		var Hi_p3_2 moneroutil.Key
		var Hi_p3_3 moneroutil.ExtendedGroupElement
		P[i].HashToEC().ToBytes(&Hi_p3_2)
		Hi_p3_3.FromBytes(&Hi_p3_2)
		Hi_p3_3.ToCached(&H_precomp)

		addKeysAAbBcC(&R, (*moneroutil.Key)(&sig.S[i]), &H_precomp, &c_p, &I_precomp, &c_c, &D_precomp)

		c_to_hash[2*n+3] = L
		c_to_hash[2*n+4] = R
		c_new = hashToScalar(c_to_hash)
		c = c_new

		i = (i + 1) % n
		if i == 0 {
			sig.C1 = Hash(c)
		}

		iteration++
	}

	// Compute final scalar: s[l]
	clsagSign(&c, &a, &p, &z, &mu_P, &mu_C, (*moneroutil.Key)(&sig.S[l]))

	// Очистка секретного ключа a
	for j := range a {
		a[j] = 0
	}

	return sig, nil
}

// Вспомогательные функции

func hashToScalar(keys []moneroutil.Key) moneroutil.Key {
	var buf bytes.Buffer
	for _, k := range keys {
		buf.Write(k[:])
	}
	hash := keccak256(buf.Bytes())
	hashKey := moneroutil.Key(hash)
	moneroutil.ScReduce32(&hashKey)
	return hashKey
}

func clsagPrepare(z moneroutil.Key, D *moneroutil.Key, H moneroutil.Key, a, aG, aH *moneroutil.Key) {
	*D = moneroutil.ScalarMult(&z, &H)                                    // D = z * H_p(P[l])
	a.FromScalar(randomScalar())                                          // a = random scalar
	aG.FromPoint(new(edwards25519.Point).ScalarBaseMult(a.KeyToScalar())) // aG = a * G
	*aH = moneroutil.ScalarMult(a, &H)                                    // aH = a * H
}

func clsagSign(c, a, p, z, mu_P, mu_C *moneroutil.Key, s *moneroutil.Key) {
	// s = a - c*mu_P*p - c*mu_C*z
	var cp_mu_P, cc_mu_C, cp_mu_P_p, cc_mu_C_z, temp moneroutil.Key

	moneroutil.ScMul(&cp_mu_P, *c, *mu_P)
	moneroutil.ScMul(&cc_mu_C, *c, *mu_C)
	moneroutil.ScMul(&cp_mu_P_p, cp_mu_P, *p)
	moneroutil.ScMul(&cc_mu_C_z, cc_mu_C, *z)
	moneroutil.ScAdd(&temp, &cp_mu_P_p, &cc_mu_C_z)
	moneroutil.ScSub(s, a, &temp)
}

// ge_dsmp = *moneroutil.CachedGroupElement
// void addKeys_aGbBcC(key &aGbBcC, const key &a, const key &b, const ge_dsmp B, const key &c, const ge_dsmp C)
func addKeysAGbBcC(result *moneroutil.Key, a *moneroutil.Key, b *moneroutil.Key, B_precomp *moneroutil.CachedGroupElement, c *moneroutil.Key, C_precomp *moneroutil.CachedGroupElement) {
	// result = a*G + b*B + c*C
	// G is the fixed basepoint and B,C require precomputation

	// Создаем precomputed массивы для B и C
	var B_array, C_array [8]moneroutil.CachedGroupElement

	// Конвертируем CachedGroupElement в ExtendedGroupElement для precompute
	var B_ext, C_ext moneroutil.ExtendedGroupElement
	// var B_comp, C_comp moneroutil.CompletedGroupElement

	// B_precomp -> Extended
	B_precomp.ToExtended(&B_ext)
	moneroutil.GePrecompute(&B_array, &B_ext)

	// C_precomp -> Extended
	C_precomp.ToExtended(&C_ext)
	moneroutil.GePrecompute(&C_array, &C_ext)

	var rv moneroutil.ProjectiveGroupElement
	moneroutil.GeTripleScalarmultBaseVartime(&rv, a, b, &B_array, c, &C_array)
	rv.ToBytes(result)
}

// ge_dsmp = *moneroutil.CachedGroupElement
// void addKeys_aAbBcC(key &aAbBcC, const key &a, const ge_dsmp A, const key &b, const ge_dsmp B, const key &c, const ge_dsmp C)
func addKeysAAbBcC(result *moneroutil.Key, a *moneroutil.Key, A_precomp *moneroutil.CachedGroupElement, b *moneroutil.Key, B_precomp *moneroutil.CachedGroupElement, c *moneroutil.Key, C_precomp *moneroutil.CachedGroupElement) {
	// result = a*A + b*B + c*C
	// A,B,C require precomputation

	// Создаем precomputed массивы
	var A_array, B_array, C_array [8]moneroutil.CachedGroupElement

	// Конвертируем все в Extended и делаем precompute
	var A_ext, B_ext, C_ext moneroutil.ExtendedGroupElement

	A_precomp.ToExtended(&A_ext)
	moneroutil.GePrecompute(&A_array, &A_ext)

	B_precomp.ToExtended(&B_ext)
	moneroutil.GePrecompute(&B_array, &B_ext)

	C_precomp.ToExtended(&C_ext)
	moneroutil.GePrecompute(&C_array, &C_ext)

	var rv moneroutil.ProjectiveGroupElement
	moneroutil.GeTripleScalarmultPrecompVartime(&rv, a, &A_array, b, &B_array, c, &C_array)
	rv.ToBytes(result)
}

func GetFullMessage(prefixHash moneroutil.Key, rv *RctSignature, rv2 *RctSigPrunable) (moneroutil.Key, error) {

	hashes := make([]moneroutil.Key, 0, 3)
	hashes = append(hashes, prefixHash)
	// Сериализуем rctSigBase, Хешируем sig_base
	sigBaseBlob := serializeRctSigBase(rv)
	sigBaseHash := keccak256(sigBaseBlob)
	hashes = append(hashes, moneroutil.Key(sigBaseHash))

	kv := make([]moneroutil.Key, 0)
	for _, p := range rv2.Bpp {
		kv = append(kv, moneroutil.Key(p.A))
		kv = append(kv, moneroutil.Key(p.A1))
		kv = append(kv, moneroutil.Key(p.B))
		kv = append(kv, moneroutil.Key(p.R1))
		kv = append(kv, moneroutil.Key(p.S1))
		kv = append(kv, moneroutil.Key(p.D1))

		for n := 0; n < len(p.L); n++ {
			kv = append(kv, moneroutil.Key(p.L[n]))
		}

		for n := 0; n < len(p.R); n++ {
			kv = append(kv, moneroutil.Key(p.R[n]))
		}
	}

	// Хешируем kv
	kvHash := cnFastHashKeyV(kv)
	hashes = append(hashes, kvHash)
	prehash := cnFastHashKeyV(hashes)

	return prehash, nil
}

// serializeRctSigBase сериализует базовую часть RCT подписи
func serializeRctSigBase(rv *RctSignature) []byte {
	var buf bytes.Buffer

	buf.WriteByte(6)
	buf.Write(encodeVarint(rv.TxnFee))

	for _, ecdh := range rv.EcdhInfo {
		buf.Write(ecdh.Amount[:])
	}

	for _, outpk := range rv.OutPk {
		buf.Write(outpk[:])
	}

	return buf.Bytes()
}

// cnFastHashKeyV хеширует вектор ключей
func cnFastHashKeyV(kv []moneroutil.Key) moneroutil.Key {
	var buf bytes.Buffer
	for _, k := range kv {
		buf.Write(k[:])
	}
	hash := keccak256(buf.Bytes())
	return moneroutil.Key(hash)
}
