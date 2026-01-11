package levin

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
)

func (t *Transaction) signCLSAGs() ([]CLSAG, error) {
	CLSAGs := make([]CLSAG, len(t.Inputs))

	full_message, err := GetFullMessage(Key(t.PrefixHash()), t.RctSignature, t.RctSigPrunable)
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
	sk := make([]Key, rows+1)
	P := make([]Key, 0, len(mixins))
	C := make([]Key, 0, len(mixins))
	C_nonzero := make([]Key, 0, len(mixins))

	// Обработка публичных ключей из mixins
	for _, mixin := range mixins {
		P = append(P, Key(mixin.Dest))
		C_nonzero = append(C_nonzero, Key(mixin.Mask))

		// C[i] = mixin.CommitmentMask - pseudoOut
		var tmp Key
		mask := Key(mixin.Mask)
		pOut := Key(pseudoOut)
		SubKeys(&tmp, &mask, &pOut)
		C = append(C, tmp)
	}

	// sk[0] = inSk.TxPublicKey (dest)
	sk[0] = Key(inSk.Dest)

	// sk[1] = inSk.CommitmentMask - a
	ScSub(&sk[1], (*Key)(&inSk.Mask), (*Key)(&a))

	// Вызов CLSAG_Gen
	return ClsagGen(message, P, sk[0], C, sk[1], C_nonzero, Key(pseudoOut), realIndx, keyImage)
}

func ClsagGen(message Hash, P []Key, p Key, C []Key, z Key, C_nonzero []Key, C_offset Key, l int, keyImage Hash) (CLSAG, error) {
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
	H_p3 := new(ExtendedGroupElement)
	H_p3 = P[l].HashToEC()
	var H Key
	H_p3.ToBytes(&H)

	// Initial values
	var D, a, aG, aH Key

	// hwdev.clsag_prepare эквивалент
	clsagPrepare(z, &D, H, &a, &aG, &aH)

	// Precompute key images //???????????
	var I_precomp, D_precomp CachedGroupElement
	var I_p3, D_p3 ExtendedGroupElement
	// I_p3.FromBytes(&sig.I)
	I := Key(keyImage)
	D_p3.FromBytes(&D)
	I_p3.FromBytes(&I)
	I_p3.ToCached(&I_precomp)
	D_p3.ToCached(&D_precomp)

	// Offset key image: sig.D = D * INV_EIGHT
	sig.D = Hash(ScalarMult(&INV_EIGHT, &D))

	// Aggregation hashes
	mu_P_to_hash := make([]Key, 2*n+4)
	mu_C_to_hash := make([]Key, 2*n+4)

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

	mu_P_to_hash[2*n+1] = Key(keyImage)
	mu_P_to_hash[2*n+2] = Key(sig.D)
	mu_P_to_hash[2*n+3] = C_offset
	mu_C_to_hash[2*n+1] = Key(keyImage)
	mu_C_to_hash[2*n+2] = Key(sig.D)
	mu_C_to_hash[2*n+3] = C_offset

	var mu_P, mu_C Key
	mu_P = hashToScalar(mu_P_to_hash)
	mu_C = hashToScalar(mu_C_to_hash)

	// Initial commitment
	c_to_hash := make([]Key, 2*n+5)
	var c Key

	HASH_KEY_CLSAG_ROUND := "CLSAG_round"
	copy(c_to_hash[0][:], []byte(HASH_KEY_CLSAG_ROUND))

	for i := 1; i < n+1; i++ {
		c_to_hash[i] = P[i-1]
		c_to_hash[i+n] = C_nonzero[i-1]
	}
	c_to_hash[2*n+1] = C_offset
	c_to_hash[2*n+2] = Key(message)
	c_to_hash[2*n+3] = aG
	c_to_hash[2*n+4] = aH

	c = hashToScalar(c_to_hash)

	i := (l + 1) % n
	if i == 0 {
		sig.C1 = Hash(c)
	}

	// Decoy indices
	sig.S = make([]Hash, n)
	var c_new, L, R, c_p, c_c Key

	iteration := 0
	for i != l {

		// sig.s[i] = random scalar
		sig.S[i] = Hash(randomScalar().Bytes())

		// c_p = c * mu_P
		ScMul(&c_p, c, mu_P)
		// c_c = c * mu_C
		ScMul(&c_c, c, mu_C)

		// Precompute points
		var P_precomp, C_precomp CachedGroupElement
		var P_p3, C_p3 ExtendedGroupElement
		P_p3.FromBytes(&P[i])
		C_p3.FromBytes(&C[i])
		P_p3.ToCached(&P_precomp)
		C_p3.ToCached(&C_precomp)

		// Compute L = s[i]*G + c_p*P[i] + c_c*C[i]
		addKeysAGbBcC(&L, (*Key)(&sig.S[i]), &c_p, &P_precomp, &c_c, &C_precomp)

		// Precompute points
		var H_precomp CachedGroupElement
		var Hi_p3_2 Key
		var Hi_p3_3 ExtendedGroupElement
		P[i].HashToEC().ToBytes(&Hi_p3_2)
		Hi_p3_3.FromBytes(&Hi_p3_2)
		Hi_p3_3.ToCached(&H_precomp)

		addKeysAAbBcC(&R, (*Key)(&sig.S[i]), &H_precomp, &c_p, &I_precomp, &c_c, &D_precomp)

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
	clsagSign(&c, &a, &p, &z, &mu_P, &mu_C, (*Key)(&sig.S[l]))

	// Очистка секретного ключа a
	for j := range a {
		a[j] = 0
	}

	return sig, nil
}

// Вспомогательные функции

func hashToScalar(keys []Key) Key {
	var buf bytes.Buffer
	for _, k := range keys {
		buf.Write(k[:])
	}
	hash := keccak256(buf.Bytes())
	hashKey := Key(hash)
	ScReduce32(&hashKey)
	return hashKey
}

func clsagPrepare(z Key, D *Key, H Key, a, aG, aH *Key) {
	*D = ScalarMult(&z, &H)                                               // D = z * H_p(P[l])
	a.FromScalar(randomScalar())                                          // a = random scalar
	aG.FromPoint(new(edwards25519.Point).ScalarBaseMult(a.KeyToScalar())) // aG = a * G
	*aH = ScalarMult(a, &H)                                               // aH = a * H
}

func clsagSign(c, a, p, z, mu_P, mu_C *Key, s *Key) {
	// s = a - c*mu_P*p - c*mu_C*z
	var cp_mu_P, cc_mu_C, cp_mu_P_p, cc_mu_C_z, temp Key

	ScMul(&cp_mu_P, *c, *mu_P)
	ScMul(&cc_mu_C, *c, *mu_C)
	ScMul(&cp_mu_P_p, cp_mu_P, *p)
	ScMul(&cc_mu_C_z, cc_mu_C, *z)
	ScAdd(&temp, &cp_mu_P_p, &cc_mu_C_z)
	ScSub(s, a, &temp)
}

// ge_dsmp = *CachedGroupElement
// void addKeys_aGbBcC(key &aGbBcC, const key &a, const key &b, const ge_dsmp B, const key &c, const ge_dsmp C)
func addKeysAGbBcC(result *Key, a *Key, b *Key, B_precomp *CachedGroupElement, c *Key, C_precomp *CachedGroupElement) {
	// result = a*G + b*B + c*C
	// G is the fixed basepoint and B,C require precomputation

	// Создаем precomputed массивы для B и C
	var B_array, C_array [8]CachedGroupElement

	// Конвертируем CachedGroupElement в ExtendedGroupElement для precompute
	var B_ext, C_ext ExtendedGroupElement
	// var B_comp, C_comp CompletedGroupElement

	// B_precomp -> Extended
	B_precomp.ToExtended(&B_ext)
	GePrecompute(&B_array, &B_ext)

	// C_precomp -> Extended
	C_precomp.ToExtended(&C_ext)
	GePrecompute(&C_array, &C_ext)

	var rv ProjectiveGroupElement
	GeTripleScalarmultBaseVartime(&rv, a, b, &B_array, c, &C_array)
	rv.ToBytes(result)
}

// ge_dsmp = *CachedGroupElement
// void addKeys_aAbBcC(key &aAbBcC, const key &a, const ge_dsmp A, const key &b, const ge_dsmp B, const key &c, const ge_dsmp C)
func addKeysAAbBcC(result *Key, a *Key, A_precomp *CachedGroupElement, b *Key, B_precomp *CachedGroupElement, c *Key, C_precomp *CachedGroupElement) {
	// result = a*A + b*B + c*C
	// A,B,C require precomputation

	// Создаем precomputed массивы
	var A_array, B_array, C_array [8]CachedGroupElement

	// Конвертируем все в Extended и делаем precompute
	var A_ext, B_ext, C_ext ExtendedGroupElement

	A_precomp.ToExtended(&A_ext)
	GePrecompute(&A_array, &A_ext)

	B_precomp.ToExtended(&B_ext)
	GePrecompute(&B_array, &B_ext)

	C_precomp.ToExtended(&C_ext)
	GePrecompute(&C_array, &C_ext)

	var rv ProjectiveGroupElement
	GeTripleScalarmultPrecompVartime(&rv, a, &A_array, b, &B_array, c, &C_array)
	rv.ToBytes(result)
}

func GetFullMessage(prefixHash Key, rv *RctSignature, rv2 *RctSigPrunable) (Key, error) {

	hashes := make([]Key, 0, 3)
	hashes = append(hashes, prefixHash)
	// Сериализуем rctSigBase, Хешируем sig_base
	sigBaseBlob := serializeRctSigBase(rv)
	sigBaseHash := keccak256(sigBaseBlob)
	hashes = append(hashes, Key(sigBaseHash))

	kv := make([]Key, 0)
	for _, p := range rv2.Bpp {
		kv = append(kv, Key(p.A))
		kv = append(kv, Key(p.A1))
		kv = append(kv, Key(p.B))
		kv = append(kv, Key(p.R1))
		kv = append(kv, Key(p.S1))
		kv = append(kv, Key(p.D1))

		for n := 0; n < len(p.L); n++ {
			kv = append(kv, Key(p.L[n]))
		}

		for n := 0; n < len(p.R); n++ {
			kv = append(kv, Key(p.R[n]))
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
func cnFastHashKeyV(kv []Key) Key {
	var buf bytes.Buffer
	for _, k := range kv {
		buf.Write(k[:])
	}
	hash := keccak256(buf.Bytes())
	return Key(hash)
}
