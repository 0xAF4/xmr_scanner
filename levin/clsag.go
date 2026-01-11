package levin

import (
	"bytes"
	"fmt"
	"os"
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
	var I_precomp moneroutil.CachedGroupElement
	var D_precomp moneroutil.CachedGroupElement
	var I_p3, D_p3 moneroutil.ExtendedGroupElement
	// I_p3.FromBytes(&sig.I)
	D_p3.FromBytes(&D)
	I_p3.ToCached(&I_precomp)
	D_p3.ToCached(&D_precomp)

	// Offset key image: sig.D = D * INV_EIGHT
	sig.D = Hash(moneroutil.ScalarMult(&moneroutil.INV_EIGHT, &D))

	fmt.Println("Building aggregation hash vectors...")
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
		fmt.Printf("--- Iteration %d, i=%d ---\n", iteration, i)

		// sig.s[i] = random scalar
		sig.S[i] = Hash(randomScalar().Bytes())

		fmt.Printf("sig.S[%d]: %x\n", i, sig.S[i])

		// c_p = c * mu_P
		moneroutil.ScMul(&c_p, c, mu_P)
		// c_c = c * mu_C
		moneroutil.ScMul(&c_c, c, mu_C)

		fmt.Printf("c_p (c * mu_P): %x\n", c_p)
		fmt.Printf("c_c (c * mu_C): %x\n", c_c)
		fmt.Printf("Current c: %x\n", c)

		// Precompute points
		var P_precomp, C_precomp moneroutil.CachedGroupElement
		var P_p3, C_p3 moneroutil.ExtendedGroupElement
		P_p3.FromBytes(&P[i])
		C_p3.FromBytes(&C[i])
		P_p3.ToCached(&P_precomp)
		C_p3.ToCached(&C_precomp)

		// Compute L = s[i]*G + c_p*P[i] + c_c*C[i]
		addKeysAGbBcC(&L, (*moneroutil.Key)(&sig.S[i]), &c_p, &P_precomp, &c_c, &C_precomp)

		fmt.Printf("L: %x\n", L)
		os.Exit(1)

		// Compute R = s[i]*H_p(P[i]) + c_p*I + c_c*D
		Hi_p3 := new(moneroutil.ExtendedGroupElement)
		Hi_p3 = P[i].HashToEC()
		var H_precomp moneroutil.CachedGroupElement
		Hi_p3.ToCached(&H_precomp)

		addKeysAAbBcC(&R, (*moneroutil.Key)(&sig.S[i]), &H_precomp, &c_p, &I_precomp, &c_c, &D_precomp)

		fmt.Printf("R: %x\n", R)

		c_to_hash[2*n+3] = L
		c_to_hash[2*n+4] = R
		c_new = hashToScalar(c_to_hash)
		c = c_new

		fmt.Printf("c_new: %x\n", c_new)

		i = (i + 1) % n
		if i == 0 {
			sig.C1 = Hash(c)
		}

		iteration++
	}

	fmt.Printf("Final c1: %x\n", sig.C1)
	fmt.Printf("Computing final scalar for index l=%d\n", l)

	// Compute final scalar: s[l]
	clsagSign(&c, &a, &p, &z, &mu_P, &mu_C, (*moneroutil.Key)(&sig.S[l]))

	fmt.Printf("sig.S[%d] (final): %x\n", l, sig.S[l])

	// Очистка секретного ключа a
	for j := range a {
		a[j] = 0
	}

	fmt.Println("=== ClsagGen END ===")

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

func addKeysAGbBcC(result *moneroutil.Key, a *moneroutil.Key, b *moneroutil.Key, B_precomp *moneroutil.CachedGroupElement, c *moneroutil.Key, C_precomp *moneroutil.CachedGroupElement) {
	// result = a*G + b*B + c*C

	// a*G
	// var aG_p3 moneroutil.ExtendedGroupElement
	// moneroutil.GeScalarMultBase(&aG_p3, a)

	// b*B
	// var bB_p3 moneroutil.ExtendedGroupElement
	// moneroutil.GeScalarMult(&bB_p3, b, B_precomp)

	// c*C
	// var cC_p3 moneroutil.ExtendedGroupElement
	// moneroutil.GeScalarMult(&cC_p3, c, C_precomp)

	// aG + bB
	// var sum1 moneroutil.ExtendedGroupElement
	// moneroutil.GeAdd(&sum1, &aG_p3, &bB_p3)

	// (aG + bB) + cC
	// var final moneroutil.ExtendedGroupElement
	// moneroutil.GeAdd(&final, &sum1, &cC_p3)

	// final.ToBytes(result)
}

func addKeysAAbBcC(result *moneroutil.Key, a *moneroutil.Key, A_precomp *moneroutil.CachedGroupElement, b *moneroutil.Key, B_precomp *moneroutil.CachedGroupElement, c *moneroutil.Key, C_precomp *moneroutil.CachedGroupElement) {
	// result = a*A + b*B + c*C

	// a*A
	// var aA_p3 moneroutil.ExtendedGroupElement
	// moneroutil.GeScalarMult(&aA_p3, a, A_precomp)

	// b*B
	// var bB_p3 moneroutil.ExtendedGroupElement
	// moneroutil.GeScalarMult(&bB_p3, b, B_precomp)

	// c*C
	// var cC_p3 moneroutil.ExtendedGroupElement
	// moneroutil.GeScalarMult(&cC_p3, c, C_precomp)

	// aA + bB
	// var sum1 moneroutil.ExtendedGroupElement
	// moneroutil.GeAdd(&sum1, &aA_p3, &bB_p3)

	// (aA + bB) + cC
	// var final moneroutil.ExtendedGroupElement
	// moneroutil.GeAdd(&final, &sum1, &cC_p3)

	// final.ToBytes(result)
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
