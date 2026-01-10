package levin

import (
	"bytes"
	"fmt"
	moneroutil "xmr_scanner/moneroutil"
)

func (t *Transaction) signCLSAGs(tx1 Transaction) ([]CLSAG, error) {
	CLSAGs := make([]CLSAG, len(t.Inputs))

	full_message, err := GetFullMessage(moneroutil.Key(t.PrefixHash()), t.RctSignature, t.RctSigPrunable)
	if err != nil {
		return nil, err
	}

	for i, input := range t.Inputs {
		CLSAGs[i], err = proveRctCLSAGSimple(Hash(full_message), input.Mixins, input.InSk, Hash(t.InputScalars[i].Bytes()), t.RctSigPrunable.PseudoOuts[i], input.OrderIndx)
		if err != nil {
			return []CLSAG{}, fmt.Errorf("Error during creation of clsag: %e", err)
		}
	}

	return CLSAGs, nil
}

func proveRctCLSAGSimple(message Hash, mixins []Mixin, inSk Mixin, a Hash, pseudoOut Hash, realIndx int) (clsag CLSAG, err error) {

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
	return ClsagGen(message, P, sk[0], C, sk[1], C_nonzero, moneroutil.Key(pseudoOut), realIndx)
}

func ClsagGen(message Hash, P []moneroutil.Key, p moneroutil.Key, C []moneroutil.Key, z moneroutil.Key, C_nonzero []moneroutil.Key, C_offset moneroutil.Key, l int) (CLSAG, error) {
	// TODO: implement CLSAG_Gen
	return CLSAG{}, nil
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
