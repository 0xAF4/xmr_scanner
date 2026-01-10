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
		// full_message, rv.mixRing[i], inSk[i], a[i], pseudoOuts[i], index[i], hwdev
		inSk, err := t.getInSk(i)
		if err != nil {
			return []CLSAG{}, fmt.Errorf("Error during creation of inSk: %e", err)
		}
		CLSAGs[i], err = SignInput(Hash(full_message), input.Mixins, inSk, Hash(t.InputScalars[i].Bytes()), t.RctSigPrunable.PseudoOuts[i], input.RealIndx)
		if err != nil {
			return []CLSAG{}, fmt.Errorf("Error during creation of clsag: %e", err)
		}
	}

	return CLSAGs, nil
}

func (t *Transaction) getInSk(i int) (Mixin, error) {
	inSk := Mixin{
		Dest: t.Inputs[i].DerivedPrivateKey,
	}

	return inSk, nil
}

func SignInput(prefixHash Hash, mixins []Mixin, inSk Mixin, a Hash, pseudoOut Hash, realIndx int) (clsag CLSAG, err error) {
	// for range len(input.KeyOffsets) {
	// 	key := moneroutil.RandomScalar()
	// 	key.FromScalar(randomScalar())
	// 	clsag.S = append(clsag.S, Hash(key.ToBytes()))
	// }
	return
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
