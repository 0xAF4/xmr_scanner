package moneroutil

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

const (
	KeyLength = 32
)

// Key can be a Scalar or a Point
type Key [KeyLength]byte

func (p *Key) FromBytes(b [KeyLength]byte) {
	*p = b
}

func (p *Key) FromPoint(point *edwards25519.Point) {
	p.FromBytes([32]byte(point.Bytes()))
}

func (p *Key) FromScalar(scalar *edwards25519.Scalar) {
	p.FromBytes([32]byte(scalar.Bytes()))
}

func (p *Key) ToBytes() (result [KeyLength]byte) {
	result = [KeyLength]byte(*p)
	return
}

func (p *Key) ToBytes2() []byte {
	result := make([]byte, KeyLength)
	copy(result, p[:])
	return result
}

func (p *Key) PubKey() (pubKey *Key) {
	point := new(ExtendedGroupElement)
	GeScalarMultBase(point, p)
	pubKey = new(Key)
	point.ToBytes(pubKey)
	return
}

// Creates a point on the Edwards Curve by hashing the key
func (p *Key) HashToEC() (result *ExtendedGroupElement) {
	result = new(ExtendedGroupElement)
	var p1 ProjectiveGroupElement
	var p2 CompletedGroupElement
	h := Key(Keccak256(p[:]))
	p1.FromBytes(&h)
	GeMul8(&p2, &p1)
	p2.ToExtended(result)
	return
}

func (p *Key) KeyToScalar() *edwards25519.Scalar {
	bytes := p.ToBytes()
	scalar := new(edwards25519.Scalar)
	scalar.SetCanonicalBytes(bytes[:])
	return scalar
}

func (p *Key) KeyToPoint() *edwards25519.Point {
	bytes := p.ToBytes()
	point := new(edwards25519.Point)
	point.SetBytes(bytes[:])
	return point
}

func RandomScalar() (result *Key) {
	result = new(Key)
	var reduceFrom [KeyLength * 2]byte
	tmp := make([]byte, KeyLength*2)
	rand.Read(tmp)
	copy(reduceFrom[:], tmp)
	ScReduce(result, &reduceFrom)
	return
}

func NewKeyPair() (privKey *Key, pubKey *Key) {
	privKey = RandomScalar()
	pubKey = privKey.PubKey()
	return
}

func (k *Key) String() string {
	return hex.EncodeToString(k[:])
}

func ParseKey(buf io.Reader) (Key, error) {
	key := [KeyLength]byte{}
	_, err := io.ReadFull(buf, key[:])
	return key, err
}

func ParseKeyFromHex(hexKey string) (result Key, err error) {
	data, err := hex.DecodeString(hexKey)
	if err != nil {
		return
	}

	if len(data) != KeyLength {
		err = fmt.Errorf("invalid key length: %d", len(data))
		return
	}

	copy(result[:], data)
	return
}

func ScMul(out *Key, a Key, b Key) {
	ScReduce32(&a)
	ScReduce32(&b)
	aS, _ := new(edwards25519.Scalar).SetCanonicalBytes(a.ToBytes2())
	bS, _ := new(edwards25519.Scalar).SetCanonicalBytes(b.ToBytes2())
	scal := new(edwards25519.Scalar).Multiply(aS, bS)
	key := Key(scal.Bytes())
	*out = key
}

const (
	RCTTypeNull            uint8 = 0
	RCTTypeFull            uint8 = 1
	RCTTypeSimple          uint8 = 2
	RCTTypeBulletproof     uint8 = 3
	RCTTypeBulletproof2    uint8 = 4
	RCTTypeCLSAG           uint8 = 5
	RCTTypeBulletproofPlus uint8 = 6
)

// Range proof commitments
type Key64 [64]Key

func (k *Key) ToExtended() (result *ExtendedGroupElement) {
	result = new(ExtendedGroupElement)
	result.FromBytes(k)
	return
}

// multiply a scalar by H (second curve point of Pedersen Commitment)
func ScalarMultH(scalar *Key) (result *Key) {
	h := new(ExtendedGroupElement)
	h.FromBytes(&H)
	resultPoint := new(ProjectiveGroupElement)
	GeScalarMult(resultPoint, scalar, h)
	result = new(Key)
	resultPoint.ToBytes(result)
	return
}

// add two points together
func AddKeys(sum, k1, k2 *Key) {
	a := k1.ToExtended()
	b := new(CachedGroupElement)
	k2.ToExtended().ToCached(b)
	c := new(CompletedGroupElement)
	geAdd(c, a, b)
	tmp := new(ExtendedGroupElement)
	c.ToExtended(tmp)
	tmp.ToBytes(sum)
}

// compute a*G + b*B
func AddKeys2(result, a, b, B *Key) {
	BPoint := B.ToExtended()
	RPoint := new(ProjectiveGroupElement)
	GeDoubleScalarMultVartime(RPoint, b, BPoint, a)
	RPoint.ToBytes(result)
}

// subtract two points A - B
func SubKeys(diff, k1, k2 *Key) {
	a := k1.ToExtended()
	b := new(CachedGroupElement)
	k2.ToExtended().ToCached(b)
	c := new(CompletedGroupElement)
	geSub(c, a, b)
	tmp := new(ExtendedGroupElement)
	c.ToExtended(tmp)
	tmp.ToBytes(diff)
}

func HashToScalar(data ...[]byte) (result *Key) {
	result = new(Key)
	*result = Key(Keccak256(data...))
	ScReduce32(result)
	return
}

func TranscriptUpdate(transcript *Key, V []byte) Key {
	// 3. Update transcript
	var buf bytes.Buffer
	buf.Write(transcript[:])
	buf.Write(V)
	result := Key(Keccak256(buf.Bytes()))

	ScReduce32(&result)
	*transcript = result
	return result
}
