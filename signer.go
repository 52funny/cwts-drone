package scheme

import (
	"crypto/sha256"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/ncw/gmp"
)

// Parameters owned by the signer
type Signer struct {
	e     *bls12381.Scalar // e
	d     *bls12381.Scalar // d
	s     *gmp.Int         // remainder
	Pub   *bls12381.G1     // Public key
	BItem                  // BItem
}

func NewSigner(e, d *bls12381.Scalar, s *gmp.Int, pub *bls12381.G1, b BItem) *Signer {
	return &Signer{e: e, d: d, s: s, Pub: pub, BItem: b}
}

// Sign returns the signature of the i-th drone
// Threshold schnorr signature = (s, R)
func (p *Signer) Sign(m string, B B) (*gmp.Int, *bls12381.G1) {
	// rho
	rho := p.rho(m, B)

	// Commitment R
	R := B.commitment(rho)

	// erho = e * rho
	erho := new(bls12381.Scalar)
	erho.Mul(p.e, rho)

	// k = d + e * rho
	k := new(bls12381.Scalar)
	k.Add(p.d, erho)

	cContent := make([]byte, 0)
	cContent = append(cContent, []byte(m)...)
	cContent = append(cContent, R.Bytes()...)
	cBytes := sha256.Sum256(cContent)

	// c = H(m || R)
	cScalar := new(bls12381.Scalar)
	cScalar.SetBytes(cBytes[:])
	c := ScalarToGmp(cScalar)

	gmpK := ScalarToGmp(k)

	// lambda = Q * Q^-1
	lambda := p.lambda(B)

	// sc = lambda * s * c
	sc := new(gmp.Int).SetInt64(1)
	sc.Mul(sc, lambda)
	sc.Mul(sc, p.s)
	sc.Mul(sc, c)

	// s = k + sc
	s := new(gmp.Int).SetInt64(0)
	s.Add(gmpK, sc)

	return s, R
}

// lambda returns the lambda of the drone
// lambda = Q * Q^-1
func (p *Signer) lambda(B B) *gmp.Int {
	Q := new(gmp.Int).SetInt64(1)
	for _, item := range B {
		Q.Mul(Q, item.P)
	}
	Q.Div(Q, p.P)

	QInv := new(gmp.Int).ModInverse(Q, p.P)
	res := new(gmp.Int).Mul(Q, QInv)
	Q.Clear()
	QInv.Clear()
	return res
}

type BItem struct {
	P *gmp.Int     // The prime number
	E *bls12381.G1 // E
	D *bls12381.G1 // D
}

// rho returns the rho of the i-th drone
// rho = H(m || E || D)
func (item BItem) rho(m string, b B) *bls12381.Scalar {
	bytesM := []byte(m)
	rho := new(bls12381.Scalar)
	sha := sha256.New()
	sha.Write(bytesM)
	for i := 0; i < len(b); i++ {
		sha.Write(b[i].E.BytesCompressed())
		sha.Write(b[i].D.BytesCompressed())
	}
	rho.SetBytes(sha.Sum(nil))
	return rho
}

// B is a list of all the drones to be signatured
type B []BItem

// NewB creates a new B
func NewB(moduli []*gmp.Int, Ei []*bls12381.G1, Di []*bls12381.G1) B {
	b := make(B, 0, len(moduli))
	for i := 0; i < len(moduli); i++ {
		b = append(b, BItem{P: moduli[i], E: Ei[i], D: Di[i]})
	}
	return b
}

// Commitment returns the commitment(R) of the i-th drone
func (b B) commitment(rho *bls12381.Scalar) *bls12381.G1 {
	R := new(bls12381.G1)
	R.SetIdentity()

	sumE := new(bls12381.G1)
	sumE.SetIdentity()

	for _, item := range b {
		R.Add(R, item.D)
		sumE.Add(sumE, item.E)
	}
	sumE.ScalarMult(rho, sumE)
	R.Add(R, sumE)
	return R
}

// Aggregate the signature
func Aggregate(s []*gmp.Int, R *bls12381.G1, P *gmp.Int) (*bls12381.Scalar, *bls12381.G1) {
	order := new(gmp.Int).SetBytes(bls12381.Order()[:])
	defer order.Clear()
	sAgg := new(gmp.Int).SetInt64(0)
	for _, si := range s {
		sAgg.Add(sAgg, si)
	}
	sAgg.Mod(sAgg, P)
	sAgg.Mod(sAgg, order)
	sS := new(bls12381.Scalar)
	sS.SetBytes(sAgg.Bytes())
	return sS, R
}

// Verify the signature
func Verify(m string, s *bls12381.Scalar, R *bls12381.G1, pub *bls12381.G1) bool {
	// c = H(m || R)
	hasher := sha256.New()
	hasher.Write([]byte(m))
	hasher.Write(R.Bytes())

	c := new(bls12381.Scalar)
	c.SetBytes(hasher.Sum(nil))

	// left = s * G
	left := new(bls12381.G1)
	left.ScalarMult(s, bls12381.G1Generator())

	// right = R + c * pub
	right := new(bls12381.G1)
	right.SetIdentity()
	right.Add(right, R)

	// cPub = c * pub
	cPub := new(bls12381.G1)
	cPub.ScalarMult(c, pub)
	right.Add(right, cPub)

	return left.IsEqual(right)
}
