package scheme

import (
	"crypto/sha256"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/ncw/gmp"
)

// Parameters owned by the drone
type Param struct {
	e     *bls12381.Scalar // e
	d     *bls12381.Scalar // d
	s     *gmp.Int         // remainder
	Pub   *bls12381.G1     // Public key
	BItem                  // BItem
}

func NewParam(e, d *bls12381.Scalar, s *gmp.Int, pub *bls12381.G1, b BItem) *Param {
	return &Param{e: e, d: d, s: s, Pub: pub, BItem: b}
}

// Sign returns the signature of the i-th drone
// Threshold schnorr signature = (s, R)
func (p *Param) Sign(m string, B B) (*gmp.Int, *bls12381.G1) {
	// Commitment R
	R := B.Commitment(m)
	// rho
	rho := p.rho(m, B)

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
	lambda := p.Lambda(B)

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

// Lambda returns the lambda of the drone
// Lambda = Q * Q^-1
func (p *Param) Lambda(B B) *gmp.Int {
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
	// rho = H(m || B)
	rho := new(bls12381.Scalar)
	rhoContent := make([]byte, 0)
	rhoContent = append(rhoContent, []byte(m)...)
	for _, item := range b {
		rhoContent = append(rhoContent, item.E.Bytes()...)
		rhoContent = append(rhoContent, item.D.Bytes()...)
	}
	rhoBytes := sha256.Sum256(rhoContent)
	rho.SetBytes(rhoBytes[:])
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
func (b B) Commitment(m string) *bls12381.G1 {
	R := new(bls12381.G1)
	R.SetIdentity()

	sumD := new(bls12381.G1)
	sumD.SetIdentity()

	// rho = H(m || B)
	rho := b[0].rho(m, b)
	for _, item := range b {
		// ans = D + rhoE
		R.Add(R, item.D)
		sumD.Add(sumD, item.E)
	}
	sumD.ScalarMult(rho, sumD)
	R.Add(R, sumD)
	return R
}

// Aggregate the signature
func Aggregate(s []*gmp.Int, R *bls12381.G1, P *gmp.Int) (*gmp.Int, *bls12381.G1) {
	order := new(gmp.Int).SetBytes(bls12381.Order()[:])
	defer order.Clear()
	sAgg := new(gmp.Int).SetInt64(0)
	for _, si := range s {
		sAgg.Add(sAgg, si)
	}
	sAgg.Mod(sAgg, P)
	sAgg.Mod(sAgg, order)
	return sAgg, R
}

// Verify the signature
func Verify(m string, s *gmp.Int, R *bls12381.G1, pub *bls12381.G1) bool {
	// c = H(m || R)
	cContent := make([]byte, 0)
	cContent = append(cContent, []byte(m)...)
	cContent = append(cContent, R.Bytes()...)
	cBytes := sha256.Sum256(cContent)
	c := new(bls12381.Scalar)
	c.SetBytes(cBytes[:])

	// left = s * G
	sScalar := GmpToScalar(s)
	left := new(bls12381.G1)
	left.ScalarMult(sScalar, bls12381.G1Generator())

	// right = R + c * pub
	right := new(bls12381.G1)
	right.SetBytes(R.Bytes())

	// cPub = c * pub
	cPub := new(bls12381.G1)
	cPub.ScalarMult(c, pub)
	right.Add(right, cPub)

	return left.IsEqual(right)
}
