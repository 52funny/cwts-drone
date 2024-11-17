package scheme_test

import (
	"flag"
	"sync"
	"testing"

	"github.com/52funny/scheme"
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/ncw/gmp"
	"github.com/stretchr/testify/assert"
)

var N = flag.Int("num", 50, "number of shares")
var T = flag.Int("threshold", 20, "threshold")

var moduli []*gmp.Int
var crt *scheme.CRTSharing
var ei []*bls12381.Scalar
var di []*bls12381.Scalar
var Ei []*bls12381.G1
var Di []*bls12381.G1

// Setup the parameters
func preparation() {
	weightOpts := []int{256}
	n := *N
	t := *T
	moduli = scheme.GenerateNumber(weightOpts, n)
	crt = scheme.NewCRTSharing(n, t-4, moduli)

	for i := 0; i < n; i++ {
		ei = append(ei, scheme.GenerateScalar())
		di = append(di, scheme.GenerateScalar())

		// E = ei * G
		E := new(bls12381.G1)
		E.ScalarMult(ei[i], bls12381.G1Generator())
		Ei = append(Ei, E)

		// D = di * G
		D := new(bls12381.G1)
		D.ScalarMult(di[i], bls12381.G1Generator())
		Di = append(Di, D)
	}
}

// Only run once
var once = sync.OnceFunc(func() {
	preparation()
})

func TestCRT(t *testing.T) {
	once()
	T := crt.ThresholdT2
	remainder := crt.Remainder
	B := scheme.NewB(moduli[:T], Ei[:T], Di[:T])

	m := "Hello World"
	signers := make([]*scheme.Signer, 0, T)
	signs := make([]*gmp.Int, 0, T)
	Rs := make([]*bls12381.G1, 0, T)

	P := new(gmp.Int).SetInt64(1)
	for i := 0; i < T; i++ {
		signers = append(signers, scheme.NewSigner(ei[i], di[i], remainder[i], crt.Pub, B[i]))
		s, R := signers[i].Sign(m, B)
		signs = append(signs, s)
		Rs = append(Rs, R)
		P.Mul(P, moduli[i])
	}

	s, r := scheme.Aggregate(signs, Rs[0], P)
	assert.True(t, scheme.Verify(m, s, r, crt.Pub))
}

func BenchmarkSign(b *testing.B) {
	once()
	T := crt.ThresholdT2
	remainder := crt.Remainder
	B := scheme.NewB(moduli[:T], Ei[:T], Di[:T])
	P := new(gmp.Int).SetInt64(1)

	signers := make([]*scheme.Signer, 0, T)
	for i := 0; i < T; i++ {
		P.Mul(P, moduli[i])
		signers = append(signers, scheme.NewSigner(ei[i], di[i], remainder[i], crt.Pub, B[i]))
	}

	m := "Hello World"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signers[0].Sign(m, B)
	}
}

func BenchmarkSignAggregation(b *testing.B) {
	once()
	T := crt.ThresholdT2
	remainder := crt.Remainder
	B := scheme.NewB(moduli[:T], Ei[:T], Di[:T])
	P := new(gmp.Int).SetInt64(1)

	signers := make([]*scheme.Signer, 0, T)
	for i := 0; i < T; i++ {
		P.Mul(P, moduli[i])
		signers = append(signers, scheme.NewSigner(ei[i], di[i], remainder[i], crt.Pub, B[i]))
	}

	m := "Hello World"
	signs := make([]*gmp.Int, 0, T)
	R := new(bls12381.G1)
	for _, p := range signers {
		s, r := p.Sign(m, B)
		R = r
		signs = append(signs, s)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		P := new(gmp.Int).SetInt64(1)
		for j := 0; j < T; j++ {
			P.Mul(P, moduli[j])
		}
		scheme.Aggregate(signs, R, P)
	}
}

func BenchmarkSignVerify(b *testing.B) {
	once()
	T := crt.ThresholdT2
	remainder := crt.Remainder
	B := scheme.NewB(moduli[:T], Ei[:T], Di[:T])
	P := new(gmp.Int).SetInt64(1)

	signers := make([]*scheme.Signer, 0, T)
	for i := 0; i < T; i++ {
		P.Mul(P, moduli[i])
		signers = append(signers, scheme.NewSigner(ei[i], di[i], remainder[i], crt.Pub, B[i]))
	}

	m := "Hello World"
	signs := make([]*gmp.Int, 0, T)
	R := new(bls12381.G1)
	for _, p := range signers {
		s, r := p.Sign(m, B)
		R = r
		signs = append(signs, s)
	}
	s, R := scheme.Aggregate(signs, R, P)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.Verify(m, s, R, crt.Pub)
	}
}
