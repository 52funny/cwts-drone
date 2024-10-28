package main

import (
	"fmt"
	"time"

	"github.com/52funny/scheme"
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/ncw/gmp"
)

func main() {
	weight_opts := []int{64, 128, 256}
	n := 100

	moduli := scheme.GenerateNumber(weight_opts, n)
	t := 4
	crt := scheme.NewCRTSharing(n, t, moduli)
	fmt.Println(crt.ThresholdT1, crt.ThresholdT2)
	fmt.Println(crt.PMin1.BitLen(), crt.PMin2.BitLen())

	ei := make([]*bls12381.Scalar, 0, n)
	Ei := make([]*bls12381.G1, 0, n)
	di := make([]*bls12381.Scalar, 0, n)
	Di := make([]*bls12381.G1, 0, n)
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

	T := crt.ThresholdT2

	remainder := crt.Remainder
	B := scheme.NewB(moduli[:T], Ei[:T], Di[:T])

	P := new(gmp.Int).SetInt64(1)

	params := make([]*scheme.Param, 0, T)
	for i := 0; i < T; i++ {
		P.Mul(P, moduli[i])
		params = append(params, scheme.NewParam(ei[i], di[i], remainder[i], crt.Pub, B[i]))
	}

	fmt.Printf("%-10s = %s\n", "S", crt.Secret)
	fmt.Printf("%-10s = %x\n", "P", P.Bytes())

	m := "Hello"

	signs := make([]*gmp.Int, 0, T)
	R := new(bls12381.G1)
	tt := time.Now()
	for _, p := range params {
		tt := time.Now()
		s, r := p.Sign(m, B)
		fmt.Println("Every Sign Time Cost:", time.Since(tt))
		R = r
		signs = append(signs, s)
	}
	fmt.Println("Sign Time Cost:", time.Since(tt))

	tt = time.Now()
	s, R := scheme.Aggregate(signs, R, P)
	fmt.Println("Aggregate Time Cost:", time.Since(tt))
	fmt.Printf("%-10s = %s\n%-10s = %x\n", "s", s, "R", R.Bytes())

	tt = time.Now()
	res := scheme.Verify(m, s, R, crt.Pub)
	fmt.Println("Verify Time Cost:", time.Since(tt))
	fmt.Println("Verify:", res)
}
