package scheme

import (
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/ncw/gmp"
)

// 128 bit statistical level
const LAMBDA int = 128

// 256 bit output of the hash function
// sha256
const HASH_BITS int = 256

type CRTSharing struct {
	N           int          // Number of parties
	ThresholdT1 int          // The minimum number of participants required to recover the secret.
	ThresholdT2 int          // The minimum number of participants required for threshold signatures.
	Thresholdt  int          // The maximum number of participants who cannot recover the secret.
	Weight      []int        // The weight of each participant.
	Moduli      []*gmp.Int   // The modulus of each participant.
	Remainder   []*gmp.Int   // The remainder of each participant.
	Secret      *gmp.Int     // The secret to be shared.
	PMin1       *gmp.Int     // The modular product of the minimum number of participants required to recover the secret.
	PMin2       *gmp.Int     // The modular product of the minimum number of participants required for threshold signatures.
	PMax        *gmp.Int     // The modular product of the maximum number of participants who cannot recover the secret.
	Pub         *bls12381.G1 // The public key
}

func NewCRTSharing(n int, t int, moduli []*gmp.Int) *CRTSharing {
	// Calculate the weight of each participant
	weight := make([]int, 0, n)
	for _, g := range moduli {
		weight = append(weight, g.BitLen())
	}

	// Calculate the PMax
	pMax := new(gmp.Int).SetInt64(1)
	for i := n - t; i < n; i++ {
		pMax.Mul(pMax, moduli[i])
	}

	// L = 2 ** (LAMBDA + pMax.bit_length())
	L := new(gmp.Int).SetInt64(1)
	L.Lsh(L, uint(LAMBDA+pMax.BitLen()))

	// Generate a random prime number within lambda bits
	p := GeneratePrime(LAMBDA)
	tmp := GeneratePrime(LAMBDA)

	p0 := new(gmp.Int).Mod(tmp, p)
	tmp.Clear()

	// leftBoundary = (L+1) * p0
	leftBoundary := new(gmp.Int).SetInt64(1)
	leftBoundary.Add(leftBoundary, L)
	leftBoundary = leftBoundary.Mul(leftBoundary, p)

	// Calculate the PMin
	pMin := new(gmp.Int).SetInt64(1)
	T := 0
	for T < n && pMin.Cmp(leftBoundary) != 1 {
		pMin.Mul(pMin, moduli[T])
		T += 1
	}
	T1 := T

	// Calculate the secret
	// S = p0 + p * L
	S := new(gmp.Int).SetInt64(0)
	S.Add(S, p0)
	tmp = new(gmp.Int).Mul(p, L)
	S.Add(S, tmp)
	tmp.Clear()

	// Make sure the secret is less than or equal to (L+1) * p0
	// S <= (L+1) * p0
	if S.Cmp(leftBoundary) == 1 {
		panic("Secret must be less than or equal to (L+1) * p0")
	}

	// Free boundary
	leftBoundary.Clear()

	// rightBoundary = 2 ** HASH_BITS * S
	rightBoundary := new(gmp.Int).SetInt64(1)
	rightBoundary.Lsh(rightBoundary, uint(HASH_BITS))
	rightBoundary.Mul(rightBoundary, S)

	pMin2 := new(gmp.Int).Set(pMin)
	for T < n && pMin2.Cmp(rightBoundary) != 1 {
		pMin2.Mul(pMin2, moduli[T])
		T++
	}
	T2 := T

	// (L+1) * p0 < PMin < PMin2 < 2 ** HASH_BITS * S
	// Make sure the PMin is greater than (L+1) * p0
	if pMin.Cmp(leftBoundary) != 1 {
		panic("PMin must be greater than (L+1) * p")
	}

	// Make sure the PMin2 is large than 2 ** HASH_BITS * S
	if pMin2.Cmp(rightBoundary) != 1 {
		panic("PMin2 must be large than 2 ** HASH_BITS * S")
	}

	// Calculate the insecurity
	// insecurity = pMax / L
	// insecurity := new(gmp.Rat).SetFrac(pMax, L)

	// Calculate the remainder
	remainder := make([]*gmp.Int, 0, n)
	for i := 0; i < n; i++ {
		remainder = append(remainder, new(gmp.Int).Mod(S, moduli[i]))
	}

	s := GmpToScalar(S)
	pub := new(bls12381.G1)
	pub.ScalarMult(s, bls12381.G1Generator())

	crt := &CRTSharing{
		N:           n,
		ThresholdT1: T1,
		ThresholdT2: T2,
		Thresholdt:  t,
		Weight:      weight,
		Moduli:      moduli,
		Remainder:   remainder,
		Secret:      S,
		PMin1:       pMin,
		PMin2:       pMin2,
		PMax:        pMax,
		Pub:         pub,
	}

	return crt
}

// Reconstruct the secret from the shares using the Chinese Remainder Theorem
func ReconstructSecret(moduli []*gmp.Int, remainder []*gmp.Int) *gmp.Int {
	total := new(gmp.Int).SetInt64(0)

	// Calculate the product of all moduli
	product := new(gmp.Int).SetInt64(1)
	for _, g := range moduli {
		product.Mul(product, g)
	}

	tmp := new(gmp.Int)
	for i := 0; i < len(moduli); i++ {
		// product / moduli[i]
		p := new(gmp.Int).Div(product, moduli[i])
		// p^-1 mod moduli[i]
		pInv := new(gmp.Int).ModInverse(p, moduli[i])
		// (p * p^-1 * remainder[i]) % product
		tmp.Mul(p, pInv)
		tmp.Mul(tmp, remainder[i])
		tmp.Mod(tmp, product)
		// total += (p * p^-1 * remainder[i]) % product
		total.Add(total, tmp)
	}
	total.Mod(total, product)
	// Free the memory
	tmp.Clear()
	product.Clear()
	return total
}
