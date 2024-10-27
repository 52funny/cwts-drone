package scheme

import (
	"crypto/rand"
	mrand "math/rand"
	"slices"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/ncw/gmp"
)

// Number of goroutines
const GOROUTINES int = 16

// Generate a random prime number with the specified number of bits
func GeneratePrime(bits int) *gmp.Int {
	x := new(gmp.Int)
	for {
		buf := make([]byte, bits/8)
		rand.Read(buf)

		// Make sure the highest bit is 1
		buf[0] |= 0b01000000
		// Make sure the lowest bit is 1
		buf[len(buf)-1] |= 0b00000001

		x.SetBytes(buf)
		if x.ProbablyPrime(3) {
			break
		}
	}
	return x
}

// Generate a random prime number in the range [n / (n + 1) * 2 ** bits, 2 ** bits)
func GenerateRangePrime(bits int, n int) *gmp.Int {
	// mst = 2 ** bits
	mst := new(gmp.Int)
	mst.Lsh(gmp.NewInt(1), uint(bits))

	// lo = n / (n + 1) * 2 ** bits
	// hi = 2 ** bits
	lo, hi := new(gmp.Rat), new(gmp.Rat)
	lo.SetNum(mst)
	hi.SetNum(mst)
	lo.Mul(lo, gmp.NewRat(int64(n), int64(n+1)))

	// Generate a random number in the range [lo, hi)
	x := new(gmp.Int)
	for {
		x = GeneratePrime(bits)
		xRat := new(gmp.Rat).SetNum(x)
		// Make sure lo <= x < hi
		if xRat.Cmp(hi) == -1 && xRat.Cmp(lo) >= 0 {
			break
		}
		xRat.Clear()
	}
	// Free the memory
	mst.Clear()
	lo.Clear()
	hi.Clear()
	return x
}

func Compact(arr []*gmp.Int) []*gmp.Int {
	// Remove duplicates
	unique := make(map[string]*gmp.Int)
	for _, x := range arr {
		unique[x.String()] = x
	}

	// Convert map to slice
	compacted := make([]*gmp.Int, 0, len(unique))
	for _, x := range unique {
		compacted = append(compacted, x)
	}
	return compacted
}

func GenerateNumber(weightOpts []int, n int) []*gmp.Int {
	ch := make(chan int, n)
	product := make(chan *gmp.Int, n)

	for i := 0; i < GOROUTINES; i++ {
		go func() {
			for weight := range ch {
				p := GenerateRangePrime(weight, n)
				product <- p
			}
		}()
	}

	for range n {
		w := weightOpts[mrand.Intn(len(weightOpts))]
		ch <- w
	}

	moduli := make([]*gmp.Int, 0, n)
	for i := 0; i < n; i++ {
		p := <-product
		moduli = append(moduli, p)
	}
	close(ch)
	close(product)

	// Sort the moduli in ascending order
	slices.SortFunc(moduli, func(x, y *gmp.Int) int {
		return x.Cmp(y)
	})
	return moduli
}

// Conver the GMP integer to a bls12381 scalar
func GmpToScalar(g *gmp.Int) *bls12381.Scalar {
	// Copy the scalar and reduce it modulo the order of the curve
	gCopy := new(gmp.Int).Set(g)
	order := bls12381.Order()
	orderGmp := new(gmp.Int).SetBytes(order)
	gCopy.Mod(gCopy, orderGmp)
	buf := gCopy.Bytes()

	// Free the gCopy memory
	gCopy.Clear()

	scalar := new(bls12381.Scalar)
	scalar.SetBytes(buf)
	return scalar
}

// Convert the bls12381 scalar to a GMP integer
func ScalarToGmp(scalar *bls12381.Scalar) *gmp.Int {
	buf := scalar.String()
	// buf[2:] is remove the 0x prefix
	g, _ := new(gmp.Int).SetString(buf[2:], 16)
	return g
}

// Generate a random scalar
func GenerateScalar() *bls12381.Scalar {
	buf := make([]byte, 32)
	rand.Read(buf)
	sc := new(bls12381.Scalar)
	sc.SetBytes(buf)
	return sc
}
