package main

import (
	"fmt"
	"net"
	"net/rpc"
	"sync/atomic"

	"github.com/52funny/scheme"
	"github.com/ncw/gmp"
)

type RpcService struct {
	crt *scheme.CRTSharing
	idx atomic.Int32
}

// Parameters returned during registration
type ShareParams struct {
	ID        string   // UUID V4
	Weight    int      // Weight
	Modulus   *gmp.Int // Modulus
	Remainder *gmp.Int // Reminder
	Pub       []byte   // Public key
}

func NewRegisterService(crt *scheme.CRTSharing) *RpcService {
	srv := &RpcService{
		crt: crt,
	}
	srv.idx.Store(0)
	return srv
}

// Register registers a new participant
func (r *RpcService) Register(id string, reply *ShareParams) error {
	// Increment the index using atomic operations
	current := r.idx.Add(1) - 1

	if int(current) >= len(r.crt.Weight) {
		return fmt.Errorf("The number of participants has reached the upper limit")
	}

	params := &ShareParams{
		ID:        id,
		Weight:    r.crt.Weight[current],
		Modulus:   r.crt.Moduli[current],
		Remainder: r.crt.Remainder[current],
		Pub:       r.crt.Pub.BytesCompressed(),
	}
	fmt.Println("Register id:", id, " weight:", params.Weight, " modulus:", params.Modulus, " remainder:", params.Remainder)
	*reply = *params
	return nil
}

// GetPublicKey returns the public key
func (r *RpcService) GetPublicKey(args int, reply *[]byte) error {
	pub := r.crt.Pub.BytesCompressed()
	*reply = pub
	return nil
}

func main() {
	weight_opts := []int{64, 128, 256}
	n := 100

	moduli := scheme.GenerateNumber(weight_opts, n)
	t := 3
	crt := scheme.NewCRTSharing(n, t, moduli)
	fmt.Printf("crt.Pub: %x\n", crt.Pub.BytesCompressed())
	fmt.Printf("crt.ThresholdT2: %v\n", crt.ThresholdT2)

	srv := NewRegisterService(crt)

	rpc.RegisterName("RpcService", srv)
	listener, err := net.Listen("tcp", ":1234")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go rpc.ServeConn(conn)
	}
}
