package main

import (
	"sync"

	"github.com/52funny/scheme"
	"github.com/ncw/gmp"
)

// Store is a store for BItem
type Store struct {
	m   map[string]*scheme.BItem
	mux sync.Mutex
}

func NewStore() *Store {
	return &Store{
		m:   make(map[string]*scheme.BItem),
		mux: sync.Mutex{},
	}
}

func (s *Store) Add(id string, b *scheme.BItem) {
	s.mux.Lock()
	s.m[id] = b
	s.mux.Unlock()
}

func (s *Store) Get(id string) *scheme.BItem {
	s.mux.Lock()
	b := s.m[id]
	s.mux.Unlock()
	return b
}

func (s *Store) Delete(id string) {
	s.mux.Lock()
	delete(s.m, id)
	s.mux.Unlock()
}

func (s *Store) Len() int {
	l := len(s.m)
	return l
}

func (s *Store) CalculateP() *gmp.Int {
	s.mux.Lock()
	product := new(gmp.Int).SetInt64(1)
	for _, v := range s.m {
		product.Mul(product, v.P)
	}
	s.mux.Unlock()
	return product
}
