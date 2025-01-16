package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/rpc"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/52funny/scheme"
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gorilla/websocket"
	"github.com/ncw/gmp"
)

var upgrader = websocket.Upgrader{}

type Message struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

// UavPubMessage is the parameter that the drone gives to the aggregator
type UavPubMessage struct {
	ID string
	E  []byte
	D  []byte
	P  *gmp.Int
}

// SignPrepMessage is the message that the aggregator sends to the drone
type SignPrepMessage struct {
	Msg string
	B   B
}

// SignResultMessage is the message that the drone sends to the aggregator
// (s, R) schnorr signature
type SignResultMessage struct {
	S *gmp.Int
	R []byte
}

type BItem struct {
	P *gmp.Int // The prime number
	E []byte   // The E
	D []byte   // The D
}

type B []BItem

// Schnorr Signature
type Signature struct {
	S *gmp.Int
	R *bls12381.G1
}

const TA_ADDR = "localhost:1234"

// Public key
var pub bls12381.G1

var signTimeStart time.Time

func main() {
	// Connect to the TA so that we can get the public key
	client, err := rpc.Dial("tcp", TA_ADDR)
	if err != nil {
		log.Fatal("dialing:", err)
	}

	var pubBytes []byte
	err = client.Call("RpcService.GetPublicKey", 0, &pubBytes)
	if err != nil {
		log.Fatal("register error:", err)
	}
	pub.SetBytes(pubBytes)
	fmt.Printf("pub: %x\n", pub.BytesCompressed())

	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}

	store := NewStore()

	collectSignCh := make(chan Signature, 256)
	aggreCh := make(chan interface{})
	go CollectSignature(collectSignCh, aggreCh, store)

	hub := newHub()
	go hub.run()

	// websocket
	http.HandleFunc("/", listen(hub, store, collectSignCh))
	go http.ListenAndServe(":2345", nil)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		s := scanner.Text()
		if s == "exit" {
			break
		}
		if s == "aggregate" {
			aggreCh <- struct{}{}
			continue
		}
		hub.broadcast <- s
	}
}

func listen(hub *Hub, store *Store, collect chan Signature) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("upgrade error:", err)
			return
		}
		c := &Client{
			store:   store,
			conn:    conn,
			hub:     hub,
			collect: collect,
			send:    make(chan string, 1), // ???? What is the buffer size
		}
		c.hub.register <- c
		go c.readPump()
		go c.writePump()
	}
}

type Client struct {
	store   *Store          // Store
	conn    *websocket.Conn // WebSocket connection
	send    chan string     // Send channel
	collect chan Signature  // Collect Signature
	hub     *Hub            // Hub
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		mt, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}

		if mt != websocket.TextMessage {
			continue
		}

		fmt.Println("Received message:", string(message))
		msg := Message{}
		json.Unmarshal(message, &msg)
		// Handle the message
		c.handleMessage(&msg)
	}
}

func (c *Client) writePump() {
	defer c.conn.Close()
	for cmd := range c.send {
		switch strings.ToLower(cmd) {
		case "signprep":
			c.store.mux.Lock()
			b := transform(c.store.m)
			c.store.mux.Unlock()

			data := SignPrepMessage{
				Msg: "Hello World!",
				B:   b,
			}
			buffer := new(bytes.Buffer)
			e := gob.NewEncoder(buffer).Encode(&data)
			if e != nil {
				log.Println("encode:", e)
				continue
			}
			msg := Message{
				Type: "SIGNPREP",
				Data: buffer.Bytes(),
			}
			err := c.conn.WriteJSON(msg)
			if err != nil {
				return
			}
			fmt.Println("SignPrep Command is sent")
		case "sign":
			msg := Message{
				Type: "SIGN",
				Data: nil,
			}
			err := c.conn.WriteJSON(msg)
			if err != nil {
				return
			}
			signTimeStart = time.Now()
			fmt.Println("Sign Command is sent")
		case "exit":
			return
		}
	}
}

func transform(m map[string]*scheme.BItem) B {
	var b B
	for _, v := range m {
		item := BItem{
			P: v.P,
			E: v.E.BytesCompressed(),
			D: v.D.BytesCompressed(),
		}
		b = append(b, item)
	}
	slices.SortFunc(b, func(a, b BItem) int {
		return a.P.Cmp(b.P)
	})
	return b
}

func (c *Client) handleMessage(msg *Message) {
	switch msg.Type {
	case "PARAMS":
		pp := UavPubMessage{}
		gob.NewDecoder(bytes.NewReader(msg.Data)).Decode(&pp)
		D := new(bls12381.G1)
		D.SetBytes(pp.D)
		E := new(bls12381.G1)
		E.SetBytes(pp.E)
		bItem := scheme.BItem{
			E: E,
			D: D,
			P: pp.P,
		}
		c.store.Add(pp.ID, &bItem)
	case "SIGNRES":
		signMsg := SignResultMessage{}
		err := gob.NewDecoder(bytes.NewReader(msg.Data)).Decode(&signMsg)
		if err != nil {
			log.Println("decode:", err)
			return
		}
		R := new(bls12381.G1)
		R.SetBytes(signMsg.R)
		sig := Signature{
			S: signMsg.S,
			R: R,
		}
		c.collect <- sig
	}
}

// Collect Signature
func CollectSignature(collectCh chan Signature, aggregate chan interface{}, store *Store) {
	signs := make([]*gmp.Int, 0, 256)
	R := make([]*bls12381.G1, 0, 256)
	for {
		select {
		case s := <-collectCh:
			signs = append(signs, s.S)
			R = append(R, s.R)

			if store.Len() == len(signs) {
				fmt.Println("Sign Time Cost:", time.Since(signTimeStart))
			}

		case <-aggregate:
			if len(R) == 0 {
				log.Println("No signature to aggregate")
				continue
			}
			p := store.CalculateP()

			tt := time.Now()
			z, r := scheme.Aggregate(signs, R[0], p)
			fmt.Println("Aggregate Time Cost:", time.Since(tt))

			fmt.Println("Aggregated Signature:")
			fmt.Printf("z: %v\n", z)
			fmt.Printf("R: %x\n", r.BytesCompressed())
			t := scheme.Verify("Hello World!", z, r, &pub)
			fmt.Println("Verify:", t)
		}
	}
}
