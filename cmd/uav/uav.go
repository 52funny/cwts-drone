package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/rpc"
	"time"

	"github.com/52funny/scheme"
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/ncw/gmp"
)

// Parameters returned during registration
type ShareParams struct {
	ID        string   // UUID V4
	Weight    int      // Weight
	Modulus   *gmp.Int // Modulus
	Remainder *gmp.Int // Reminder
	Pub       []byte   // Public key
}

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

// WebSocket server address
const WebSocketServer = "ws://localhost:2345"

func main() {
	client, err := rpc.Dial("tcp", "localhost:1234")
	if err != nil {
		log.Fatal("dialing:", err)
	}

	var secret ShareParams
	id := uuid.New().String()
	err = client.Call("RpcService.Register", id, &secret)
	if err != nil {
		log.Fatal("register error:", err)
	}
	fmt.Println("Register id:", id, " weight:", secret.Weight, " modulus:", secret.Modulus, " remainder:", secret.Remainder)

	e := scheme.GenerateScalar()
	d := scheme.GenerateScalar()
	E := new(bls12381.G1)
	E.ScalarMult(e, bls12381.G1Generator())
	D := new(bls12381.G1)
	D.ScalarMult(d, bls12381.G1Generator())

	// Parameters to be sent to the aggregator
	bItem := scheme.BItem{
		E: E,
		D: D,
		P: secret.Modulus,
	}
	pub := new(bls12381.G1)
	pub.SetBytes(secret.Pub)
	pp := scheme.NewSigner(e, d, secret.Remainder, pub, bItem)

	fmt.Printf("pp.Pub: %x\n", pp.Pub.BytesCompressed())

	conn, _, err := websocket.DefaultDialer.Dial(WebSocketServer, nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	pubMsg := UavPubMessage{
		ID: id,
		E:  E.BytesCompressed(),
		D:  D.BytesCompressed(),
		P:  secret.Modulus,
	}
	buffer := new(bytes.Buffer)
	gob.NewEncoder(buffer).Encode(pubMsg)
	msg := Message{
		Type: "PARAMS",
		Data: buffer.Bytes(),
	}
	err = conn.WriteJSON(msg)
	if err != nil {
		log.Fatal("write:", err)
	}

	// m is message that need to be signed
	var m string
	// BList is the list of BItem
	var BList scheme.B

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Fatal("read:", err)
		}
		fmt.Println("Received message:", string(message))
		msg := Message{}
		json.Unmarshal(message, &msg)
		switch msg.Type {
		case "SIGNPREP":
			// SIGNPREP is the message to prepare the signature
			fmt.Println("Signature preparation")
			prepMsg := SignPrepMessage{}
			err := gob.NewDecoder(bytes.NewReader(msg.Data)).Decode(&prepMsg)
			if err != nil {
				log.Println("decode:", err)
				return
			}
			BList = transform(prepMsg.B)
			m = prepMsg.Msg
			fmt.Println("B len:", len(BList))
			fmt.Println("M:", m)
		case "SIGN":
			// SIGN is the message to sign the message
			tt := time.Now()
			s, R := pp.Sign(m, BList)
			fmt.Println("Sign Time Cost:", time.Since(tt))
			fmt.Printf("s: %v\n", s)
			fmt.Printf("R: %x\n", R.BytesCompressed())
			signMsg := SignResultMessage{
				S: s,
				R: R.BytesCompressed(),
			}
			var buffer bytes.Buffer
			gob.NewEncoder(&buffer).Encode(signMsg)
			msg := Message{
				Type: "SIGNRES",
				Data: buffer.Bytes(),
			}
			err := conn.WriteJSON(msg)
			if err != nil {
				log.Println("write:", err)
				return
			}
		}
	}
}

func transform(origin B) scheme.B {
	b := make(scheme.B, 0)
	for _, v := range origin {
		E := new(bls12381.G1)
		E.SetBytes(v.E)
		D := new(bls12381.G1)
		D.SetBytes(v.D)
		item := scheme.BItem{
			P: v.P,
			E: E,
			D: D,
		}
		b = append(b, item)
	}
	return b
}
