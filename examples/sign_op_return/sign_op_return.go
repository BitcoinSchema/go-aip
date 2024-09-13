package main

import (
	"log"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoinschema/go-aip"
)

func main() {
	priv, _ := ec.NewPrivateKey()
	outData, a, err := aip.SignOpReturnData(
		priv,
		aip.BitcoinECDSA,
		[][]byte{[]byte("some op_return data")},
	)
	if err != nil {
		log.Fatalf("error occurred: %s", err.Error())
	}
	log.Printf("address: %s", a.AlgorithmSigningComponent)
	log.Printf("signature: %s", a.Signature)
	log.Printf("output: %x", outData)
}
