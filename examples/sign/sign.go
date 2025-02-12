package main

import (
	"log"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoinschema/go-aip"
)

func main() {
	priv, _ := ec.NewPrivateKey()
	a, err := aip.Sign(
		priv,
		aip.BitcoinECDSA,
		[]byte("example message"),
	)
	if err != nil {
		log.Fatalf("error occurred: %s", err.Error())
	}
	log.Printf("address: %s signature: %s", a.AlgorithmSigningComponent, a.Signature)
}
