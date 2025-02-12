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
	if _, err = a.Validate(); err == nil {
		log.Printf("signature is valid: %s", a.Signature)
	} else {
		log.Fatalf("signature failed validation: %s", err.Error())
	}
}
