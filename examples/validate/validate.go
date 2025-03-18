package main

import (
	"log"

	"github.com/bitcoinschema/go-aip"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func main() {
	priv, _ := ec.NewPrivateKey()
	a, err := aip.Sign(
		priv,
		aip.BitcoinECDSA,
		"example message",
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
