// Package aip is a library for working with Author Identity Protocol (AIP) in Go
//
// If you have any suggestions or comments, please feel free to open an issue on
// this GitHub repository!
//
// By BitcoinSchema Organization (https://bitcoinschema.org)
package aip

import (
	"bytes"
	"strings"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/libsv/libsv/transaction/output"
)

// Prefix is the Bitcom prefix used by AIP
const Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"
const pipe = "|"

// Algorithm is an enum for the different possible signature algorithms
type Algorithm string

// Algorithm names
const (
	BitcoinECDSA         Algorithm = "BITCOIN_ECDSA"        // Backwards compatible for BitcoinSignedMessage
	BitcoinSignedMessage Algorithm = "BitcoinSignedMessage" // New algo name
	Paymail              Algorithm = "paymail"              // Using "pubkey" as aip.Address
)

// Aip is an Author Identity Protocol object
type Aip struct {
	Algorithm                 Algorithm `json:"algorithm"`                   // Known AIP algorithm type
	AlgorithmSigningComponent string    `json:"algorithm_signing_component"` // Changes based on the Algorithm
	Data                      []string  `json:"data"`                        // Data to be signed or validated
	Indices                   []int     `json:"indices,omitempty"`           // BOB indices
	Signature                 string    `json:"signature"`                   // AIP generated signature
}

// Validate returns true if the given AIP signature is valid for given data
func (a *Aip) Validate() bool {

	// Both data and component are required
	if len(a.Data) == 0 || len(a.AlgorithmSigningComponent) == 0 {
		return false
	}

	// Convert pubkey to address
	if a.Algorithm == Paymail {

		// Get the public address for this paymail from pki
		addr, err := bitcoin.GetAddressFromPubKeyString(a.AlgorithmSigningComponent)
		if err != nil {
			return false
		}
		a.AlgorithmSigningComponent = addr.String()
	}

	// You get the address associated with the pki instead of the current address
	return bitcoin.VerifyMessage(a.AlgorithmSigningComponent, a.Signature, strings.Join(a.Data, "")) == nil
}

// Sign will provide an AIP signature for a given private key and message using
// the provided algorithm
func Sign(privateKey string, algorithm Algorithm, message string) (a *Aip, err error) {

	// Create the base AIP object
	a = &Aip{Algorithm: algorithm, Data: []string{message}}

	// Sign using the private key and the message
	if a.Signature, err = bitcoin.SignMessage(privateKey, message); err != nil {
		return
	}

	// Store address vs pubkey
	switch algorithm {
	case BitcoinECDSA, BitcoinSignedMessage:
		// Signing component = bitcoin address
		// Get the address of the private key
		if a.AlgorithmSigningComponent, err = bitcoin.GetAddressFromPrivateKey(privateKey); err != nil {
			return
		}
	case Paymail:
		// Signingc omponent = paymail identity key
		// Get pubKey from private key and overload the address field in AIP
		if a.AlgorithmSigningComponent, err = bitcoin.PubKeyFromPrivateKeyString(privateKey); err != nil {
			return
		}
	}

	return
}

// SignOpReturnData will append the given data and return an output.Output
func SignOpReturnData(privateKey string, algorithm Algorithm, data [][]byte) (out *output.Output, a *Aip, err error) {

	// Sign with AIP
	if a, err = Sign(privateKey, algorithm, string(bytes.Join(data, []byte{}))); err != nil {
		return
	}

	// Add AIP signature
	data = append(
		data,
		[]byte(Prefix),
		[]byte(a.Algorithm),
		[]byte(a.AlgorithmSigningComponent),
		[]byte(a.Signature),
	)

	// Create the output
	out, err = output.NewOpReturnParts(data)
	return
}
