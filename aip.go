// Package aip is a library for working with Author Identity Protocol (AIP) in Go
//
// If you have any suggestions or comments, please feel free to open an issue on
// this GitHub repository!
//
// By BitcoinSchema Organization (https://bitcoinschema.org)
package aip

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	bsm "github.com/bitcoin-sv/go-sdk/compat/bsm"
	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoin-sv/go-sdk/script"
)

// Prefix is the Bitcom prefix used by AIP
var Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"

var hexPrefix = hex.EncodeToString([]byte(Prefix))

const pipe = "|"
const opReturn = string(rune(script.OpRETURN)) // creates: j

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
func (a *Aip) Validate() (bool, error) {

	// Both data and component are required
	if len(a.Data) == 0 || len(a.AlgorithmSigningComponent) == 0 {
		return false, errors.New("missing data or signing component")
	}

	// Check to be sure OP_RETURN was prepended before trying to validate
	if a.Data[0] != opReturn {
		return false, fmt.Errorf("the first item in payload is always OP_RETURN, got: %s", a.Data[0])
	}

	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return false, err
	}
	// Convert pubkey to address
	if a.Algorithm == Paymail {
		// Detect whether this key was compressed when sig was made
		_, wasCompressed, err := bsm.PubKeyFromSignature(sig, []byte(strings.Join(a.Data, "")))
		if err != nil {
			return false, err
		}
		var pubKey *ec.PublicKey
		var addr *script.Address
		if pubKey, err = ec.PublicKeyFromString(a.AlgorithmSigningComponent); err != nil {
			return false, err
		}
		if addr, err = script.NewAddressFromPublicKeyWithCompression(
			pubKey,
			true,
			wasCompressed); err != nil {
			return false, err
		}
		a.AlgorithmSigningComponent = addr.AddressString

	}

	// You get the address associated with the pki instead of the current address
	err = bsm.VerifyMessage(a.AlgorithmSigningComponent, sig, []byte(strings.Join(a.Data, "")))
	return err == nil, err
}

// Sign will provide an AIP signature for a given private key and message using
// the provided algorithm. It prepends an OP_RETURN to the payload
func Sign(privateKey *ec.PrivateKey, algorithm Algorithm, message string) (a *Aip, err error) {

	// Prepend the OP_RETURN to keep consistent with BitcoinFiles SDK
	// data = append(data, []byte{byte(txscript.OP_RETURN)})
	prependedData := []string{opReturn, message}

	// Create the base AIP object
	a = &Aip{Algorithm: algorithm, Data: prependedData}

	// Sign using the private key and the message
	var sig []byte
	if sig, err = bsm.SignMessage(privateKey, []byte(strings.Join(prependedData, ""))); err != nil {
		return nil, err
	}

	a.Signature = base64.StdEncoding.EncodeToString(sig)

	// Store address vs pubkey
	switch algorithm {
	case BitcoinECDSA, BitcoinSignedMessage:
		// Signing component = bitcoin address
		// Get the address of the private key
		if add, err := script.NewAddressFromPublicKey(privateKey.PubKey(), true); err != nil {
			return nil, err
		} else {
			a.AlgorithmSigningComponent = add.AddressString
		}
	case Paymail:
		// Signing component = paymail identity key
		// Get pubKey from private key and overload the address field in AIP
		// if pubkey, err := bitcoin.PubKeyFromPrivateKeyString(privateKey, false); err != nil {
		// 	return
		// }
		a.AlgorithmSigningComponent = hex.EncodeToString(privateKey.PubKey().SerializeCompressed())
	}

	return
}

// SignOpReturnData will append the given data and return a bt.Output
func SignOpReturnData(privateKey *ec.PrivateKey, algorithm Algorithm,
	data [][]byte) (outData [][]byte, a *Aip, err error) {

	// Sign with AIP
	if a, err = Sign(privateKey, algorithm, string(bytes.Join(data, []byte{}))); err != nil {
		return
	}

	// Add AIP signature
	outData = append(
		data,
		[]byte(Prefix),
		[]byte(a.Algorithm),
		[]byte(a.AlgorithmSigningComponent),
		[]byte(a.Signature),
	)

	// // Create the output
	// out, err = bt.NewOpReturnPartsOutput(outData)
	return
}
