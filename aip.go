// Package aip is a library for working with Author Identity Protocol (AIP) in Go
//
// If you have any suggestions or comments, please feel free to open an issue on
// this GitHub repository!
//
// By BitcoinSchema Organization (https://bitcoinschema.org)
package aip

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/bitcoinschema/go-bob"
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

// FromTape takes a BOB Tape and returns a Aip data structure.
// Using from tape alone will prevent validation (data is needed via SetData to enable)
func (a *Aip) FromTape(tape bob.Tape) {

	if len(tape.Cell) < 4 || tape.Cell[0].S != Prefix {
		return
	}

	a.Algorithm = Algorithm(tape.Cell[1].S)
	a.AlgorithmSigningComponent = tape.Cell[2].S
	a.Signature = tape.Cell[3].B // Is this B or S????

	if len(tape.Cell) > 4 {

		a.Indices = make([]int, len(tape.Cell)-4)

		// TODO: Consider OP_RETURN is included in sig when processing a tx using indices
		// Loop over remaining indices if they exist and append to indices slice
		for x := 4; x < len(tape.Cell); x++ {
			index, _ := strconv.ParseUint(tape.Cell[x].S, 10, 64)
			// todo: check error?
			a.Indices = append(a.Indices, int(index))
		}
	}
}

// SetDataFromTape sets the data the AIP signature is signing
func (a *Aip) SetDataFromTape(tapes []bob.Tape) {

	var data = []string{"j"}

	if len(a.Indices) == 0 {

		// walk over all output values and concatenate them until we hit the aip prefix, then add in the separator
		for _, tape := range tapes {
			for _, cell := range tape.Cell {
				if cell.S != Prefix {
					// Skip the OPS
					if cell.Ops != "" {
						continue
					}
					data = append(data, cell.S)
				} else {
					data = append(data, pipe)
					a.Data = data
					return
				}
			}
		}

	} else {
		var indexCt = 0

		for _, tape := range tapes {
			for _, cell := range tape.Cell {
				if cell.S != Prefix && contains(a.Indices, indexCt) {
					data = append(data, cell.S)
				} else {
					data = append(data, pipe)
				}
				indexCt++
			}
		}

		a.Data = data
	}
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

// NewFromTape will create a new AIP object from a bob.Tape
func NewFromTape(tape bob.Tape) (a *Aip) {
	a = new(Aip)
	a.FromTape(tape)
	return
}

// SignBobOpReturnData appends a signature to a BOB Tx by adding a
// protocol separator followed by AIP information
func SignBobOpReturnData(privateKey string, algorithm Algorithm, output bob.Output) (*bob.Output, *Aip, error) {

	// Parse the data to sign
	var dataToSign []string
	for _, tape := range output.Tape {
		for _, cell := range tape.Cell {
			if len(cell.S) > 0 {
				dataToSign = append(dataToSign, cell.S)
			} else {
				// TODO: Review this case. Should we assume the b64 is signed?
				//  Should protocol doc for AIP mention this?
				dataToSign = append(dataToSign, cell.B)
			}
		}
	}

	// Sign the data
	a, err := Sign(privateKey, algorithm, strings.Join(dataToSign, ""))
	if err != nil {
		return nil, nil, err
	}

	// Create the output tape
	output.Tape = append(output.Tape, bob.Tape{
		Cell: []bob.Cell{{
			H: hex.EncodeToString([]byte(Prefix)),
			S: Prefix,
		}, {
			H: hex.EncodeToString([]byte(algorithm)),
			S: string(algorithm),
		}, {
			H: hex.EncodeToString([]byte(a.AlgorithmSigningComponent)),
			S: a.AlgorithmSigningComponent,
		}, {
			H: hex.EncodeToString([]byte(a.Signature)),
			S: a.Signature,
		}},
	})

	return &output, a, nil
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

// Sign will provide an AIP signature for a given private key and message
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
		// SigningComponent = bitcoin address
		// Get the address of the private key
		if a.AlgorithmSigningComponent, err = bitcoin.GetAddressFromPrivateKey(privateKey); err != nil {
			return
		}
	case Paymail:
		// SigningComponent = paymail identity key
		// Get pubKey from private key and overload the address field in AIP
		if a.AlgorithmSigningComponent, err = bitcoin.PubKeyFromPrivateKeyString(privateKey); err != nil {
			return
		}
	}
	return
}

// ValidateTapes validates the AIP signature for a given []bob.Tape
func ValidateTapes(tapes []bob.Tape) bool {
	for _, tape := range tapes {
		// Once we hit AIP Prefix, stop
		if tape.Cell[0].S == Prefix {
			a := NewFromTape(tape)
			a.SetDataFromTape(tapes)
			return a.Validate()
		}
	}
	return false
}

// contains looks in a slice for a given value
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
