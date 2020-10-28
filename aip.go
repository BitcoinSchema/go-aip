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
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/bitcoinschema/go-bob"
	"github.com/bitcoinsv/bsvutil"
	"github.com/libsv/libsv/transaction/output"
	"github.com/tonicpow/go-paymail"
)

// Prefix is the Bitcom prefix used by AIP
const Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"
const pipe = "|"

// Algorithm is an enum for the different possible signature algorithms
type Algorithm string

// Algorithms
const (
	BitcoinECDSA Algorithm = "BITCOIN_ECDSA"
	Paymail      Algorithm = "paymail"
)

// Aip is an Author Identity Protocol object
type Aip struct {
	Algorithm Algorithm
	Address   string
	Data      []string
	Signature string
	Indices   []int `json:"indices,omitempty" bson:"indices,omitempty"`
}

// FromTape takes a BOB Tape and returns a Aip data structure.
// Using from tape alone will prevent validation (data is needed via SetData to enable)
func (a *Aip) FromTape(tape bob.Tape) {

	if len(tape.Cell) < 4 || tape.Cell[0].S != Prefix {
		return
	}

	a.Algorithm = Algorithm(tape.Cell[1].S)
	a.Address = tape.Cell[2].S
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
	if len(a.Data) == 0 {
		return false
	}
	switch a.Algorithm {
	case BitcoinECDSA:
		// Validate verifies a Bitcoin signed message signature
		return bitcoin.VerifyMessage(a.Address, a.Signature, strings.Join(a.Data, "")) == nil
	case Paymail:
		if len(a.Address) == 0 {
			return false
		}

		// Get the PKI for the address
		pki, err := getPki(a.Address)
		if err != nil {
			return false
		}

		// Get the public address for this paymail from pki
		var addr *bsvutil.LegacyAddressPubKeyHash
		if addr, err = bitcoin.GetAddressFromPubKeyString(pki.PubKey); err != nil {
			return false
		}

		// You get the address associated with the pki instead of the current address
		return bitcoin.VerifyMessage(addr.String(), a.Signature, strings.Join(a.Data, "")) == nil
	default:
		return false
	}
}

// NewFromTape will create a new AIP object from a bob.Tape
func NewFromTape(tape bob.Tape) (a *Aip) {
	a = new(Aip)
	a.FromTape(tape)
	return
}

// SignBobOpReturnData appends a signature to a BOB Tx by adding a
// protocol separator push_data followed by AIP information
func SignBobOpReturnData(privateKey string, algorithm Algorithm,
	addressString string, output bob.Output) (*bob.Output, *Aip, error) {

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

	// get data to sign from bob tx
	if algorithm == Paymail {
		// pubkey is used, derive address
		addr, err := bitcoin.GetAddressFromPubKeyString(addressString)
		if err != nil {
			return nil, nil, err
		}
		addressString = addr.String()
	}

	// Sign the data
	a, err := Sign(privateKey, algorithm, strings.Join(dataToSign, ""), addressString)
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
			H: hex.EncodeToString([]byte(addressString)),
			S: addressString,
		}, {
			H: hex.EncodeToString([]byte(a.Signature)),
			S: a.Signature,
		}},
	})

	return &output, a, nil
}

// SignOpReturnData will append the given data and return an output.Output
func SignOpReturnData(privateKey string, algorithm Algorithm,
	addressString string, data [][]byte) (*output.Output, *Aip, error) {

	// get data to sign from bob tx
	if algorithm == Paymail {
		// pubkey is used, derive address
		addr, err := bitcoin.GetAddressFromPubKeyString(addressString)
		if err != nil {
			return nil, nil, err
		}
		addressString = addr.String()
	}

	// Sign with AIP
	a, err := Sign(privateKey, BitcoinECDSA, string(bytes.Join(data, []byte{})), addressString)
	if err != nil {
		return nil, nil, err
	}

	// Add AIP signature
	data = append(
		data,
		[]byte(Prefix),
		[]byte(a.Algorithm),
		[]byte(a.Address),
		[]byte(a.Signature),
	)

	// Create the output
	var out *output.Output
	if out, err = output.NewOpReturnParts(data); err != nil {
		return nil, nil, err
	}

	return out, a, nil
}

// Sign will provide an AIP signature for a given private key and message
// Just set paymail = "" when using BitcoinECDSA signature
func Sign(privateKey string, algorithm Algorithm, message, paymailAddress string) (a *Aip, err error) {

	// Create the base AIP object
	a = &Aip{Algorithm: algorithm, Data: []string{message}}
	var sig string

	// Sign using different algorithms
	switch algorithm {
	case BitcoinECDSA:
		if paymailAddress != "" {
			err = fmt.Errorf("paymail is provided but algorithm is: %s", BitcoinECDSA)
			return
		}
		if sig, err = bitcoin.SignMessage(privateKey, message); err != nil {
			return
		}
		a.Signature = sig
		var address string
		if address, err = bitcoin.GetAddressFromPrivateKey(privateKey); err != nil {
			return
		}
		a.Address = address
	case Paymail:
		if sig, err = bitcoin.SignMessage(privateKey, message); err != nil {
			return
		}
		a.Signature = sig
		_, _, a.Address = paymail.SanitizePaymail(paymailAddress)
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

// getPki will fetch the PKI info for a given paymail
func getPki(paymailString string) (*paymail.PKI, error) {

	// Load the client
	client, err := paymail.NewClient(nil, nil)
	if err != nil {
		return nil, err
	}

	// Parse the paymail address
	alias, domain, _ := paymail.SanitizePaymail(paymailString)

	var srv *net.SRV
	srv, err = client.GetSRVRecord(paymail.DefaultServiceName, paymail.DefaultProtocol, domain)
	if err != nil {
		return nil, err
	}

	// Get the capabilities
	// This is required first to get the corresponding PKI endpoint url
	var capabilities *paymail.Capabilities
	if capabilities, err = client.GetCapabilities(srv.Target, paymail.DefaultPort); err != nil {
		return nil, err
	}

	// Extract the PKI URL from the capabilities response
	pkiURL := capabilities.GetString(paymail.BRFCPki, paymail.BRFCPkiAlternate)

	// Get the actual PKI
	return client.GetPKI(pkiURL, alias, domain)
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
