package aip

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoin-sv/go-sdk/script"
	"github.com/bitcoinschema/go-bpu"
)

// NewFromTape will create a new AIP object from a bob.Tape
// Using the FromTape() alone will prevent validation (data is needed via SetData to enable)
func NewFromTape(tape bpu.Tape) (a *Aip) {
	a = new(Aip)
	a.FromTape(tape)
	return
}

// FromTape takes a BOB Tape and returns an Aip data structure.
// Using the FromTape() alone will prevent validation (data is needed via SetData to enable)
func (a *Aip) FromTape(tape bpu.Tape) {

	// Not a valid tape?
	if len(tape.Cell) < 4 {
		return
	}

	// Loop to find start of AIP
	var startIndex int
	found := false
	for i, cell := range tape.Cell {
		if *cell.S == Prefix {
			startIndex = i
			found = true
			break
		}
	}

	if !found {
		return
	}
	// Set the AIP fields
	if tape.Cell[startIndex+1].S != nil {
		a.Algorithm = Algorithm(*tape.Cell[startIndex+1].S)
	}
	if tape.Cell[startIndex+2].S != nil {
		a.AlgorithmSigningComponent = *tape.Cell[startIndex+2].S
	}
	// Get the signature
	if len(*tape.Cell[startIndex+3].S) > 0 {
		sigBytes, err := base64.StdEncoding.DecodeString(*tape.Cell[startIndex+3].S)
		if err != nil {
			return
		}
		a.Signature = sigBytes
	}

	// Final index count
	finalIndexCount := startIndex + 4

	// Store the indices
	if len(tape.Cell) > finalIndexCount {
		// TODO: Consider OP_RETURN is included in sig when processing a tx using indices
		// Loop over remaining indices if they exist and append to indices slice
		a.Indices = make([]int, len(tape.Cell)-finalIndexCount)
		for x := finalIndexCount - 1; x < len(tape.Cell); x++ {
			if tape.Cell[x].S == nil {
				continue
			}
			if index, err := strconv.Atoi(*tape.Cell[x].S); err == nil {
				a.Indices = append(a.Indices, index)
			}
		}
	}

	// Set the signature
	sigStr := base64.StdEncoding.EncodeToString(a.Signature)
	tape.Cell[startIndex+3].S = &sigStr
}

// NewFromTapes will create a new AIP object from a []bob.Tape
// Using the FromTapes() alone will prevent validation (data is needed via SetData to enable)
func NewFromTapes(tapes []bpu.Tape) (a *Aip) {
	// Find the first tape that contains the AIP prefix
	for i, t := range tapes {
		for _, cell := range t.Cell {
			if cell.S != nil && *cell.S == Prefix {
				a = new(Aip)
				a.FromTape(t)
				// Set data from tapes up to this AIP entry
				a.SetDataFromTapes(tapes[:i+1])
				return
			}
		}
	}
	return
}

// SetDataFromTapes sets the data the AIP signature is signing
func (a *Aip) SetDataFromTapes(tapes []bpu.Tape) {
	// Set OP_RETURN to be consistent with BitcoinFiles SDK
	var data [][]byte
	var foundAIP bool
	var aipTapeIndex int
	var aipCellIndex int

	// First find the AIP tape and cell index
	for i, tape := range tapes {
		for j, cell := range tape.Cell {
			if cell.S != nil && *cell.S == Prefix {
				aipTapeIndex = i
				aipCellIndex = j
				foundAIP = true
				break
			}

		}
		if foundAIP {
			break
		}
	}

	// If we found AIP, collect data from all tapes up to the AIP tape
	if foundAIP {
		// Always start with OP_RETURN
		data = append(data, []byte{byte(script.OpRETURN)})

		// Collect all data up to the AIP entry
		for i := 0; i < len(tapes); i++ {
			for j := 0; j < len(tapes[i].Cell); j++ {
				cell := tapes[i].Cell[j]
				// If we're on the AIP tape and at/past the AIP cell, stop
				if i == aipTapeIndex && j >= aipCellIndex {
					break
				}

				// Skip OP_RETURN since we already added it
				if cell.Op != nil && *cell.Op == script.OpRETURN {
					continue
				}

				// Add the cell data if it exists
				if cell.B != nil {
					bytesFromBase64, err := base64.StdEncoding.DecodeString(*cell.B)
					if err != nil {
						return
					}
					data = append(data, bytesFromBase64)
				}
				// else if cell.H != nil {
				// 	bytesFromHex, err := hex.DecodeString(*cell.H)
				// 	if err != nil {
				// 		return
				// 	}
				// 	data = append(data, bytesFromHex)
				// } else if cell.S != nil {
				// 	data = append(data, []byte(*cell.S))
				// }
			}

		}
		// add the protocol separator
		data = append(data, []byte(pipe))
	}

	// Join all data with no separator to match signing format
	a.Data = bytes.Join(data, []byte{})

	// log the data
	fmt.Printf("Data: %x\n", a.Data)
}

// SignBobOpReturnData appends a signature to a BOB Tx by adding a
// protocol separator followed by AIP information
func SignBobOpReturnData(privateKey *ec.PrivateKey, algorithm Algorithm, output bpu.Output) (*bpu.Output, *Aip, error) {

	// Parse the data to sign
	var dataToSign [][]byte
	for _, tape := range output.Tape {
		for _, cell := range tape.Cell {
			// prefer binary
			if cell.B != nil {
				base64Bytes, err := base64.StdEncoding.DecodeString(*cell.B)
				if err != nil {
					return nil, nil, err
				}
				dataToSign = append(dataToSign, base64Bytes)
			} else if cell.H != nil {
				hexBytes, err := hex.DecodeString(*cell.H)
				if err != nil {
					return nil, nil, err
				}
				dataToSign = append(dataToSign, hexBytes)
			} else if cell.S != nil {
				dataToSign = append(dataToSign, []byte(*cell.S))
			}
		}
	}

	// Sign the data
	a, err := Sign(privateKey, algorithm, bytes.Join(dataToSign, []byte{}))
	if err != nil {
		return nil, nil, err
	}

	// Create hex encoded versions
	hexPrefix := hex.EncodeToString([]byte(Prefix))
	algoHex := hex.EncodeToString([]byte(a.Algorithm))
	hexAlgoSigningComponent := hex.EncodeToString([]byte(a.AlgorithmSigningComponent))
	hexSig := hex.EncodeToString(a.Signature)

	// Create string versions for S fields
	algoStr := string(a.Algorithm)
	sigStr := base64.StdEncoding.EncodeToString(a.Signature)

	// Create the output tape
	output.Tape = append(output.Tape, bpu.Tape{
		Cell: []bpu.Cell{{
			H: &hexPrefix,
			S: &Prefix,
		}, {
			H: &algoHex,
			S: &algoStr,
		}, {
			H: &hexAlgoSigningComponent,
			S: &a.AlgorithmSigningComponent,
		}, {
			H: &hexSig,
			S: &sigStr,
		}},
	})

	return &output, a, nil
}

// ValidateTapes validates the AIP signature for a given []bob.Tape
func ValidateTapes(tapes []bpu.Tape) (bool, error) {
	// Loop tapes -> cells (only supporting 1 sig right now)
	for _, tape := range tapes {
		for _, cell := range tape.Cell {

			// Once we hit AIP Prefix, stop
			if cell.S != nil && *cell.S == Prefix {
				a := NewFromTape(tape)
				a.SetDataFromTapes(tapes)
				return a.Validate()
			}
		}

	}
	return false, errors.New("no AIP tape found")
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

// NewFromAllTapes will create all AIP objects from a []bob.Tape
func NewFromAllTapes(tapes []bpu.Tape) []*Aip {
	var aips []*Aip

	// Find all tapes that contain the AIP prefix
	for i, t := range tapes {
		for _, cell := range t.Cell {
			if cell.S != nil && *cell.S == Prefix {
				a := new(Aip)
				a.FromTape(t)
				// For all AIP entries, include all data from the start up to this entry
				a.SetDataFromTapes(tapes[:i+1])
				aips = append(aips, a)
				continue
			}
		}
	}
	return aips
}
