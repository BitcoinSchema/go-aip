package aip

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
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
	if tape.Cell[startIndex+3].B != nil {
		a.Signature = *tape.Cell[startIndex+3].B
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
}

// NewFromTapes will create a new AIP object from a []bob.Tape
// Using the FromTapes() alone will prevent validation (data is needed via SetData to enable)
func NewFromTapes(tapes []bpu.Tape) (a *Aip) {
	// Loop tapes -> cells (only supporting 1 sig right now)
	for _, t := range tapes {
		for _, cell := range t.Cell {
			if cell.S != nil && *cell.S == Prefix {
				a = new(Aip)
				a.FromTape(t)
				a.SetDataFromTapes(tapes, 0)
				return
			}
		}
	}
	return
}

// // SetDataFromTapes sets the data the AIP signature is signing
// func (a *Aip) SetDataFromTapes(tapes []bpu.Tape) {

// 	// Set OP_RETURN to be consistent with BitcoinFiles SDK
// 	var data = []string{opReturn}

// 	if len(a.Indices) == 0 {

// 		// Walk over all output values and concatenate them until we hit the AIP prefix, then add in the separator
// 		for _, tape := range tapes {
// 			for _, cell := range tape.Cell {
// 				if cell.S != nil && *cell.S == Prefix {
// 					data = append(data, pipe)
// 					a.Data = data
// 					return
// 				}
// 				// Skip the OPS
// 				// if cell.Ops != nil {
// 				if cell.Op != nil && (*cell.Op == 0 || *cell.Op > 0x4e) {
// 					continue
// 				}
// 				if cell.S != nil {
// 					data = append(data, strings.TrimSpace(*cell.S))
// 				}

// 			}
// 		}

// 	} else {

// 		var indexCt = 0

// 		for _, tape := range tapes {
// 			for _, cell := range tape.Cell {
// 				if cell.S != nil && *cell.S != Prefix && contains(a.Indices, indexCt) {
// 					data = append(data, *cell.S)
// 				} else {
// 					data = append(data, pipe)
// 				}
// 				indexCt++
// 			}
// 		}

// 		a.Data = data
// 	}
// }

// SetDataFromTapes sets the data the AIP signature is signing
func (a *Aip) SetDataFromTapes(tapes []bpu.Tape, instance int) {
	// Set OP_RETURN to be consistent with BitcoinFiles SDK
	// var data [][]byte
	var data = []string{opReturn}
	var foundAIP bool
	var aipTapeIndex int
	var aipCellIndex int

	// First find the AIP tape and cell index
	aipCount := 0
	for i, tape := range tapes {
		for j, cell := range tape.Cell {
			if cell.S != nil && *cell.S == Prefix {
				if aipCount == instance {
					aipTapeIndex = i
					aipCellIndex = j
					foundAIP = true
					break
				}
				aipCount++
			}

		}
		if foundAIP {
			break
		}
	}

	// If we found AIP, collect data from all tapes up to the AIP tape
	if foundAIP {
		if len(a.Indices) == 0 {

			// Walk over all output values and concatenate them until we hit the AIP prefix, then add in the separator
			for i, tape := range tapes {
				for j, cell := range tape.Cell {
					if i == aipTapeIndex && j >= aipCellIndex {
						break
					}
					if cell.S != nil && *cell.S == Prefix {
						data = append(data, pipe)
						a.Data = data
						return
					}
					// Skip the OPS
					// if cell.Ops != nil {
					if cell.Op != nil && (*cell.Op == 0 || *cell.Op > 0x4e) {
						continue
					}
					if cell.S != nil {
						data = append(data, strings.TrimSpace(*cell.S))
					}

				}
			}

		} else {

			var indexCt = 0

			for _, tape := range tapes {
				for _, cell := range tape.Cell {
					if cell.S != nil && *cell.S != Prefix && contains(a.Indices, indexCt) {
						data = append(data, *cell.S)
					} else {
						data = append(data, pipe)
					}
					indexCt++
				}
			}

			a.Data = data
		}

		// // Always start with OP_RETURN
		// data = append(data, []byte{byte(script.OpRETURN)})

		// // Collect all data up to the AIP entry
		// for i := 0; i < len(tapes); i++ {
		// 	for j := 0; j < len(tapes[i].Cell); j++ {
		// 		cell := tapes[i].Cell[j]
		// 		// If we're on the AIP tape and at/past the AIP cell, stop
		// 		if i == aipTapeIndex && j >= aipCellIndex {
		// 			break
		// 		}

		// 		// Skip OP_RETURN since we already added it
		// 		if cell.Op != nil && *cell.Op == script.OpRETURN {
		// 			continue
		// 		}

		// 		// Add the cell data if it exists
		// 		if cell.B != nil {
		// 			bytesFromBase64, err := base64.StdEncoding.DecodeString(*cell.B)
		// 			if err != nil {
		// 				return
		// 			}
		// 			data = append(data, bytesFromBase64)
		// 		}
		// 		// else if cell.H != nil {
		// 		// 	bytesFromHex, err := hex.DecodeString(*cell.H)
		// 		// 	if err != nil {
		// 		// 		return
		// 		// 	}
		// 		// 	data = append(data, bytesFromHex)
		// 		// } else if cell.S != nil {
		// 		// 	data = append(data, []byte(*cell.S))
		// 		// }
		// 	}

		// }
		// // add the protocol separator
		// data = append(data, []byte(pipe))
	}

	// Join all data with no separator to match signing format
	// a.Data = bytes.Join(data, []byte{})

	// log the data
	fmt.Printf("Data: %x\n", a.Data)
}

// SignBobOpReturnData appends a signature to a BOB Tx by adding a
// protocol separator followed by AIP information
func SignBobOpReturnData(privateKey *ec.PrivateKey, algorithm Algorithm, output bpu.Output) (*bpu.Output, *Aip, error) {

	// Parse the data to sign
	var dataToSign []string
	for _, tape := range output.Tape {
		for _, cell := range tape.Cell {
			if cell.S != nil {
				dataToSign = append(dataToSign, *cell.S)
			} else {
				// TODO: Review this case. Should we assume the b64 is signed?
				//  Should protocol doc for AIP mention this?
				if cell.B != nil {
					dataToSign = append(dataToSign, *cell.B)
				}
				// else if cell.Op != nil {
				// 	dataToSign = append(dataToSign, string(*cell.Op))
				// }
			}
		}
	}

	// Sign the data
	a, err := Sign(privateKey, algorithm, strings.Join(dataToSign, ""))
	if err != nil {
		return nil, nil, err
	}

	algoHex := hex.EncodeToString([]byte(algorithm))
	algoStr := string(algorithm)

	hexAlgoSigningComponent := hex.EncodeToString([]byte(a.AlgorithmSigningComponent))
	hexSig := hex.EncodeToString([]byte(a.Signature))

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
			S: &a.Signature,
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
				a.SetDataFromTapes(tapes, 0)
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
	instance := 0
	for i, t := range tapes {
		for _, cell := range t.Cell {
			if cell.S != nil && *cell.S == Prefix {
				a := new(Aip)
				a.FromTape(t)
				// For all AIP entries, include all data from the start up to this entry
				a.SetDataFromTapes(tapes[:i+1], instance)
				instance++
				aips = append(aips, a)
				continue
			}
		}
	}
	return aips
}
