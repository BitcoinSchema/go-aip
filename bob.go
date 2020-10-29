package aip

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/bitcoinschema/go-bob"
)

// NewFromTape will create a new AIP object from a bob.Tape
// Using the FromTape() alone will prevent validation (data is needed via SetData to enable)
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

// FromTape takes a BOB Tape and returns a Aip data structure.
// Using the FromTape() alone will prevent validation (data is needed via SetData to enable)
func (a *Aip) FromTape(tape bob.Tape) {

	// Not a valid tape?
	if len(tape.Cell) < 4 || tape.Cell[0].S != Prefix {
		return
	}

	// Set the AIP fields
	a.Algorithm = Algorithm(tape.Cell[1].S)
	a.AlgorithmSigningComponent = tape.Cell[2].S
	a.Signature = tape.Cell[3].B // Is this B or S????

	// Store the indices
	if len(tape.Cell) > 4 {

		// TODO: Consider OP_RETURN is included in sig when processing a tx using indices
		// Loop over remaining indices if they exist and append to indices slice
		a.Indices = make([]int, len(tape.Cell)-4)
		for x := 4; x < len(tape.Cell); x++ {
			index, err := strconv.ParseUint(tape.Cell[x].S, 10, 64)
			if err == nil {
				a.Indices = append(a.Indices, int(index))
			}
		}
	}
}

// todo: FromTapes() - looks through tapes trying to detect AIP

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

// contains looks in a slice for a given value
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
