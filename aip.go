package aip

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/rohenaz/go-bitcoin"
	"github.com/rohenaz/go-bob"
)

// Prefix is the Bitcom prefix used by AIP
const Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"

// constants
const (
	BITCOIN_ECDSA = "BITCOIN_ECDSA"
)

// Aip is Author Identity Protocol
type Aip struct {
	Algorithm string
	Address   string
	Data      []string
	Signature string
	Indicies  []int `json:"indicies,omitempty" bson:"indicies,omitempty"`
}

// New creates a new Aip struct
func New() *Aip {
	return &Aip{}
}

func (a *Aip) SetData(bobTx *bob.Tx) {
	var data []string

	if len(a.Indicies) == 0 {
		// walk over all output values and concatenate them until we hit the aip prefix, then add in the seperator
		for _, output := range bobTx.Out {

			for _, tape := range output.Tape {
				for _, cell := range tape.Cell {
					if cell.S != Prefix {
						// Skip the OPS
						if cell.Ops != "" {
							log.Println("Skip ops")
							continue
						}
						log.Println("Not the end", cell.S)
						data = append(data, cell.S)
					} else {
						log.Println("We've hit the end", cell.S)
						data = append(data, "|")
						a.Data = data
						return
					}
				}
			}
		}
	} else {
		var indexCt = 0
		for _, output := range bobTx.Out {
			for _, tape := range output.Tape {
				for _, cell := range tape.Cell {

					// TODO: This doesnt work yet, needs the count to start on the AIP containing output
					if cell.S != Prefix && contains(a.Indicies, indexCt) {
						data = append(data, cell.S)
					} else {
						data = append(data, "|")
					}
					indexCt = indexCt + 1
				}
			}
		}
		a.Data = data
	}
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// FromTape takes a BOB Tape and returns a Aip data structure
func (a *Aip) FromTape(tape bob.Tape) {

	// log.Println("Cell len is", len(tape.Cell))
	if len(tape.Cell) < 4 || tape.Cell[0].S != Prefix {
		return
	}

	a.Algorithm = tape.Cell[1].S
	a.Address = tape.Cell[2].S
	a.Signature = tape.Cell[3].B // Is this B or S????

	if len(tape.Cell) > 4 {

		a.Indicies = make([]int, len(tape.Cell)-4)

		// Loop over remaining indicies if they exist and append to indicies slice
		for x := 4; x < len(tape.Cell); x++ {
			// log.Println("X IS", x)
			// log.Printf("Cell Data %+v", tape.Cell[x])
			index, _ := strconv.ParseUint(tape.Cell[x].S, 10, 64)
			a.Indicies = append(a.Indicies, int(index))
		}
		// log.Printf("THE IDXS %+v", a.Indicies)
	}
}

// Sign will provide an AIP signature for a given private key and data
func (a *Aip) Sign(privKey string, message string) (ok bool) {
	// pk = bsvec.PrivateKey
	// pk.Sign(data)
	a.Signature = bitcoin.SignMessage(privKey, message)
	a.Address = bitcoin.AddressFromPrivKey(privKey)
	a.Algorithm = "BITCOIN_ECDSA"
	return true
}

// Validate returns true if the given AIP signature is valid for given data
func (a *Aip) Validate(data string) (ok bool) {
	switch a.Algorithm {
	case BITCOIN_ECDSA:
		// Validate verifies a Bitcoin signed message signature
		return bitcoin.VerifyMessage(a.Address, a.Signature, data)
	}
	return
}

// ValidateTapes validates the AIP signature for a given []bob.Tape
func ValidateTapes(tapes []bob.Tape) bool {

	var data []string
	var aipTape bob.Tape
	for tapeIdx, tape := range tapes {

		// Once we hit AIP Prefix, stop
		if tape.Cell[0].S == Prefix {
			aipTape = tape
			break
		}

		for _, cell := range tape.Cell {
			if cell.Op > 0 {
				data = append(data, fmt.Sprintf("%d", cell.Op))
				continue
			}

			data = append(data, cell.S)
		}

		if tapeIdx != 0 {
			data = append(data, "|")
		}

	}

	a := New()
	a.FromTape(aipTape)
	return a.Validate(strings.Join(data, ""))
}
