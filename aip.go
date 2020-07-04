package aip

import (
	"strconv"

	"github.com/rohenaz/go-bob"
)

// Prefix is the Bitcom prefix used by AIP
const Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"

// Aip is Author Identity Protocol
type Aip struct {
	Algorithm string
	Address   string
	Signature string
	Indecies  []int `json:"indicies,omitempty" bson:"indicies,omitempty"`
}

// New creates a new Aip struct
func New() *Aip {
	return &Aip{}
}

// FromTape takes a BOB Tape and returns a Aip data structure
func (a *Aip) FromTape(tape bob.Tape) {
	a.Algorithm = tape.Cell[1].S
	a.Address = tape.Cell[2].S
	a.Signature = tape.Cell[3].B // Is this B or S????

	if len(tape.Cell) > 4 {
		a.Indecies = make([]int, len(tape.Cell)-4)

		// Loop over remaining indicies if they exist and append to indicies slice
		for x := 4; x < len(tape.Cell); x++ {
			index, _ := strconv.ParseUint(tape.Cell[x].S, 10, 64)
			a.Indecies = append(a.Indecies, int(index))
		}
	}

}
