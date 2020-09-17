package aip

import (
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
	Signature string
	Indicies  []int `json:"indicies,omitempty" bson:"indicies,omitempty"`
}

// New creates a new Aip struct
func New() *Aip {
	return &Aip{}
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
				data = append(data, string(cell.Op))
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
