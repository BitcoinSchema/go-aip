package aip

import (
	"bytes"
	"log"
	"strconv"

	"encoding/base64"

	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/bitcoinsv/bsvd/chaincfg"
	"github.com/bitcoinsv/bsvd/chaincfg/chainhash"
	"github.com/bitcoinsv/bsvd/wire"
	"github.com/bitcoinsv/bsvutil"
	"github.com/libsv/libsv/script/address"
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
			index, _ := strconv.ParseUint(tape.Cell[x].S, 10, 64)
			a.Indicies = append(a.Indicies, int(index))
		}
	}
}

// Sign will provide an AIP signature for a given private key and data
// func Sign(xpriv string, data []byte) string {
// 	// pk = bsvec.PrivateKey
// 	// pk.Sign(data)
// 	return ""
// }

// Validate returns true if the given AIP signature is valid for given data
func (a *Aip) Validate(buf bytes.Buffer) bool {

	switch a.Algorithm {
	case BITCOIN_ECDSA:

		// verify signature against data
		addy, err := address.NewFromString(a.Address)
		if err != nil {
			return false
		}

		// Decode base64 signature.
		sig, err := base64.StdEncoding.DecodeString(a.Signature)
		if err != nil {
			log.Println("Failed to decode b64 signature", err)
			return false
		}

		expectedMessageHash := chainhash.DoubleHashB(buf.Bytes())
		pk, wasCompressed, err := bsvec.RecoverCompact(bsvec.S256(), sig, expectedMessageHash)
		if err != nil {
			// Mirror Bitcoin Core behavior, which treats error in
			// RecoverCompact as invalid signature.
			log.Printf("Signature validation failed %s Compressed?: %t\n", err, wasCompressed)
			return false
		}

		// Reconstruct the pubkey hash.
		var serializedPK []byte
		if wasCompressed {
			serializedPK = pk.SerializeCompressed()
		} else {
			serializedPK = pk.SerializeUncompressed()
		}

		address, err := bsvutil.NewAddressPubKey(serializedPK, &chaincfg.MainNetParams)
		if err != nil {
			// Again mirror Bitcoin Core behavior, which treats error in public key
			// reconstruction as invalid signature.
			log.Panicln("Failed to do the thing 2", err)
			return false
		}

		if address.EncodeAddress() == addy.AddressString {
			return true
		}

	}
	return false
}

// ValidateTapes validates the AIP signature for a given []bob.Tape
func ValidateTapes(tapes []bob.Tape) bool {

	var data []string
	var aipTape bob.Tape
	for tapeIdx, tape := range tapes {

		if tape.Cell[0].S == Prefix {
			aipTape = tape
			break
		}

		for _, cell := range tape.Cell {
			data = append(data, cell.S)
		}

		if tapeIdx != 0 {
			data = append(data, "|")
		}

	}

	log.Printf("Validating %s", data)

	a := New()
	a.FromTape(aipTape)

	var idxs []int
	// if there are no indicies, everything is signed
	if len(a.Indicies) == 0 {
		idxs = make([]int, len(data))
		for i := range idxs {
			idxs[i] = i
		}
	}
	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer

	wire.WriteVarInt(&buf, 0, 0)
	wire.WriteVarInt(&buf, 0, 106)

	for idx := 0; idx < len(a.Indicies); idx++ {
		arg := data[idxs[idx]]

		if len(arg) == 0 {
			wire.WriteVarInt(&buf, 0, 0)
			continue
		}
		log.Println("Writing", arg)
		wire.WriteVarString(&buf, 0, arg)
	}

	// Write the pipe
	wire.WriteVarString(&buf, 0, "|")

	return a.Validate(buf)
}
