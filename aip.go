package aip

import (
	"encoding/hex"
	"log"
	"strconv"
	"strings"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/rohenaz/go-bob"
	"github.com/tonicpow/go-paymail"
)

// Prefix is the Bitcom prefix used by AIP
const Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"

// Algorithm is an enum for the different possible signature algorithms
type Algorithm string

// Algorithms
const (
	PAYMAIL       Algorithm = "paymail"
	BITCOIN_ECDSA Algorithm = "BITCOIN_ECDSA"
)

// Aip is Author Identity Protocol
type Aip struct {
	Algorithm Algorithm
	Address   string
	Data      []string
	Signature string
	Indicies  []int `json:"indicies,omitempty" bson:"indicies,omitempty"`
}

// New creates a new Aip struct
func New() *Aip {
	return &Aip{}
}

// SetData sets the data the AIP signature is signing
func (a *Aip) SetData(tapes []bob.Tape) {

	var data = []string{"j"}

	if len(a.Indicies) == 0 {
		// walk over all output values and concatenate them until we hit the aip prefix, then add in the seperator

		for _, tape := range tapes {
			for _, cell := range tape.Cell {
				if cell.S != Prefix {
					// Skip the OPS
					if cell.Ops != "" {
						continue
					}
					data = append(data, cell.S)
				} else {
					data = append(data, "|")
					a.Data = data
					return
				}
			}
		}

	} else {
		var indexCt = 0

		for _, tape := range tapes {
			for _, cell := range tape.Cell {
				if cell.S != Prefix && contains(a.Indicies, indexCt) {
					data = append(data, cell.S)
				} else {
					data = append(data, "|")
				}
				indexCt = indexCt + 1
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

// FromTape takes a BOB Tape and returns a Aip data structure. Using from tape alone will prevent validation (data is needed via SetData to enable)
func (a *Aip) FromTape(tape bob.Tape) {

	// log.Println("Cell len is", len(tape.Cell))
	if len(tape.Cell) < 4 || tape.Cell[0].S != Prefix {
		return
	}

	a.Algorithm = Algorithm(tape.Cell[1].S)
	a.Address = tape.Cell[2].S
	a.Signature = tape.Cell[3].B // Is this B or S????

	if len(tape.Cell) > 4 {

		a.Indicies = make([]int, len(tape.Cell)-4)

		// TODO: Consider OP_RETURN is included in sig when processing a tx using indices
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

// SignOpReturnData appends a signature to a Bob Tx by adding a protocol separator pushdata followed by AIP information
func (a *Aip) SignOpReturnData(output bob.Output, algorithm Algorithm, addressString string, privKey string) bob.Output {

	var dataToSign []string
	for _, tape := range output.Tape {
		for _, cell := range tape.Cell {
			if len(cell.S) > 0 {
				dataToSign = append(dataToSign, cell.S)
			} else {
				// TODO: Review this case. Should we assume the b64 is signed? Should protocol doc for AIP mention this?
				dataToSign = append(dataToSign, cell.B)
			}
		}
	}
	// get data to sign from bob tx
	// TODO: We need a live paymail set up with matching key in the test... somehow...
	a.Sign(privKey, strings.Join(dataToSign, ""), algorithm, addressString)
	a.Data = dataToSign

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

	return output
}

// Sign will provide an AIP signature for a given private key and data. Just set paymail = "" when using BITCOIN_ECDSA signature
func (a *Aip) Sign(privKey string, message string, algorithm Algorithm, paymail string) (ok bool) {

	// pk = bsvec.PrivateKey
	// pk.Sign(data)
	switch algorithm {
	case BITCOIN_ECDSA:
		if &paymail != nil {
			// Error if paymail is provided, but algorithm is BITCOIN_ECDSA
			return
		}
		sig, err := bitcoin.SignMessage(privKey, message)
		if err != nil {
			return
		}
		a.Signature = sig
		address, err := bitcoin.GetAddressFromPrivateKey(privKey)
		if err != nil {
			return
		}
		a.Address = address
	case PAYMAIL:
		sig, err := bitcoin.SignMessage(privKey, message)
		if err != nil {
			return
		}
		a.Signature = sig
		a.Address = paymail
	}
	a.Algorithm = algorithm
	return true
}

func getPki(paymailString string) (*paymail.PKI, error) {
	// Load the client
	client, err := paymail.NewClient(nil, nil)
	if err != nil {
		log.Fatalf("error loading client: %s", err.Error())
	}

	paymailParts := strings.Split(paymailString, "@")

	// Get the capabilities
	// This is required first to get the corresponding PKI endpoint url
	var capabilities *paymail.Capabilities
	if capabilities, err = client.GetCapabilities(paymailParts[1], paymail.DefaultPort); err != nil {
		log.Fatal("error getting capabilities: " + err.Error())
	}
	log.Println("found capabilities: ", len(capabilities.Capabilities))

	// Extract the PKI URL from the capabilities response
	pkiURL := capabilities.GetString(paymail.BRFCPki, paymail.BRFCPkiAlternate)

	// Get the actual PKI
	var pki *paymail.PKI
	if pki, err = client.GetPKI(pkiURL, paymailParts[0], paymailParts[1]); err != nil {
		log.Fatal("error getting pki: " + err.Error())
	}
	log.Println("found pki:", pki)
	return pki, nil
}

// Validate returns true if the given AIP signature is valid for given data
func (a *Aip) Validate() (ok bool) {
	if len(a.Data) == 0 {
		return
	}
	switch a.Algorithm {
	case BITCOIN_ECDSA:
		// Validate verifies a Bitcoin signed message signature
		err := bitcoin.VerifyMessage(a.Address, a.Signature, strings.Join(a.Data, ""))
		return err == nil
	case PAYMAIL:
		paymailAddress := a.Address

		pki, err := getPki(paymailAddress)
		if err != nil {
			return false
		}
		// Get the public address for this paymail from pki

		addr, err := bitcoin.GetAddressFromPubKeyString(pki.PubKey)
		if err != nil {
			return false
		}

		// You get the address associated with the pki instead of the current address
		err = bitcoin.VerifyMessage(addr.String(), a.Signature, strings.Join(a.Data, ""))
		return err == nil
	}
	return
}

// ValidateTapes validates the AIP signature for a given []bob.Tape
func ValidateTapes(tapes []bob.Tape) bool {

	var aipTape bob.Tape
	for _, tape := range tapes {
		// Once we hit AIP Prefix, stop
		if tape.Cell[0].S == Prefix {
			aipTape = tape
			break
		}
	}

	a := New()
	a.FromTape(aipTape)
	a.SetData(tapes)
	return a.Validate()
}
