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

	bsm "github.com/bitcoin-sv/go-sdk/compat/bsm"
	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoin-sv/go-sdk/script"
)

// Prefix is the Bitcom prefix used by AIP
var Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"

var hexPrefix = hex.EncodeToString([]byte(Prefix))

const pipe = "|"

// const opReturn = string(rune(script.OpRETURN)) // creates: j

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
	Data                      []byte    `json:"data"`                        // Data to be signed or validated
	Indices                   []int     `json:"indices,omitempty"`           // BOB indices
	Signature                 []byte    `json:"signature"`                   // AIP generated signature
}

// Validate validates the AIP entry
func (a *Aip) Validate() (valid bool, err error) {
	if err = bsm.VerifyMessage(a.AlgorithmSigningComponent, a.Signature, a.Data); err != nil {
		return false, fmt.Errorf("signature verification failed: %v", err)
	}
	return true, nil
}

// Sign will provide an AIP signature for a given private key and message using
// the provided algorithm
func Sign(privateKey *ec.PrivateKey, algorithm Algorithm, message []byte) (a *Aip, err error) {
	// Create the base AIP object
	a = &Aip{Algorithm: algorithm, Data: message}

	// Sign using the private key and the message
	var sig []byte
	if sig, err = bsm.SignMessage(privateKey, message); err != nil {
		return nil, err
	}

	a.Signature = sig

	// Store address vs pubkey
	switch algorithm {
	case BitcoinECDSA, BitcoinSignedMessage:
		// Signing component = bitcoin address
		// Get the address of the private key
		if add, err := script.NewAddressFromPublicKey(privateKey.PubKey(), true); err != nil {
			return nil, err
		} else {
			a.AlgorithmSigningComponent = add.AddressString
		}
	case Paymail:
		// Signing component = paymail identity key
		a.AlgorithmSigningComponent = hex.EncodeToString(privateKey.PubKey().Compressed())
	}

	return
}

// JS implementation for reference

// /**
//  * Construct an AIP buffer from the op return data
//  * @param opReturn
//  * @returns {Buffer}
//  */
//  getAIPMessageBuffer(opReturn: string[]): Buffer {
// 	const buffers = [];
// 	if (opReturn[0].replace("0x", "") !== "6a") {
// 		// include OP_RETURN in constructing the signature buffer
// 		buffers.push(Buffer.from("6a", "hex"));
// 	}
// 	for (const op of opReturn) {
// 		buffers.push(Buffer.from(op.replace("0x", ""), "hex"));
// 	}
// 	// add a trailing "|" - this is the AIP way
// 	buffers.push(Buffer.from("|"));

// 	return Buffer.concat([...buffers] as unknown as Uint8Array[]);
// }

// /**
//  * Sign an op_return hex array with AIP
//  * @param opReturn {array}
//  * @param signingPath {string}
//  * @param outputType {string}
//  * @return {[]}
//  */
//  signOpReturnWithAIP(
// 	opReturn: string[],
// 	signingPath = "",
// 	outputType: BufferEncoding = "hex",
// ): string[] {
// 	const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
// 	const { address, signature } = this.signMessage(
// 		aipMessageBuffer,
// 		signingPath,
// 	);

// 	return opReturn.concat([
// 		Buffer.from("|").toString(outputType),
// 		Buffer.from(AIP_BITCOM_ADDRESS).toString(outputType),
// 		Buffer.from("BITCOIN_ECDSA").toString(outputType),
// 		Buffer.from(address).toString(outputType),
// 		Buffer.from(signature, "base64").toString(outputType),
// 	]);
// }

// SignOpReturnData will append the given data and return a bt.Output
func SignOpReturnData(privateKey *ec.PrivateKey, algorithm Algorithm,
	data [][]byte) (outData [][]byte, a *Aip, err error) {

	// Ensure first byte is OP_RETURN if not already
	if len(data) == 0 || len(data[0]) == 0 || data[0][0] != byte(script.OpRETURN) {
		data = append([][]byte{{byte(script.OpRETURN)}}, data...)
	}

	// add trailing pipe
	data = append(data, []byte(pipe))

	// Create message buffer by joining all data
	messageBuffer := bytes.Join(data, []byte{})

	// Sign with AIP
	if a, err = Sign(privateKey, algorithm, messageBuffer); err != nil {
		return
	}

	// Add AIP signature
	outData = append(
		data,
		[]byte(Prefix),
		[]byte(a.Algorithm),
		[]byte(a.AlgorithmSigningComponent),
		a.Signature,
	)

	return
}
