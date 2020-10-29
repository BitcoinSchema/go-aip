package aip

import (
	"fmt"
	"testing"

	"github.com/bitcoinschema/go-bob"
)

// TestNewFromTape will test the method NewFromTape()
func TestNewFromTape(t *testing.T) {
	t.Parallel()

	// Parse from string into BOB
	bobValidData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}
	var bobInvalidData *bob.Tx
	if bobInvalidData, err = bob.NewFromString(sampleInvalidBobTx); err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	var (
		// Testing private methods
		tests = []struct {
			inputTapes         []bob.Tape
			inputIndex         int
			expectedSignature  string
			expectedAlgorithm  Algorithm
			expectedComponent  string
			expectedNil        bool
			expectedValidation bool
		}{
			{
				bobValidData.Out[0].Tape,
				2,
				"H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=",
				BitcoinECDSA,
				"134a6TXxzgQ9Az3w8BcvgdZyA5UqRL89da",
				false,
				true,
			},
			{
				bobInvalidData.Out[0].Tape,
				2,
				"H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=",
				BitcoinECDSA,
				"invalid-address",
				false,
				false,
			},
			{
				[]bob.Tape{*new(bob.Tape)},
				0,
				"",
				"",
				"",
				false,
				false,
			},
		}
	)

	// Run tests
	for _, test := range tests {
		if a := NewFromTape(test.inputTapes[test.inputIndex]); a == nil && !test.expectedNil {
			t.Errorf("%s Failed: [%v] inputted and nil was not expected", t.Name(), test.inputTapes[test.inputIndex])
		} else if a != nil && test.expectedNil {
			t.Errorf("%s Failed: [%v] inputted and nil was expected", t.Name(), test.inputTapes[test.inputIndex])
		} else if a != nil && a.Signature != test.expectedSignature {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes[test.inputIndex], test.expectedSignature, a.Signature)
		} else if a != nil && a.Algorithm != test.expectedAlgorithm {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes[test.inputIndex], test.expectedAlgorithm, a.Algorithm)
		} else if a != nil && a.AlgorithmSigningComponent != test.expectedComponent {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes[test.inputIndex], test.expectedComponent, a.AlgorithmSigningComponent)
		} else if a != nil && len(test.inputTapes) > 1 {
			valid := ValidateTapes(test.inputTapes)
			if valid && !test.expectedValidation {
				t.Errorf("%s Failed: [%v] inputted and validation should have failed", t.Name(), test.inputTapes)
			} else if !valid && test.expectedValidation {
				t.Errorf("%s Failed: [%v] inputted and validation should have passed", t.Name(), test.inputTapes)
			}
		}
	}
}

// ExampleNewFromTape example using NewFromTape()
func ExampleNewFromTape() {
	// Get BOB data from a TX
	bobValidData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}

	// Get from tape given the AIP index
	a := NewFromTape(bobValidData.Out[0].Tape[2])

	fmt.Printf("address: %s signature: %s", a.AlgorithmSigningComponent, a.Signature)
	// Output:address: 134a6TXxzgQ9Az3w8BcvgdZyA5UqRL89da signature: H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=
}

// BenchmarkNewFromTape benchmarks the method NewFromTape()
func BenchmarkNewFromTape(b *testing.B) {
	bobValidData, _ := bob.NewFromString(sampleValidBobTx)
	for i := 0; i < b.N; i++ {
		_ = NewFromTape(bobValidData.Out[0].Tape[2])
	}
}

// TestNewFromTapes will test the method NewFromTapes()
func TestNewFromTapes(t *testing.T) {
	t.Parallel()

	// Parse from string into BOB
	bobValidData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}
	var bobInvalidData *bob.Tx
	if bobInvalidData, err = bob.NewFromString(sampleInvalidBobTx); err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	var (
		// Testing private methods
		tests = []struct {
			inputTapes         []bob.Tape
			expectedSignature  string
			expectedAlgorithm  Algorithm
			expectedComponent  string
			expectedData0      string
			expectedData1      string
			expectedData2      string
			expectedNil        bool
			expectedValidation bool
		}{
			{
				bobValidData.Out[0].Tape,
				"H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=",
				BitcoinECDSA,
				"134a6TXxzgQ9Az3w8BcvgdZyA5UqRL89da",
				"j",
				"1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT",
				"ATTEST",
				false,
				true,
			},
			{
				bobInvalidData.Out[0].Tape,
				"H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=",
				BitcoinECDSA,
				"invalid-address",
				"j",
				"1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT",
				"ATTEST",
				false,
				false,
			},
			{
				[]bob.Tape{*new(bob.Tape)},
				"",
				"",
				"",
				"",
				"",
				"",
				true,
				false,
			},
		}
	)

	// Run tests
	for _, test := range tests {
		if a := NewFromTapes(test.inputTapes); a == nil && !test.expectedNil {
			t.Errorf("%s Failed: [%v] inputted and nil was not expected", t.Name(), test.inputTapes)
		} else if a != nil && test.expectedNil {
			t.Errorf("%s Failed: [%v] inputted and nil was expected", t.Name(), test.inputTapes)
		} else if a != nil && a.Signature != test.expectedSignature {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes, test.expectedSignature, a.Signature)
		} else if a != nil && a.Algorithm != test.expectedAlgorithm {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes, test.expectedAlgorithm, a.Algorithm)
		} else if a != nil && a.AlgorithmSigningComponent != test.expectedComponent {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes, test.expectedComponent, a.AlgorithmSigningComponent)
		} else if a != nil && len(a.Data) > 0 && a.Data[0] != test.expectedData0 {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes, test.expectedData0, a.Data[0])
		} else if a != nil && len(a.Data) > 0 && a.Data[1] != test.expectedData1 {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes, test.expectedData1, a.Data[1])
		} else if a != nil && len(a.Data) > 0 && a.Data[2] != test.expectedData2 {
			t.Errorf("%s Failed: [%v] inputted and expected [%s] but got [%s]", t.Name(), test.inputTapes, test.expectedData2, a.Data[2])
		} else if a != nil && len(test.inputTapes) > 1 {
			valid := ValidateTapes(test.inputTapes)
			if valid && !test.expectedValidation {
				t.Errorf("%s Failed: [%v] inputted and validation should have failed", t.Name(), test.inputTapes)
			} else if !valid && test.expectedValidation {
				t.Errorf("%s Failed: [%v] inputted and validation should have passed", t.Name(), test.inputTapes)
			}
		}
	}
}

// ExampleNewFromTapes example using NewFromTapes()
func ExampleNewFromTapes() {
	// Get BOB data from a TX
	bobValidData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}

	// Get from tape given the AIP index
	a := NewFromTapes(bobValidData.Out[0].Tape)

	fmt.Printf("address: %s signature: %s", a.AlgorithmSigningComponent, a.Signature)
	// Output:address: 134a6TXxzgQ9Az3w8BcvgdZyA5UqRL89da signature: H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=
}

// BenchmarkNewFromTapes benchmarks the method NewFromTapes()
func BenchmarkNewFromTapes(b *testing.B) {
	bobValidData, _ := bob.NewFromString(sampleValidBobTx)
	for i := 0; i < b.N; i++ {
		_ = NewFromTapes(bobValidData.Out[0].Tape)
	}
}

/*
// TestSignOpReturnDataUsingBob tests for nil case in SignOpReturnData()
func TestSignOpReturnDataUsingBob(t *testing.T) {

	// Get the private key
	privateKey, err := bitcoin.PrivateKeyFromString(examplePrivateKey)
	if err != nil {
		t.Fatalf("failed to get private key")
	}

	// Create op_return
	opReturn := bitcoin.OpReturnData{[]byte("prefix1"), []byte("example data"), []byte{0x13, 0x37}}

	// Create a transaction
	var tx *transaction.Transaction
	tx, err = bitcoin.CreateTx(nil, nil, []bitcoin.OpReturnData{opReturn}, privateKey)
	if err != nil {
		t.Fatalf("failed to create tx %s", err)
	}

	// Create the bob tx from hex
	var bobTx *bob.Tx
	if bobTx, err = bob.NewFromRawTxString(tx.ToString()); err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	// Sign the output
	var signedOutput *output.Output
	var a *Aip
	signedOutput, a, err = SignOpReturnData(examplePrivateKey, BitcoinECDSA, bobTx.Out[0])
	if err != nil {
		t.Errorf("Failed to sign %s", err)
	}

	if !ValidateTapes(signedOutput.Tape) {
		t.Errorf("Failed to validate bob tapes %+v", signedOutput)
	}
}
*/
