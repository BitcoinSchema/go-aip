package aip

import (
	"testing"

	"github.com/bitcoinschema/go-bob"
)

// TestSign will test the method Sign()
func TestNewFromTape(t *testing.T) {
	t.Parallel()

	// Parse from string into BOB
	bobValidData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}
	bobInvalidData, err := bob.NewFromString(sampleInvalidBobTx)
	if err != nil {
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

func TestSetData(t *testing.T) {

	const sampleBobTx = `{ "_id": "5f08ddb0f797435fbff1ddf0", "tx": { "h": "744a55a8637aa191aa058630da51803abbeadc2de3d65b4acace1f5f10789c5b" }, "in": [ { "i": 0, "seq": 4294967295, "tape": [ { "cell": [ { "s": "0E\u0002!\u0000�\u0000��>�ȇ�ii}6��\\\t.���eB�\u0015\u0016�Ezd\u0002 !��6�V��L\u0002�-)�Ή=\f\u0003\u001co\u001f5|�\u001dn2��A", "h": "3045022100e000f9e33ebac8878269697d368edc5c092ee48be79ec965429e1516d1457a6402202195d036f456a1cf4c02e2aa2d29b5ce893d0c031c6f1f357ce91d6e32e3e8a541", "b": "MEUCIQDgAPnjPrrIh4JpaX02jtxcCS7ki+eeyWVCnhUW0UV6ZAIgIZXQNvRWoc9MAuKqLSm1zok9DAMcbx81fOkdbjLj6KVB", "i": 0, "ii": 0 }, { "s": "\u0004@��8��x��x���,#\u001d�(��B�A%\f����E��\u0000��T[�=(�\u0017Ϳ\u0001\u0010*\u001cr\\iZ��\u0007Ha�\u0018WM�(", "h": "0440ffb338848f78bfbb78b9b4a82c231dc728ceef42b341250c84ba99cf458bf2af0095df545bef3d28e717cdbf01102a1c725c695adfe40748619518574df228", "b": "BED/sziEj3i/u3i5tKgsIx3HKM7vQrNBJQyEupnPRYvyrwCV31Rb7z0o5xfNvwEQKhxyXGla3+QHSGGVGFdN8ig=", "i": 1, "ii": 1 } ], "i": 0 } ], "e": { "h": "eec0d4693a11b441211c046d25ce49514e72be0ce4437f3805af2d93ad905bc3", "i": 1, "a": "1LC16EQVsqVYGeYTCrjvNf8j28zr4DwBuk" } } ], "out": [ { "i": 0, "tape": [ { "cell": [ { "op": 0, "ops": "OP_0", "i": 0, "ii": 0 }, { "op": 106, "ops": "OP_RETURN", "i": 1, "ii": 1 } ], "i": 0 }, { "cell": [ { "s": "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT", "h": "31424150537561506e66476e53424d33474c56397968785564596534764762644d54", "b": "MUJBUFN1YVBuZkduU0JNM0dMVjl5aHhVZFllNHZHYmRNVA==", "i": 0, "ii": 2 }, { "s": "ATTEST", "h": "415454455354", "b": "QVRURVNU", "i": 1, "ii": 3 }, { "s": "cf39fc55da24dc23eff1809e6e6cf32a0fe6aecc81296543e9ac84b8c501bac5", "h": "63663339666335356461323464633233656666313830396536653663663332613066653661656363383132393635343365396163383462386335303162616335", "b": "Y2YzOWZjNTVkYTI0ZGMyM2VmZjE4MDllNmU2Y2YzMmEwZmU2YWVjYzgxMjk2NTQzZTlhYzg0YjhjNTAxYmFjNQ==", "i": 2, "ii": 4 }, { "s": "0", "h": "30", "b": "MA==", "i": 3, "ii": 5 } ], "i": 1 }, { "cell": [ { "s": "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva", "h": "313550636948473232534e4c514a584d6f5355615756693757537163376843667661", "b": "MTVQY2lIRzIyU05MUUpYTW9TVWFXVmk3V1NxYzdoQ2Z2YQ==", "i": 0, "ii": 7 }, { "s": "BITCOIN_ECDSA", "h": "424954434f494e5f4543445341", "b": "QklUQ09JTl9FQ0RTQQ==", "i": 1, "ii": 8 }, { "s": "134a6TXxzgQ9Az3w8BcvgdZyA5UqRL89da", "h": "31333461365458787a675139417a33773842637667645a7941355571524c38396461", "b": "MTM0YTZUWHh6Z1E5QXozdzhCY3ZnZFp5QTVVcVJMODlkYQ==", "i": 2, "ii": 9 }, { "s": "\u001f�nm�3坨\u001b�{\u001f\t��\u0000��(ӏ��h�D��o\u000b\u0006�$�(\u001a�'i��_�\u0006YA\"\f��ޚ` + "`" + `/U.\u0012�^W�\n", "h": "1fe96e6df733e59da81bc07b1f098ff19fad00b3fe28d38f81e768ed44d7c16f0b06932480281ab42769bdbb5fef065941220ccfcdde9a602f552e12dc5e57d70a", "b": "H+lubfcz5Z2oG8B7HwmP8Z+tALP+KNOPgedo7UTXwW8LBpMkgCgatCdpvbtf7wZZQSIMz83emmAvVS4S3F5X1wo=", "i": 3, "ii": 10 } ], "i": 2 } ], "e": { "v": 0, "i": 0, "a": "false" } }, { "i": 1, "tape": [ { "cell": [ { "op": 118, "ops": "OP_DUP", "i": 0, "ii": 0 }, { "op": 169, "ops": "OP_HASH160", "i": 1, "ii": 1 }, { "s": "�\no;L˺��E\t^��{i\u0011}", "h": "d27f0a6f3b4ccbbacaf945095ed3eeb97b69117d", "b": "0n8KbztMy7rK+UUJXtPuuXtpEX0=", "i": 2, "ii": 2 }, { "op": 136, "ops": "OP_EQUALVERIFY", "i": 3, "ii": 3 }, { "op": 172, "ops": "OP_CHECKSIG", "i": 4, "ii": 4 } ], "i": 0 } ], "e": { "v": 14492205, "i": 1, "a": "1LC16EQVsqVYGeYTCrjvNf8j28zr4DwBuk" } } ], "lock": 0, "timestamp": 1594416560292 }`

	bobData, err := bob.NewFromString(sampleBobTx)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	aip := &Aip{}
	aip.SetDataFromTape(bobData.Out[0].Tape)

	// 0x6a 1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT ATTEST cf39fc55da24dc23eff1809e6e6cf32a0fe6aecc81296543e9ac84b8c501bac5 0 |
	// 0x6a (OP_RETURN)  in ascii is 'j'
	if aip.Data[0] != "j" || aip.Data[1] != "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT" || aip.Data[2] != "ATTEST" && aip.Data[3] != "cf39fc55da24dc23eff1809e6e6cf32a0fe6aecc81296543e9ac84b8c501bac5" || aip.Data[4] != "0" {
		t.Fatalf("failed setting aip data %+v", aip.Data)
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
