package aip

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoin-sv/go-sdk/script"
	"github.com/bitcoin-sv/go-sdk/transaction"
	"github.com/bitcoinschema/go-bob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const examplePrivateKeyHex = "54035dd4c7dda99ac473905a3d82f7864322b49bab1ff441cc457183b9bd8abd"

var privBytes, _ = hex.DecodeString(examplePrivateKeyHex)
var examplePrivateKey, _ = ec.PrivateKeyFromBytes(privBytes)

var exampleMessage = []byte("test message")

// TestSign will test the method Sign()
func TestSign(t *testing.T) {
	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputPrivateKey   string
			inputAlgorithm    Algorithm
			inputMessage      []byte
			expectedSignature string
			expectedNil       bool
			expectedError     bool
		}{
			{
				"0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd",
				BitcoinECDSA,
				exampleMessage,
				"IFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8=",
				false,
				false,
			},
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				Paymail,
				exampleMessage,
				"IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
				false,
				false,
			},
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				BitcoinECDSA,
				[]byte(""),
				"H3/iGpfMJCLPiM9w9p1a35ZQ9YoVrVRXpii6TGRHc4RHWSEhGVaQ0buAnATiecttBWJrNKfE2zXQroxcIHpN3ag=",
				false,
				false,
			},
			{
				"e83385af76b2b1997326b567461fb73dd9c27eab9e1e86d26779f4650c5f2b75",
				BitcoinECDSA,
				exampleMessage,
				"IGtOmD/drk1w39g5U5xccky32Fj8eR71Ld/7lzEw+Sr7CU5rMJ1yeDte4eakr0YQMp9ZI57YYKS7cqjA5l6YpGs=",
				false,
				false,
			},
			{
				"e83385af76b2b1997326b567461fb73dd9c27eab9e1e86d26779f4650c5f2b75",
				BitcoinSignedMessage,
				exampleMessage,
				"IGtOmD/drk1w39g5U5xccky32Fj8eR71Ld/7lzEw+Sr7CU5rMJ1yeDte4eakr0YQMp9ZI57YYKS7cqjA5l6YpGs=",
				false,
				false,
			},
			{
				"e83385af76b2b1997326b567461fb73dd9c27eab9e1e86d26779f4650c5f2b75",
				Paymail,
				exampleMessage,
				"IGtOmD/drk1w39g5U5xccky32Fj8eR71Ld/7lzEw+Sr7CU5rMJ1yeDte4eakr0YQMp9ZI57YYKS7cqjA5l6YpGs=",
				false,
				false,
			},
			{
				"73646673676572676164666764666761646667616466",
				BitcoinECDSA,
				exampleMessage,
				"IMlJxr2jImPKkuh5QQPmyRkNCiwsYC1uKOicBf1j69AZRqUmA3bVGylmNERlXMXtuweVzV3E40OtVckCxDfVhY8=",
				false,
				false,
			},
			{
				"73646673676572676164666764666761646667616466",
				BitcoinSignedMessage,
				exampleMessage,
				"IMlJxr2jImPKkuh5QQPmyRkNCiwsYC1uKOicBf1j69AZRqUmA3bVGylmNERlXMXtuweVzV3E40OtVckCxDfVhY8=",
				false,
				false,
			},
			{
				"73646673676572676164666764666761646667616466",
				Paymail,
				exampleMessage,
				"IMlJxr2jImPKkuh5QQPmyRkNCiwsYC1uKOicBf1j69AZRqUmA3bVGylmNERlXMXtuweVzV3E40OtVckCxDfVhY8=",
				false,
				false,
			},
		}
	)

	// Run tests
	for testNo, test := range tests {
		if privBytes, err := hex.DecodeString(test.inputPrivateKey); err != nil {
			t.Errorf("%d %s Failed: [%s] inputted and error not expected but got: %s", testNo, t.Name(), test.inputPrivateKey, err.Error())
		} else {
			priv, _ := ec.PrivateKeyFromBytes(privBytes)
			if a, err := Sign(priv, test.inputAlgorithm, test.inputMessage); err != nil && !test.expectedError {
				t.Errorf("%d %s Failed: [%s] [%s] [%s] inputted and error not expected but got: %s", testNo, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage, err.Error())
			} else if err == nil && test.expectedError {
				t.Errorf("%d %s Failed: [%s] [%s] [%s] inputted and error was expected", testNo, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
			} else if a == nil && !test.expectedNil {
				t.Errorf("%d %s Failed: [%s] [%s] [%s] inputted and nil was not expected (aip)", testNo, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
			} else if a != nil && test.expectedNil {
				t.Errorf("%d %s Failed: [%s] [%s] [%s] inputted and nil was expected (aip)", testNo, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
			} else if a != nil {
				sigStr := base64.StdEncoding.EncodeToString(a.Signature)
				if sigStr != test.expectedSignature {
					t.Errorf("%d %s Failed: [%s] [%s] [%s] inputted and expected [%s] but got [%s]", testNo, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage, test.expectedSignature, sigStr)
				}
			} else if a != nil && err == nil {
				// Test validation - THIS WILL NOT WORK BECAUSE DATA IS NOT SET
				if _, err = a.Validate(); err != nil {
					t.Errorf("%d %s Failed: [%s] [%s] [%s] inputted and validation failed: %s", testNo, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage, err.Error())
				}
			}
		}
	}
}

// ExampleSign example using Sign()
func ExampleSign() {
	a, err := Sign(examplePrivateKey, BitcoinECDSA, exampleMessage)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("address: %s signature: %s", a.AlgorithmSigningComponent, base64.StdEncoding.EncodeToString(a.Signature))
	// Output:address: 1DfGxKmgL3ETwUdNnXLBueEvNpjcDGcKgK signature: H0aEV4aeqI/2mH5DHGoEFPQWBkRS0bUMR6Q9/yVBGR7xRDH8XNY4u3Wr+mCKX1eXmjaSOIs80ZSIUtFCqQhAhCU=
}

// ExampleSign_paymail example using Sign()
func ExampleSign_paymail() {
	a, err := Sign(examplePrivateKey, Paymail, exampleMessage)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("address: %s signature: %s", a.AlgorithmSigningComponent, base64.StdEncoding.EncodeToString(a.Signature))
	// Output:address: 031b8c93100d35bd448f4646cc4678f278351b439b52b303ea31ec9edb5475e73f signature: H0aEV4aeqI/2mH5DHGoEFPQWBkRS0bUMR6Q9/yVBGR7xRDH8XNY4u3Wr+mCKX1eXmjaSOIs80ZSIUtFCqQhAhCU=
}

// BenchmarkSign benchmarks the method Sign()
func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Sign(examplePrivateKey, BitcoinECDSA, exampleMessage)
	}
}

// BenchmarkSign_paymail benchmarks the method Sign()
func BenchmarkSign_paymail(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Sign(examplePrivateKey, Paymail, exampleMessage)
	}
}

func mustBase64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestAip_Validate will test the method Validate()
func TestAip_Validate(t *testing.T) {
	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputAip      *Aip
			expectedValid bool
		}{
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "12SsqqYk43kggMBpSvWHwJwR31NsgMePKS",
				Data:                      append([]byte{byte(script.OpRETURN)}, []byte(exampleMessage)...),
				Signature:                 mustBase64Decode("HOpsJCCkmIOBs8HJIn3Od7aa/SLycQSsZ5QuLvaSlKobYvxpkE5Lcb4fAFLXp1h5pJTEHtm/SZICybovE8AcpiM="),
			}, true},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "12SsqqYk43kggMBpSvWHwJwR31NsgMePKS",
				Data:                      []byte("test message"),
				Signature:                 mustBase64Decode("HOpsJCCkmIOBs8HJIn3Od7aa/SLycQSsZ5QuLvaSlKobYvxpkE5Lcb4fAFLXp1h5pJTEHtm/SZICybovE8AcpiM="),
			}, false},
			{&Aip{}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "1PASGrpoPtNXYVsWtRn3rR3JoesuZmK1Z5",
				Data:                      append([]byte{byte(script.OpRETURN)}, []byte(exampleMessage)...),
				Signature:                 []byte("invalid-sig"),
			}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "",
				Data:                      []byte(exampleMessage),
				Signature:                 mustBase64Decode("IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic="),
			}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "invalid-address",
				Data:                      []byte(exampleMessage),
				Signature:                 mustBase64Decode("IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic="),
			}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "invalid-address",
				Data:                      nil,
				Signature:                 mustBase64Decode("IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic="),
			}, false},
		}
	)

	// Run tests
	for _, test := range tests {
		if valid, err := test.inputAip.Validate(); valid && !test.expectedValid {
			t.Errorf("%s Failed: [%v] inputted and was valid but should NOT be valid", t.Name(), test.inputAip)
		} else if !valid && test.expectedValid && err != nil {
			t.Errorf("%s Failed: [%v] inputted and NOT valid but should be valid, error: %s", t.Name(), test.inputAip, err.Error())
		}
	}
}

// TestAip_ValidatePanic tests for nil case in Validate()
func TestAip_ValidatePanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("the code did not panic")
		}
	}()

	a := &Aip{}
	if a.Algorithm != "" {
		t.Fatalf("algorithm should be empty")
	}
	a = nil
	if valid, _ := a.Validate(); valid {
		t.Fatalf("should be NOT valid")
	}

}

// ExampleAip_Validate example using Validate()
func ExampleAip_Validate() {
	a, err := Sign(examplePrivateKey, BitcoinECDSA, exampleMessage)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}

	if valid, err := a.Validate(); valid {
		fmt.Printf("valid signature: %s", base64.StdEncoding.EncodeToString(a.Signature))
	} else if err != nil {
		fmt.Printf("signature validation failed: %s", err.Error())
	}
	// Output:valid signature: H0aEV4aeqI/2mH5DHGoEFPQWBkRS0bUMR6Q9/yVBGR7xRDH8XNY4u3Wr+mCKX1eXmjaSOIs80ZSIUtFCqQhAhCU=
}

// BenchmarkAip_Validate benchmarks the method Validate()
func BenchmarkAip_Validate(b *testing.B) {
	a, _ := Sign(examplePrivateKey, BitcoinECDSA, exampleMessage)
	for i := 0; i < b.N; i++ {
		_, _ = a.Validate()
	}
}

// TestSignOpReturnData tests for nil case in SignOpReturnData(), takes data including the OP_RETURN byte
func TestSignOpReturnData(t *testing.T) {
	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputPrivateKey   string
			inputAlgorithm    Algorithm
			inputData         [][]byte
			expectedSignature string
			expectedOutput    string
			expectedAipNil    bool
			expectedOutNil    bool
			expectedError     bool
		}{
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				BitcoinECDSA,
				[][]byte{[]byte(exampleMessage)},
				"HzcMCEFxGJ1obmpgRLPUHrfrkSvqFWG2dTm8aYG8LFzbGKyJku1Z+Flv62CfAkLRjxjNN7aqbrFE8422Qs6i1Ic=",
				"006a0c74657374206d657373616765227c313550636948473232534e4c514a584d6f53556157566937575371633768436676610d424954434f494e5f45434453412131553151733836707847724e55796a37673752346d386b3879346b6d78766f756f4c5847774a696635464b72367250704b5967685a374637526d6177303071356e576f364e694a4f756a652b3657424f4d367164384d6c566e625772326d7272412b61614461744878617652384a54636b7053667831524a316f3d",
				false,
				false,
				false,
			},
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				Paymail,
				[][]byte{[]byte(exampleMessage)},
				"HzcMCEFxGJ1obmpgRLPUHrfrkSvqFWG2dTm8aYG8LFzbGKyJku1Z+Flv62CfAkLRjxjNN7aqbrFE8422Qs6i1Ic=",
				"006a0c74657374206d657373616765227c313550636948473232534e4c514a584d6f5355615756693757537163376843667661077061796d61696c4c82303439393332396133303066333338653136343731373538313961666334356435353661366235666533633834313236663634633666353035616537616139333930343261346361633931326335396261663738323534346131626234356632333432613536303334343435656133313233643733393536663731306334333962654c5847774a696635464b72367250704b5967685a374637526d6177303071356e576f364e694a4f756a652b3657424f4d367164384d6c566e625772326d7272412b61614461744878617652384a54636b7053667831524a316f3d",
				false,
				false,
				false,
			},
		}
	)

	// Run tests
	for idx, test := range tests {
		if privBytes, err := hex.DecodeString(test.inputPrivateKey); err != nil {
			t.Errorf("%d %s Failed: [%s] inputted and error not expected but got: %s", idx, t.Name(), test.inputPrivateKey, err.Error())
		} else {
			priv, _ := ec.PrivateKeyFromBytes(privBytes)
			if outData, a, err := SignOpReturnData(priv, test.inputAlgorithm, test.inputData); err != nil && !test.expectedError {
				t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and error not expected but got: %s", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData, err.Error())
			} else if err == nil && test.expectedError {
				t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and error was expected", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
			} else if a == nil && !test.expectedAipNil {
				t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and nil was not expected (aip)", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
			} else if a != nil && test.expectedAipNil {
				t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and nil was expected (aip)", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
			} else if outData == nil && !test.expectedOutNil {
				t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and nil was not expected (out)", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
			} else if outData != nil && test.expectedOutNil {
				t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and nil was expected (out)", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
			} else if a != nil {
				sigStr := base64.StdEncoding.EncodeToString(a.Signature)
				if sigStr != test.expectedSignature {
					t.Errorf("%d %s Failed: [%s] [%s] [%v] inputted and expected signature [%s] but got [%s]", idx, t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData, test.expectedSignature, sigStr)
				}
			}
		}
	}
}

// ExampleSignOpReturnData example using SignOpReturnData()
func ExampleSignOpReturnData() {
	outData, a, err := SignOpReturnData(examplePrivateKey, BitcoinECDSA, [][]byte{{byte(script.OpRETURN)}, []byte("some op_return data")})
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("signature: %s outData: %x", base64.StdEncoding.EncodeToString(a.Signature), outData)
	// Output:signature: Hw8haDUGsGtewecoomWc5aw8xzzKYPkZz5dq56G0jCdIbw5YnoRKYjw9xFZdANttJqv5zkjN78cs/zOfohMLuJI= outData: [6a 736f6d65206f705f72657475726e2064617461 7c 313550636948473232534e4c514a584d6f5355615756693757537163376843667661 424954434f494e5f4543445341 31446647784b6d674c3345547755644e6e584c42756545764e706a634447634b674b 1f0f21683506b06b5ec1e728a2659ce5ac3cc73cca60f919cf976ae7a1b48c27486f0e589e844a623c3dc4565d00db6d26abf9ce48cdefc72cff339fa2130bb892]
}

// BenchmarkSignOpReturnData benchmarks the method SignOpReturnData()
func BenchmarkSignOpReturnData(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = SignOpReturnData(examplePrivateKey, BitcoinECDSA, [][]byte{[]byte("some op_return data")})
	}
}

func TestBoom2FromTx(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(`0100000001960b7798ec6d83359c0caeb9a9c46aad7e12d98864b3933617ac6ae5da778aa3020000006b4830450221008f7c4e00ae9086f134fd65eb8d60ba309c3b09a11f0c653710ae4e3522ac6593022007ec80fa044d50b0ccef680cfd2102a04ed76e9065ff8d8645ae0710b5f12aca4121036eed1297fcbbc0800e11c5df3ea54aec0fe7024522e0d31d10197754f023ea16ffffffff030000000000000000fdff00006a0a6f6e636861696e2e737606706f772e636f0375726c4cae7b2275726c223a2268747470733a2f2f726f62657274666b656e6e6564796a722e737562737461636b2e636f6d2f702f72666b2d6a722d6e65772d68616d7073686972652d696e737469747574652d706f6c69746963732d737065656368222c225f617070223a22706f772e636f222c225f74797065223a2275726c222c225f6e6f6e6365223a2265333838346438312d613738322d346531372d616230352d333030333362373261366230227d017c22313550636948473232534e4c514a584d6f53556157566937575371633768436676610d424954434f494e5f454344534100000105a0860100000000001976a9146821cc34e3c6de0d2c34965c99167092718bd5ab88ac8c024f0c000000001976a91471b62aeab78c77e3b36a7e260210f0fd6098411d88ac00000000`)
	if err != nil {
		t.Fatalf("error occurred: %s", err)
	}

	bob, _ := bob.NewFromTx(tx)
	aipTx := NewFromTape(bob.Out[0].Tape[0])
	if err != nil {
		t.Fatalf("error occurred: %s", err)
	} else if aipTx == nil {
		t.Fatalf("Bmaptx Failed %v", aipTx)
	}
}

// TestFromRawTxHexFile tests parsing and validating a raw transaction hex string from a file
func TestFromRawTxHexFile(t *testing.T) {
	assert := assert.New(t)

	// Load the test data
	rawTx, err := os.ReadFile("test_data/d4738845dc0d045a35c72fcacaa2d4dee19a3be1cbfcb0d333ce2aec6f0de311.hex")
	assert.NoError(err)

	var txBytes = make([]byte, hex.DecodedLen(len(rawTx)))

	_, err = hex.Decode(txBytes, rawTx)
	assert.NoError(err)

	// Parse the transaction
	tx, err := transaction.NewTransactionFromBytes(txBytes)
	assert.NoError(err)

	// Convert to BOB format
	bobTx, err := bob.NewFromTx(tx)
	assert.NoError(err)

	// Get the AIP entries
	entries := NewFromAllTapes(bobTx.Out[0].Tape)
	assert.Equal(2, len(entries))
	t.Logf("Found %d AIP entries", len(entries))

	// Check the first AIP entry
	assert.Equal(BitcoinECDSA, entries[0].Algorithm)
	assert.Equal("1EXhSbGFiEAZCE5eeBvUxT6cBVHhrpPWXz", entries[0].AlgorithmSigningComponent)
	t.Logf("AIP entry 0 - Algorithm: %s, SigningComponent: %s", entries[0].Algorithm, entries[0].AlgorithmSigningComponent)
	t.Logf("AIP entry 0 - Data: %v", entries[0].Data)
	t.Logf("AIP entry 0 - Raw Data String: %s", string(entries[0].Data))
	t.Logf("AIP entry 0 - Signature: %s", entries[0].Signature)

	// Validate the first AIP entry
	valid, err := entries[0].Validate()
	if err != nil {
		t.Logf("AIP entry 0 - Validation Error: %s", err)
	}
	t.Logf("AIP entry 0 - Valid: %t", valid)
	assert.True(valid)

	// Check the second AIP entry
	assert.Equal(BitcoinECDSA, entries[1].Algorithm)
	assert.Equal("19nknLhRnGKRR3hobeFuuqmHUMiNTKZHsR", entries[1].AlgorithmSigningComponent)
	t.Logf("AIP entry 1 - Algorithm: %s, SigningComponent: %s", entries[1].Algorithm, entries[1].AlgorithmSigningComponent)
	t.Logf("AIP entry 1 - Data: %v", entries[1].Data)
	t.Logf("AIP entry 1 - Raw Data String: %s", string(entries[1].Data))
	t.Logf("AIP entry 1 - Signature: %s", entries[1].Signature)

	// Validate the second AIP entry
	valid, err = entries[1].Validate()
	if err != nil {
		t.Logf("AIP entry 1 - Validation Error: %s", err)
	}
	t.Logf("AIP entry 1 - Valid: %t", valid)
	assert.True(valid)

	// Check that the addresses match what we expect
	assert.Equal("1EXhSbGFiEAZCE5eeBvUxT6cBVHhrpPWXz", entries[0].AlgorithmSigningComponent)
	assert.Equal("19nknLhRnGKRR3hobeFuuqmHUMiNTKZHsR", entries[1].AlgorithmSigningComponent)
}

func TestFromRawTx(t *testing.T) {
	// Load the test data
	rawTx, err := os.ReadFile("test_data/d7a5395fb025d0f12cfa6b764f933c97390604c7772405593232ed9b95307595.hex")
	require.NoError(t, err)

	tx, err := bob.NewFromRawTxString(strings.TrimSpace(string(rawTx)))
	require.NoError(t, err)

	a := NewFromTapes(tx.Out[0].Tape)
	require.NotNil(t, a)

	t.Logf("Algorithm: %s", a.Algorithm)
	t.Logf("SigningComponent: %s", a.AlgorithmSigningComponent)
	t.Logf("Signature: %s", base64.StdEncoding.EncodeToString(a.Signature))
	t.Logf("Data: %s", a.Data)

	require.NoError(t, err)
	require.Equal(t, BitcoinECDSA, a.Algorithm)
	require.Equal(t, "d7a5395fb025d0f12cfa6b764f933c97390604c7772405593232ed9b95307595", tx.Tx.Tx.H)
	require.Equal(t, "17n2mKd4kbgUBUeju9irCmNFLNHLhbiFih", a.AlgorithmSigningComponent)
	require.Equal(t, "IEag/sUJ2ID4EAsxRLLxLTUIqCg6OLP91Py/dhCw7yupBtSZwtQ5CFYokX4t5ZG25nfJ/8xjwU5nYybeO+68ydY=", base64.StdEncoding.EncodeToString(a.Signature))

	// validate
	valid, err := a.Validate()
	// Twetch AIP is invalid!
	require.Error(t, err)
	require.False(t, valid)
}
