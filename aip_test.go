package aip

import (
	"fmt"
	"testing"
)

const examplePrivateKey = "54035dd4c7dda99ac473905a3d82f7864322b49bab1ff441cc457183b9bd8abd"
const exampleMessage = "test message"

// TestSign will test the method Sign()
func TestSign(t *testing.T) {
	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputPrivateKey   string
			inputAlgorithm    Algorithm
			inputMessage      string
			expectedSignature string
			expectedNil       bool
			expectedError     bool
		}{
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				BitcoinECDSA,
				exampleMessage,
				"IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
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
				"",
				BitcoinECDSA,
				exampleMessage,
				"",
				false,
				true,
			},
			{
				"",
				Paymail,
				exampleMessage,
				"",
				false,
				true,
			},
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				BitcoinECDSA,
				"",
				"H3/iGpfMJCLPiM9w9p1a35ZQ9YoVrVRXpii6TGRHc4RHWSEhGVaQ0buAnATiecttBWJrNKfE2zXQroxcIHpN3ag=",
				false,
				false,
			},
			{
				"00000",
				BitcoinECDSA,
				"",
				"",
				false,
				true,
			},
			{
				"00000",
				Paymail,
				"",
				"",
				false,
				true,
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
	for _, test := range tests {
		if a, err := Sign(test.inputPrivateKey, test.inputAlgorithm, test.inputMessage); err != nil && !test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%s] inputted and error not expected but got: %s", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage, err.Error())
		} else if err == nil && test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%s] inputted and error was expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
		} else if a == nil && !test.expectedNil {
			t.Errorf("%s Failed: [%s] [%s] [%s] inputted and nil was not expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
		} else if a != nil && test.expectedNil {
			t.Errorf("%s Failed: [%s] [%s] [%s] inputted and nil was expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
		} else if a != nil && a.Signature != test.expectedSignature {
			t.Errorf("%s Failed: [%s] [%s] [%s] inputted and expected [%s] but got [%s]", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage, test.expectedSignature, a.Signature)
		} else if a != nil && err == nil {
			// Test validation
			if !a.Validate() {
				t.Errorf("%s Failed: [%s] [%s] [%s] inputted and validation failed", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputMessage)
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
	fmt.Printf("address: %s signature: %s", a.AlgorithmSigningComponent, a.Signature)
	// Output:address: 1DfGxKmgL3ETwUdNnXLBueEvNpjcDGcKgK signature: H0aEV4aeqI/2mH5DHGoEFPQWBkRS0bUMR6Q9/yVBGR7xRDH8XNY4u3Wr+mCKX1eXmjaSOIs80ZSIUtFCqQhAhCU=
}

// ExampleSign_paymail example using Sign()
func ExampleSign_paymail() {
	a, err := Sign(examplePrivateKey, Paymail, exampleMessage)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("pubkey: %s signature: %s", a.AlgorithmSigningComponent, a.Signature)
	// Output:pubkey: 031b8c93100d35bd448f4646cc4678f278351b439b52b303ea31ec9edb5475e73f signature: H0aEV4aeqI/2mH5DHGoEFPQWBkRS0bUMR6Q9/yVBGR7xRDH8XNY4u3Wr+mCKX1eXmjaSOIs80ZSIUtFCqQhAhCU=
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

// TestAip_Validate will test the method Validate()
func TestAip_Validate(t *testing.T) {

	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputAip      *Aip
			expectedValid bool
		}{
			{&Aip{}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "1PASGrpoPtNXYVsWtRn3rR3JoesuZmK1Z5",
				Data:                      []string{exampleMessage},
				Signature:                 "IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
			}, true},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "1PASGrpoPtNXYVsWtRn3rR3JoesuZmK1Z5",
				Data:                      []string{exampleMessage},
				Signature:                 "invalid-sig",
			}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "",
				Data:                      []string{exampleMessage},
				Signature:                 "IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
			}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "invalid-address",
				Data:                      []string{exampleMessage},
				Signature:                 "IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
			}, false},
			{&Aip{
				Algorithm:                 BitcoinECDSA,
				AlgorithmSigningComponent: "invalid-address",
				Data:                      nil,
				Signature:                 "IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
			}, false},
			{&Aip{
				Algorithm:                 Paymail,
				AlgorithmSigningComponent: "0233fbdf657a4d0a7a2587fccc4c6ad9a952cfe79d517001a1cc462996c5db13bc",
				Data:                      []string{exampleMessage},
				Signature:                 "IMlJxr2jImPKkuh5QQPmyRkNCiwsYC1uKOicBf1j69AZRqUmA3bVGylmNERlXMXtuweVzV3E40OtVckCxDfVhY8=",
			}, true},
			{&Aip{
				Algorithm:                 Paymail,
				AlgorithmSigningComponent: "0",
				Data:                      []string{exampleMessage},
				Signature:                 "IMlJxr2jImPKkuh5QQPmyRkNCiwsYC1uKOicBf1j69AZRqUmA3bVGylmNERlXMXtuweVzV3E40OtVckCxDfVhY8=",
			}, false},
		}
	)

	// Run tests
	for _, test := range tests {
		if valid := test.inputAip.Validate(); valid && !test.expectedValid {
			t.Errorf("%s Failed: [%v] inputted and was valid but should NOT be valid", t.Name(), test.inputAip)
		} else if !valid && test.expectedValid {
			t.Errorf("%s Failed: [%v] inputted and NOT valid but should be valid", t.Name(), test.inputAip)
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
	if a.Validate() {
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

	if a.Validate() {
		fmt.Printf("valid signature: %s", a.Signature)
	} else {
		fmt.Printf("signature validation failed: %s", a.Signature)
	}
	// Output:valid signature: H0aEV4aeqI/2mH5DHGoEFPQWBkRS0bUMR6Q9/yVBGR7xRDH8XNY4u3Wr+mCKX1eXmjaSOIs80ZSIUtFCqQhAhCU=
}

// BenchmarkAip_Validate benchmarks the method Validate()
func BenchmarkAip_Validate(b *testing.B) {
	a, _ := Sign(examplePrivateKey, BitcoinECDSA, exampleMessage)
	for i := 0; i < b.N; i++ {
		_ = a.Validate()
	}
}

// TestSignOpReturnData tests for nil case in SignOpReturnData()
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
				"IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
				"006a0c74657374206d65737361676522313550636948473232534e4c514a584d6f53556157566937575371633768436676610d424954434f494e5f454344534122315041534772706f50744e585956735774526e337252334a6f6573755a6d4b315a354c58494c3166395835522f2f2b31582b6e426634616c634d652b466f6d30447476354a34522b4c424869447948595374364f5a7176755833745448775a6566672f6958752f6c734153636432656b5163692b777462447969633d",
				false,
				false,
				false,
			},
			{
				"",
				BitcoinECDSA,
				[][]byte{[]byte(exampleMessage)},
				"",
				"",
				false,
				true,
				true,
			},
			{
				"80699541455b59a8a8a33b85892319de8b8e8944eb8b48e9467137825ae192e59f01",
				Paymail,
				[][]byte{[]byte(exampleMessage)},
				"IL1f9X5R//+1X+nBf4alcMe+Fom0Dtv5J4R+LBHiDyHYSt6OZqvuX3tTHwZefg/iXu/lsAScd2ekQci+wtbDyic=",
				"006a0c74657374206d65737361676522313550636948473232534e4c514a584d6f5355615756693757537163376843667661077061796d61696c423032393933323961333030663333386531363437313735383139616663343564353536613662356665336338343132366636346336663530356165376161393339304c58494c3166395835522f2f2b31582b6e426634616c634d652b466f6d30447476354a34522b4c424869447948595374364f5a7176755833745448775a6566672f6958752f6c734153636432656b5163692b777462447969633d",
				false,
				false,
				false,
			},
		}
	)

	// Run tests
	for _, test := range tests {
		if out, a, err := SignOpReturnData(test.inputPrivateKey, test.inputAlgorithm, test.inputData); err != nil && !test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and error not expected but got: %s", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData, err.Error())
		} else if err == nil && test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and error was expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
		} else if a == nil && !test.expectedAipNil {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and nil was not expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
		} else if a != nil && test.expectedAipNil {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and nil was expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
		} else if out == nil && !test.expectedOutNil {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and nil was not expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
		} else if out != nil && test.expectedOutNil {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and nil was expected", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData)
		} else if a != nil && a.Signature != test.expectedSignature {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and expected signature [%s] but got [%s]", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData, test.expectedSignature, a.Signature)
		} else if out != nil && out.GetLockingScriptHexString() != test.expectedOutput {
			t.Errorf("%s Failed: [%s] [%s] [%v] inputted and expected output [%s] but got [%s]", t.Name(), test.inputPrivateKey, test.inputAlgorithm, test.inputData, test.expectedOutput, out.GetLockingScriptHexString())
		}
	}
}

// ExampleSignOpReturnData example using SignOpReturnData()
func ExampleSignOpReturnData() {
	out, a, err := SignOpReturnData(examplePrivateKey, BitcoinECDSA, [][]byte{[]byte("some op_return data")})
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("signature: %s output: %s", a.Signature, out.GetLockingScriptHexString())
	// Output:signature: Hwvwd4vKBvbfcnkqfXTzc0c5JWcbV9nmGz28zh8ds1yHOoMLP7w4aJrErTCg2xO+W8TqiioG0oJKP2a5rk1+lhE= output: 006a13736f6d65206f705f72657475726e206461746122313550636948473232534e4c514a584d6f53556157566937575371633768436676610d424954434f494e5f45434453412231446647784b6d674c3345547755644e6e584c42756545764e706a634447634b674b4c58487776776434764b42766266636e6b716658547a633063354a57636256396e6d477a32387a683864733179484f6f4d4c50377734614a72457254436732784f2b5738547169696f47306f4a4b50326135726b312b6c68453d
}

// BenchmarkSignOpReturnData benchmarks the method SignOpReturnData()
func BenchmarkSignOpReturnData(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = SignOpReturnData(examplePrivateKey, BitcoinECDSA, [][]byte{[]byte("some op_return data")})
	}
}
