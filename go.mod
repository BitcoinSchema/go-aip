module github.com/bitcoinschema/go-aip

go 1.16

require (
	github.com/bitcoinschema/go-bitcoin v0.3.20
	github.com/bitcoinschema/go-bob v0.3.1
	github.com/bitcoinschema/go-bpu v0.0.3
	github.com/bitcoinsv/bsvutil v0.0.0-20181216182056-1d77cf353ea9
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.3 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0 // indirect
	github.com/libsv/go-bt v1.0.8
)

replace github.com/libsv/go-bt => github.com/libsv/go-bt v1.0.4

// Bad version of go-bob, failing tests etc
// replace github.com/bitcoinschema/go-bob => github.com/bitcoinschema/go-bob v0.2.1
