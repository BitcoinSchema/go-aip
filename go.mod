module github.com/bitcoinschema/go-aip

go 1.22

toolchain go1.22.5

require (
	github.com/bitcoin-sv/go-sdk v1.1.7
	github.com/bitcoinschema/go-bob v0.4.3
	github.com/bitcoinschema/go-bpu v0.1.3

)

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.21.0 // indirect
)

replace github.com/bitcoinschema/go-bob => ../go-bob

replace github.com/bitcoinschema/go-bpu => ../go-bpu
