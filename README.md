# go-aip

Author Identity Protocol

Library for working with [Author Identity Protocol](https://github.com/BitcoinFiles/AUTHOR_IDENTITY_PROTOCOL) in go

## Related packages

- [go-bob](https://github.com/rohenaz/go-bob)
- [go-bmap](https://github.com/rohenaz/go-bmap)

# Validate Bob Tapes

```go
	bobData := bob.New()
	bobData.FromString(sampleBobTx)

	tapes := bobData.Out[0].Tape
	if !ValidateTapes(tapes) {
		t.Error("Failed to validate AIP signature")
	}
```
