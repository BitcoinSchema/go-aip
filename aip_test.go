package aip

import (
	"testing"

	"github.com/rohenaz/go-bob"
)

func TestValidate(t *testing.T) {

	const sampleBobTx = `{ "_id": "5ed07f4b57cd6b1658b817f7", "tx": { "h": "375e67f427d04e1e1a202be6f27ec33a382d3a655af539c079a9f595ec606bef" }, "in": [ { "i": 0, "tape": [ { "cell": [ { "b": "MEQCIAIKjpbGASg3rUKJwqUPW08rlcf+inWtoaTa6fnDV/gMAiBXl1x2YSZpvLi6OVot1+G23BQbIIViDv09YbFXZy+mBUE=", "s": "0D\u0002 \u0002\n���\u0001(7�B�¥\u000f[O+����u�������W�\f\u0002 W�\\va&i���9Z-���\u0014\u001b �b\u000e�=a�Wg/�\u0005A", "ii": 0, "i": 0 }, { "b": "A1B3SiT3OTW6r9F1cT651UwXkAG64vhQJeSnsCrL9fA4", "s": "\u0003PwJ$�95���uq>��L\u0017�\u0001���P%䧰*���8", "ii": 1, "i": 1 } ], "i": 0 } ], "e": { "h": "48e93234cb6aaf1098c4195164e426c67b0104b744758f146e0d1496bb7d6ebf", "i": 5, "a": "1Bpx4FdsENLcFgvkpEmBVu1o2AgqW2Ye5j" }, "seq": 4294967295 } ], "out": [ { "i": 0, "tape": [ { "cell": [ { "op": 0, "ops": "OP_0", "ii": 0, "i": 0 }, { "op": 106, "ops": "OP_RETURN", "ii": 1, "i": 1 } ], "i": 0 }, { "cell": [ { "b": "MUxvdmVGN3FRaWpwamFzY1B5dEhvcjJ1U0VFakhISDhZQg==", "s": "1LoveF7qQijpjascPytHor2uSEEjHHH8YB", "ii": 2, "i": 0 }, { "b": "NWYwNDcwMTEwZTExNTIwNzlmMjU2MjNhZDJjYzNhYmRmOGU0ODU4MzFkMGI1MzJhYzkxNWY3Zjc0MGQ5NWFiMQ==", "s": "5f0470110e1152079f25623ad2cc3abdf8e485831d0b532ac915f7f740d95ab1", "ii": 3, "i": 1 }, { "b": "dHdldGNo", "s": "twetch", "ii": 4, "i": 2 }, { "b": "YmUxMzI0NzYtM2IxZS00Mzk0LTk1YTItODM2Y2I2ZjE3M2I4", "s": "be132476-3b1e-4394-95a2-836cb6f173b8", "ii": 5, "i": 3 } ], "i": 1 }, { "cell": [ { "b": "MTVQY2lIRzIyU05MUUpYTW9TVWFXVmk3V1NxYzdoQ2Z2YQ==", "s": "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva", "ii": 7, "i": 0 }, { "b": "QklUQ09JTl9FQ0RTQQ==", "s": "BITCOIN_ECDSA", "ii": 8, "i": 1 }, { "b": "MTQ4c3hhY1BYYXBRTmhGQlJuWTlQUFk1cWN5b2lhY0dlcQ==", "s": "148sxacPXapQNhFBRnY9PPY5qcyoiacGeq", "ii": 9, "i": 2 }, { "b": "SVAxUTE0UGxZL1lrRnQwZy9Dd29sdFRKTGhMa2trb3lsOWtJaWhyaE4zWFlQSFRJaDFxbUNteElkTXZ6OTIvaDBnYWdCRnU2ZWtsbUEvMWpaL21DSUV3PQ==", "s": "IP1Q14PlY/YkFt0g/CwoltTJLhLkkkoyl9kIihrhN3XYPHTIh1qmCmxIdMvz92/h0gagBFu6eklmA/1jZ/mCIEw=", "ii": 10, "i": 3 } ], "i": 2 } ], "e": { "v": 0, "i": 0, "a": "false" } }, { "i": 1, "tape": [ { "cell": [ { "op": 118, "ops": "OP_DUP", "ii": 0, "i": 0 }, { "op": 169, "ops": "OP_HASH160", "ii": 1, "i": 1 }, { "b": "tyEUOsrxZFF9FqST84M12N7gJXk=", "s": "�!\u0014:��dQ}\u0016���5���%y", "ii": 2, "i": 2 }, { "op": 136, "ops": "OP_EQUALVERIFY", "ii": 3, "i": 3 }, { "op": 172, "ops": "OP_CHECKSIG", "ii": 4, "i": 4 } ], "i": 0 } ], "e": { "v": 546, "i": 1, "a": "1HhJHUbJskwHEmxnHE62hVZrbWKAZyXegm" } }, { "i": 2, "tape": [ { "cell": [ { "op": 118, "ops": "OP_DUP", "ii": 0, "i": 0 }, { "op": 169, "ops": "OP_HASH160", "ii": 1, "i": 1 }, { "b": "BRhv8HEO0AQinmRMBlOymFxkiiM=", "s": "\u0005\u0018o�q\u000e�\u0004\"�dL\u0006S��\\d�#", "ii": 2, "i": 2 }, { "op": 136, "ops": "OP_EQUALVERIFY", "ii": 3, "i": 3 }, { "op": 172, "ops": "OP_CHECKSIG", "ii": 4, "i": 4 } ], "i": 0 } ], "e": { "v": 4718, "i": 2, "a": "1Twetcht1cTUxpdDoX5HQRpoXeuupAdyf" } }, { "i": 3, "tape": [ { "cell": [ { "op": 118, "ops": "OP_DUP", "ii": 0, "i": 0 }, { "op": 169, "ops": "OP_HASH160", "ii": 1, "i": 1 }, { "b": "ge8V46sxXUTHoX/MDhoMTUDe5aU=", "s": "��\u0015�1]Dǡ�\u000e\u001a\fM@��", "ii": 2, "i": 2 }, { "op": 136, "ops": "OP_EQUALVERIFY", "ii": 3, "i": 3 }, { "op": 172, "ops": "OP_CHECKSIG", "ii": 4, "i": 4 } ], "i": 0 } ], "e": { "v": 6990, "i": 3, "a": "1Cr2ahVvRz5gdNVbKMrNUbqudzeXgVKrx2" } }, { "i": 4, "tape": [ { "cell": [ { "op": 118, "ops": "OP_DUP", "ii": 0, "i": 0 }, { "op": 169, "ops": "OP_HASH160", "ii": 1, "i": 1 }, { "b": "Z3WtDwnQdIHbl2gZcRtaVBF/Xng=", "s": "gu�\u000f\t�t�ۗh\u0019q\u001bZT\u0011^x", "ii": 2, "i": 2 }, { "op": 136, "ops": "OP_EQUALVERIFY", "ii": 3, "i": 3 }, { "op": 172, "ops": "OP_CHECKSIG", "ii": 4, "i": 4 } ], "i": 0 } ], "e": { "v": 13980, "i": 4, "a": "1AS3a2ocVtMEBFxYiyWKywsZYxRyxxWQCZ" } }, { "i": 5, "tape": [ { "cell": [ { "op": 118, "ops": "OP_DUP", "ii": 0, "i": 0 }, { "op": 169, "ops": "OP_HASH160", "ii": 1, "i": 1 }, { "b": "bnGmFJIqldGih1Hpvw+zKO9pbkQ=", "s": "nq�\u0014�*�Ѣ�Q�\u000f�(�inD", "ii": 2, "i": 2 }, { "op": 136, "ops": "OP_EQUALVERIFY", "ii": 3, "i": 3 }, { "op": 172, "ops": "OP_CHECKSIG", "ii": 4, "i": 4 } ], "i": 0 } ], "e": { "v": 1699347, "i": 5, "a": "1B4yUZC7NkikrXPXEyPEQ6WhVBvYz3asN1" } } ], "lock": 0, "blk": { "i": 635130, "h": "000000000000000002f50329db73a826c97deb0e642e142dc81cdfda4b4a39ba", "t": 1589606545 }, "i": 2690 }`

	bobData := bob.New()
	bobData.FromString(sampleBobTx)

	if bobData.Tx.H != "375e67f427d04e1e1a202be6f27ec33a382d3a655af539c079a9f595ec606bef" {
		t.Error("From String Failed")
	}

	tapes := bobData.Out[0].Tape
	if !ValidateTapes(tapes) {
		t.Error("Failed to validate AIP signature")
	}
}
