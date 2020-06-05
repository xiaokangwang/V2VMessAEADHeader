package V2VMessAEADHeader

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestOpenVMessAEADHeader(t *testing.T) {
	TestHeader := []byte("Test Header")
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	var keyw [16]byte
	copy(keyw[:], key)
	sealed := SealVMessAEADHeader(keyw, TestHeader)

	var AEADR = bytes.NewReader(sealed)

	var authid [16]byte

	io.ReadFull(AEADR, authid[:])

	out, _, err, _ := OpenVMessAEADHeader(keyw, authid, AEADR)

	fmt.Println(string(out))
	fmt.Println(err)
}

func TestOpenVMessAEADHeader2(t *testing.T) {
	TestHeader := []byte("Test Header")
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	var keyw [16]byte
	copy(keyw[:], key)
	sealed := SealVMessAEADHeader(keyw, TestHeader)

	var AEADR = bytes.NewReader(sealed)

	var authid [16]byte

	io.ReadFull(AEADR, authid[:])

	out, _, err, readen := OpenVMessAEADHeader(keyw, authid, AEADR)
	assert.Equal(t, len(sealed)-16-AEADR.Len(), readen)
	assert.Equal(t, string(TestHeader), string(out))
	assert.Nil(t, err)
}

func TestOpenVMessAEADHeader4(t *testing.T) {
	for i := 0; i <= 60; i++ {
		TestHeader := []byte("Test Header")
		key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
		var keyw [16]byte
		copy(keyw[:], key)
		sealed := SealVMessAEADHeader(keyw, TestHeader)
		sealed[i] = 0xff
		var AEADR = bytes.NewReader(sealed)

		var authid [16]byte

		io.ReadFull(AEADR, authid[:])

		out, drain, err, readen := OpenVMessAEADHeader(keyw, authid, AEADR)
		assert.Equal(t, len(sealed)-16-AEADR.Len(), readen)
		assert.Equal(t, true, drain)
		assert.NotNil(t, err)
		if err == nil {
			fmt.Println(">")
		}
		assert.Nil(t, out)
	}

}
