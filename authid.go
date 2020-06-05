package V2VMessAEADHeader

import (
	"bytes"
	"crypto/aes"
	rand3 "crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/xiaokangwang/V2VMessAEADHeader/antiReplayWindow"
	"hash/crc32"
	"io"
	"math"
	"time"
)

import "crypto/cipher"

func CreateAuthID(cmdKey []byte, time int64) [16]byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, time)
	var zero uint32
	io.CopyN(buf, rand3.Reader, 4)
	zero = crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(buf, binary.BigEndian, zero)
	aesBlock := NewCipherFromKey(cmdKey)
	if buf.Len() != 16 {
		panic("Size unexpected")
	}
	var result [16]byte
	aesBlock.Encrypt(result[:], buf.Bytes())
	return result
}

func NewCipherFromKey(cmdKey []byte) cipher.Block {
	aesBlock, err := aes.NewCipher(KDF16(cmdKey, "AES Auth ID Encryption"))
	if err != nil {
		panic(err)
	}
	return aesBlock
}

type AuthIDDecoder struct {
	s cipher.Block
}

func NewAuthIDDecoder(cmdKey []byte) *AuthIDDecoder {
	return &AuthIDDecoder{NewCipherFromKey(cmdKey)}
}

func (aidd *AuthIDDecoder) Decode(data [16]byte) (int64, uint32, int32, []byte) {
	aidd.s.Decrypt(data[:], data[:])
	var time int64
	var zero uint32
	var rand int32
	reader := bytes.NewReader(data[:])
	binary.Read(reader, binary.BigEndian, &time)
	binary.Read(reader, binary.BigEndian, &rand)
	binary.Read(reader, binary.BigEndian, &zero)
	return time, zero, rand, data[:]
}

func NewAuthIDDecoderHolder() *AuthIDDecoderHolder {
	return &AuthIDDecoderHolder{make(map[string]*AuthIDDecoderItem), antiReplayWindow.NewAntiReplayWindow(120)}
}

type AuthIDDecoderHolder struct {
	aidhi map[string]*AuthIDDecoderItem
	apw   *antiReplayWindow.AntiReplayWindow
}

type AuthIDDecoderItem struct {
	dec    *AuthIDDecoder
	ticket interface{}
}

func NewAuthIDDecoderItem(key [16]byte, ticket interface{}) *AuthIDDecoderItem {
	return &AuthIDDecoderItem{
		dec:    NewAuthIDDecoder(key[:]),
		ticket: ticket,
	}
}

func (a *AuthIDDecoderHolder) AddUser(key [16]byte, ticket interface{}) {
	a.aidhi[string(key[:])] = NewAuthIDDecoderItem(key, ticket)
}

func (a *AuthIDDecoderHolder) RemoveUser(key [16]byte) {
	delete(a.aidhi, string(key[:]))
}

func (a *AuthIDDecoderHolder) Match(AuthID [16]byte) (interface{}, error) {
	if !a.apw.Check(AuthID[:]) {
		return nil, errReplay
	}
	for _, v := range a.aidhi {

		t, z, r, d := v.dec.Decode(AuthID)
		if z != crc32.ChecksumIEEE(d[:12]) {
			continue
		}
		if math.Abs(float64(t-time.Now().Unix())) > 120 {
			continue
		}
		_ = r

		return v.ticket, nil

	}
	return nil, errNotFound
}

var errNotFound = errors.New("user do not exist")

var errReplay = errors.New("replayed request")
